/***s************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN

#include <assert.h>
#include <windows.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <shared_mutex>
#include <thread>

#include "ftd2xx.h"
#include "ftdi/abstract.h"

namespace PCSX {
namespace FTDI {
namespace Private {
class DeviceData {
  public:
    FT_HANDLE m_handle = nullptr;
    HANDLE m_event = nullptr;
    enum {
        STATE_CLOSED,
        STATE_OPEN_PENDING,
        STATE_OPENED,
        STATE_CLOSE_PENDING,
    } m_state = STATE_CLOSED;
};
}  // namespace Private
}  // namespace FTDI
}  // namespace PCSX

static PCSX::FTDI::Device* s_devices = nullptr;
static unsigned s_numDevs = 0;
static HANDLE s_thread;
static std::atomic_bool s_exitThread;
static bool s_threadRunning = false;
static HANDLE s_kickEvent = nullptr;
static std::shared_mutex s_listLock;
static unsigned s_numOpened = 0;

static PCSX::GUI* s_gui = nullptr;

static void asyncCallbackTrampoline(uv_async_t* handle) {
    PCSX::FTDI::Device* device = (PCSX::FTDI::Device*)handle->data;
    device->asyncCallback();
}

static void asyncCloseCallbackTrampoline(uv_handle_t* handle) {
    PCSX::FTDI::Device* device = reinterpret_cast<PCSX::FTDI::Device*>(handle->data);
    device->asyncCloseCallback();
}

PCSX::FTDI::Device::Device() {
    uv_async_init(s_gui->loop(), &m_async, asyncCallbackTrampoline);
    m_async.data = this;
}

PCSX::FTDI::Device::~Device() {
    assert(m_private->m_state == Private::DeviceData::STATE_CLOSED);
    assert(!m_private->m_event);
    assert(!m_private->m_handle);
    delete m_private;
    uv_loop_t* loop = m_async.loop;
    uv_close(reinterpret_cast<uv_handle_t*>(&m_async), asyncCloseCallbackTrampoline);
    while (!m_asyncClosed) uv_run(loop, UV_RUN_ONCE);
}

void PCSX::FTDI::Device::open() {
    std::unique_lock<std::shared_mutex> guard(s_listLock);
    assert(m_private->m_state == Private::DeviceData::STATE_CLOSED);
    m_private->m_state = Private::DeviceData::STATE_OPEN_PENDING;
    SetEvent(s_kickEvent);
}
void PCSX::FTDI::Device::close() {
    std::unique_lock<std::shared_mutex> guard(s_listLock);
    assert(m_private->m_state == Private::DeviceData::STATE_OPENED);
    m_private->m_state = Private::DeviceData::STATE_CLOSE_PENDING;
    SetEvent(s_kickEvent);
}
bool PCSX::FTDI::Device::isOpened() const { return m_private->m_state == Private::DeviceData::STATE_OPENED; }
bool PCSX::FTDI::Device::isBusy() const {
    return m_private->m_state == Private::DeviceData::STATE_CLOSE_PENDING ||
           m_private->m_state == Private::DeviceData::STATE_OPEN_PENDING;
}

void PCSX::FTDI::Devices::scan() {
    FT_STATUS status;
    DWORD numDevs = 0;

    std::unique_lock<std::shared_mutex> guard(s_listLock);
    // we can't modify the list if there's any device that's still opened
    if (s_numDevs != 0) return;

    delete[] s_devices;
    s_numDevs = 0;
    status = FT_CreateDeviceInfoList(&numDevs);

    if (status != FT_OK || numDevs == 0) return;
    s_numDevs = numDevs;

    FT_DEVICE_LIST_INFO_NODE* nodes = new FT_DEVICE_LIST_INFO_NODE[numDevs];

    status = FT_GetDeviceInfoList(nodes, &numDevs);

    if (status == FT_OK && numDevs != 0) {
        s_devices = new Device[numDevs];
        for (DWORD i = 0; i < numDevs; i++) {
            const FT_DEVICE_LIST_INFO_NODE* n = nodes + i;
            s_devices[i].m_locked = n->Flags & FT_FLAGS_OPENED;
            s_devices[i].m_highSpeed = n->Flags & FT_FLAGS_HISPEED;
            s_devices[i].m_vendorID = (n->ID >> 16) & 0xffff;
            s_devices[i].m_deviceID = n->ID & 0xffff;
            s_devices[i].m_type = n->Type;
            s_devices[i].m_serial = n->SerialNumber;
            s_devices[i].m_description = n->Description;
            s_devices[i].m_private = new Private::DeviceData();
        }
    }

    delete[] nodes;
}

void PCSX::FTDI::Devices::iterate(std::function<bool(Device&)> iter) {
    std::shared_lock<std::shared_mutex> guard(s_listLock);
    for (unsigned i = 0; i < s_numDevs; i++) {
        if (!iter(s_devices[i])) break;
    }
}

void PCSX::FTDI::Devices::threadProc() {
    SetThreadDescription(GetCurrentThread(), L"abstract ftd2xx thread");
    while (!s_exitThread) {
        std::vector<HANDLE> objects;
        std::vector<Device*> devices;
        objects.push_back(s_kickEvent);
        devices.push_back(nullptr);
        {
            std::shared_lock<std::shared_mutex> guard(s_listLock);

            for (unsigned i = 0; i < s_numDevs; i++) {
                auto& device = s_devices[i];
                switch (device.m_private->m_state) {
                    case Private::DeviceData::STATE_OPEN_PENDING:
                        s_numOpened++;
                        FT_OpenEx(const_cast<char*>(device.m_serial.c_str()), FT_OPEN_BY_SERIAL_NUMBER,
                                  &device.m_private->m_handle);
                        device.m_private->m_event = CreateEvent(nullptr, FALSE, FALSE, L"Event for FTDI device");
                        FT_SetEventNotification(device.m_private->m_handle,
                                                FT_EVENT_RXCHAR | FT_EVENT_MODEM_STATUS | FT_EVENT_LINE_STATUS,
                                                device.m_private->m_event);
                        device.m_private->m_state = Private::DeviceData::STATE_OPENED;
                    case Private::DeviceData::STATE_OPENED:
                        objects.push_back(device.m_private->m_event);
                        devices.push_back(&device);
                        break;
                    case Private::DeviceData::STATE_CLOSE_PENDING:
                        s_numOpened--;
                        FT_Close(device.m_private->m_handle);
                        CloseHandle(device.m_private->m_event);
                        device.m_private->m_handle = nullptr;
                        device.m_private->m_event = nullptr;
                        device.m_private->m_state = Private::DeviceData::STATE_CLOSED;
                        break;
                }
            }
        }
        DWORD idx;
        do {
            assert(objects.size() <= MAXIMUM_WAIT_OBJECTS);
            idx = WaitForMultipleObjects(objects.size(), objects.data(), FALSE, INFINITE);
            Device* device = devices[idx - WAIT_OBJECT_0];
            if (!device) continue;
            DWORD events;
            FT_GetEventStatus(device->m_private->m_handle, &events);
            printf("%i", events);
        } while (idx != WAIT_OBJECT_0);
    }
    CloseHandle(s_kickEvent);
    s_kickEvent = nullptr;
    s_exitThread = false;
    s_threadRunning = false;
}

static DWORD WINAPI threadProcTrampoline(LPVOID parameter) {
    PCSX::FTDI::Devices::threadProc();
    return 0;
}

void PCSX::FTDI::Devices::startThread() {
    assert(!s_threadRunning);
    s_kickEvent = CreateEvent(nullptr, FALSE, FALSE, L"abstract ftd2xx kick event");
    s_threadRunning = true;
    s_thread = CreateThread(nullptr, 0, threadProcTrampoline, nullptr, 0, nullptr);
}

void PCSX::FTDI::Devices::stopThread() {
    assert(s_threadRunning);
    s_exitThread = true;
    SetEvent(s_kickEvent);
    WaitForSingleObject(s_thread, INFINITE);
    s_thread = nullptr;
    assert(!s_threadRunning);
}

bool PCSX::FTDI::Devices::isThreadRunning() { return s_threadRunning; }

void PCSX::FTDI::Devices::shutdown() {
    if (!isThreadRunning()) startThread();
    {
        bool run = true;
        while (run) {
            run = false;
            std::unique_lock<std::shared_mutex> guard(s_listLock);
            for (unsigned i = 0; i < s_numDevs; i++) {
                auto& device = s_devices[i];
                switch (device.m_private->m_state) {
                    case Private::DeviceData::STATE_OPENED:
                        device.close();
                    case Private::DeviceData::STATE_CLOSE_PENDING:
                    case Private::DeviceData::STATE_OPEN_PENDING:
                        run = true;
                        break;
                }
            }
        }
    }
    stopThread();
    delete[] s_devices;
    s_numDevs = 0;
}

void PCSX::FTDI::Devices::setGUI(GUI* gui) { s_gui = gui; }

#endif
