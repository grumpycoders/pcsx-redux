/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include "psyqo/cdrom-device.hh"

#include <EASTL/atomic.h>

#include "common/hardware/dma.h"
#include "common/kernel/events.h"
#include "common/syscalls/syscalls.h"
#include "psyqo/hardware/cdrom.hh"
#include "psyqo/hardware/cpu.hh"
#include "psyqo/hardware/sbus.hh"
#include "psyqo/kernel.hh"
#include "psyqo/msf.hh"

void psyqo::CDRomDevice::prepare() {
    Hardware::CPU::IMask.set(Hardware::CPU::IRQ::CDRom);
    Kernel::enableDma(Kernel::DMA::CDRom);
    m_event = Kernel::openEvent(EVENT_CDROM, 0x1000, EVENT_MODE_CALLBACK, [this]() {
        Hardware::CPU::IReg.clear(Hardware::CPU::IRQ::CDRom);
        irq();
    });
    syscall_enableEvent(m_event);
}

psyqo::CDRomDevice::~CDRomDevice() { Kernel::abort("CDRomDevice can't be destroyed (yet)"); }

void psyqo::CDRomDevice::reset(eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "Only one read allowed at a time");
    Kernel::assert(m_action == NONE, "CDRom state machine is busy");
    m_callback = eastl::move(callback);
    m_action = RESET;
    eastl::atomic_signal_fence(eastl::memory_order_release);
    Hardware::CDRom::Cause = 0x1f;
    Hardware::CDRom::CauseMask = 0x1f;
    Hardware::CDRom::Command.send(Hardware::CDRom::CDL::INIT);
}

psyqo::TaskQueue::Task psyqo::CDRomDevice::scheduleReset() {
    return TaskQueue::Task([this](auto task) { reset([task](bool success) { task->complete(success); }); });
}

void psyqo::CDRomDevice::readSectors(uint32_t sector, uint32_t count, void *buffer,
                                     eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "Only one action allowed at a time");
    Kernel::assert(m_action == NONE, "CDRom state machine is busy");
    m_callback = eastl::move(callback);
    m_action = SETLOC;
    m_count = count;
    m_ptr = reinterpret_cast<uint8_t *>(buffer);
    eastl::atomic_signal_fence(eastl::memory_order_release);
    MSF msf(sector + 150);
    uint8_t bcd[3];
    msf.toBCD(bcd);
    Hardware::CDRom::Command.send(Hardware::CDRom::CDL::SETLOC, bcd[0], bcd[1], bcd[2]);
}

void psyqo::CDRomDevice::irq() {
    uint8_t cause = Hardware::CDRom::Cause;

    if (cause & 7) {
        Hardware::CDRom::Cause = 7;
    }

    if (cause & 0x18) {
        Hardware::CDRom::Cause = 0x18;
    }

    switch (cause & 7) {
        case 1:
            dataReady();
            break;
        case 2:
            complete();
            break;
        case 3:
            acknowledge();
            break;
        case 4:
            end();
            break;
        case 5:
            discError();
            break;
    }
}

void psyqo::CDRomDevice::dataReady() {
    uint8_t status = Hardware::CDRom::Response;
    Hardware::CDRom::Ctrl.throwAway();
    Hardware::CDRom::DataRequest = 0;
    Hardware::CDRom::InterruptControl.throwAway();
    Hardware::CDRom::DataRequest = 0x80;
    Hardware::SBus::Dev5Ctrl = 0x20943;
    Hardware::SBus::ComCtrl = 0x132c;
    eastl::atomic_signal_fence(eastl::memory_order_acquire);
    DMA_CTRL[DMA_CDROM].MADR = reinterpret_cast<uintptr_t>(m_ptr);
    DMA_CTRL[DMA_CDROM].BCR = 512 | 0x10000;
    DMA_CTRL[DMA_CDROM].CHCR = 0x11000000;
    m_ptr += 2048;
    if (--m_count == 0) {
        m_action = PAUSE;
        Hardware::CDRom::Command.send(Hardware::CDRom::CDL::PAUSE);
    }
    eastl::atomic_signal_fence(eastl::memory_order_release);
}

void psyqo::CDRomDevice::complete() {
    switch (m_action) {
        case RESET:
        case PAUSE:
            eastl::atomic_signal_fence(eastl::memory_order_acquire);
            Kernel::assert(!!m_callback, "Wrong CDRomDevice state");
            Kernel::queueCallbackFromISR([this]() {
                auto callback = eastl::move(m_callback);
                m_action = NONE;
                callback(true);
            });
            break;
        default:
            Kernel::abort("CDRomDevice::complete() called in wrong state");
            break;
    }
}

void psyqo::CDRomDevice::acknowledge() {
    uint8_t status = Hardware::CDRom::Response;
    switch (m_action) {
        case RESET:
            break;
        case SETLOC:
            m_action = SETMODE;
            Hardware::CDRom::Command.send(Hardware::CDRom::CDL::SETMODE, 0x80);
            break;
        case SETMODE:
            m_action = READ;
            Hardware::CDRom::Command.send(Hardware::CDRom::CDL::READN);
            break;
        case READ:
            break;
        case PAUSE:
            break;
        default:
            Kernel::abort("Not implemented");
            break;
    }
}

void psyqo::CDRomDevice::end() { Kernel::abort("Not implemented"); }

void psyqo::CDRomDevice::discError() {
    eastl::atomic_signal_fence(eastl::memory_order_acquire);
    Kernel::assert(!!m_callback, "Wrong CDRomDevice state");
    Kernel::queueCallbackFromISR([this]() {
        auto callback = eastl::move(m_callback);
        m_action = NONE;
        callback(false);
    });
}
