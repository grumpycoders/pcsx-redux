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
    eastl::function<void()> callback = [this]() {
        Hardware::CPU::IReg.clear(Hardware::CPU::IRQ::CDRom);
        irq();
    };
    if (Kernel::isKernelTakenOver()) {
        Kernel::queueIRQHandler(Kernel::IRQ::CDRom, eastl::move(callback));
    } else {
        m_event = Kernel::openEvent(EVENT_CDROM, 0x1000, EVENT_MODE_CALLBACK, eastl::move(callback));
        syscall_enableEvent(m_event);
    }
}

psyqo::CDRomDevice::~CDRomDevice() { Kernel::abort("CDRomDevice can't be destroyed (yet)"); }

namespace {

enum class ResetActionState : uint8_t {
    IDLE,
    RESET,
    RESET_ACK,
};

class ResetAction : public psyqo::CDRomDevice::Action<ResetActionState> {
  public:
    void start(psyqo::CDRomDevice *device, eastl::function<void(bool)> &&callback) {
        psyqo::Kernel::assert(getState() == ResetActionState::IDLE,
                              "CDRomDevice::reset() called while another action is in progress");
        registerMe(device);
        setCallback(eastl::move(callback));
        setState(ResetActionState::RESET);
        eastl::atomic_signal_fence(eastl::memory_order_release);
        psyqo::Hardware::CDRom::Cause = 0x1f;
        psyqo::Hardware::CDRom::CauseMask = 0x1f;
        psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::INIT);
    }
    bool complete(const psyqo::CDRomDevice::Response &) override {
        psyqo::Kernel::assert(getState() == ResetActionState::RESET_ACK,
                              "ResetAction got CDROM complete in wrong state");
        setSuccess(true);
        return true;
    }
    bool acknowledge(const psyqo::CDRomDevice::Response &) override {
        psyqo::Kernel::assert(getState() == ResetActionState::RESET,
                              "ResetAction got CDROM acknowledge in wrong state");
        setState(ResetActionState::RESET_ACK);
        return false;
    }
};

ResetAction resetAction;

enum class ReadSectorsActionState : uint8_t {
    IDLE,
    SETLOC,
    SETMODE,
    READ,
    READ_ACK,
    PAUSE,
    PAUSE_ACK,
};

class ReadSectorsAction : public psyqo::CDRomDevice::Action<ReadSectorsActionState> {
  public:
    void start(psyqo::CDRomDevice *device, uint32_t sector, uint32_t count, void *buffer,
               eastl::function<void(bool)> &&callback) {
        psyqo::Kernel::assert(getState() == ReadSectorsActionState::IDLE,
                              "CDRomDevice::readSectors() called while another action is in progress");
        registerMe(device);
        setCallback(eastl::move(callback));
        setState(ReadSectorsActionState::SETLOC);
        m_count = count;
        m_ptr = reinterpret_cast<uint8_t *>(buffer);
        eastl::atomic_signal_fence(eastl::memory_order_release);
        psyqo::MSF msf(sector + 150);
        uint8_t bcd[3];
        msf.toBCD(bcd);
        psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::SETLOC, bcd[0], bcd[1], bcd[2]);
    }
    bool dataReady(const psyqo::CDRomDevice::Response &) override {
        psyqo::Kernel::assert(getState() == ReadSectorsActionState::READ_ACK,
                              "ReadSectorsAction got CDROM dataReady in wrong state");
        psyqo::Hardware::CDRom::Ctrl.throwAway();
        psyqo::Hardware::CDRom::DataRequest = 0;
        psyqo::Hardware::CDRom::InterruptControl.throwAway();
        psyqo::Hardware::CDRom::DataRequest = 0x80;
        psyqo::Hardware::SBus::Dev5Ctrl = 0x20943;
        psyqo::Hardware::SBus::ComCtrl = 0x132c;
        eastl::atomic_signal_fence(eastl::memory_order_acquire);
        DMA_CTRL[DMA_CDROM].MADR = reinterpret_cast<uintptr_t>(m_ptr);
        DMA_CTRL[DMA_CDROM].BCR = 512 | 0x10000;
        DMA_CTRL[DMA_CDROM].CHCR = 0x11000000;
        m_ptr += 2048;
        if (--m_count == 0) {
            setState(ReadSectorsActionState::PAUSE);
            psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::PAUSE);
        }
        eastl::atomic_signal_fence(eastl::memory_order_release);
        return false;
    }
    bool complete(const psyqo::CDRomDevice::Response &) override {
        psyqo::Kernel::assert(getState() == ReadSectorsActionState::PAUSE_ACK,
                              "ReadSectorsAction got CDROM complete in wrong state");
        setSuccess(true);
        return true;
    }
    bool acknowledge(const psyqo::CDRomDevice::Response &) override {
        switch (getState()) {
            case ReadSectorsActionState::SETLOC:
                setState(ReadSectorsActionState::SETMODE);
                psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::SETMODE, 0x80);
                break;
            case ReadSectorsActionState::SETMODE:
                setState(ReadSectorsActionState::READ);
                psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::READN);
                break;
            case ReadSectorsActionState::READ:
                setState(ReadSectorsActionState::READ_ACK);
                break;
            case ReadSectorsActionState::PAUSE:
                setState(ReadSectorsActionState::PAUSE_ACK);
                break;
            default:
                psyqo::Kernel::abort("ReadSectorsAction got CDROM acknowledge in wrong state");
                break;
        }
        return false;
    }

  private:
    uint32_t m_count = 0;
    uint8_t *m_ptr = nullptr;
};

ReadSectorsAction readSectorsAction;

enum class ReadTOCActionState : uint8_t {
    IDLE,
    GETTN,
    GETTD,
};

class ReadTOCAction : public psyqo::CDRomDevice::Action<ReadTOCActionState> {
  public:
    void start(psyqo::CDRomDevice *device, psyqo::MSF *toc, eastl::function<void(bool)> &&callback) {
        psyqo::Kernel::assert(getState() == ReadTOCActionState::IDLE,
                              "CDRomDevice::readTOC() called while another action is in progress");
        registerMe(device);
        setCallback(eastl::move(callback));
        m_toc = toc;
        setState(ReadTOCActionState::GETTN);
        eastl::atomic_signal_fence(eastl::memory_order_release);
        psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::GETTN);
    }
    bool acknowledge(const psyqo::CDRomDevice::Response &response) override {
        switch (getState()) {
            case ReadTOCActionState::GETTN:
                setState(ReadTOCActionState::GETTD);
                m_currentTrack = response[1];
                m_lastTrack = response[2];
                psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::GETTD, psyqo::itob(1));
                break;
            case ReadTOCActionState::GETTD: {
                psyqo::MSF &msf = m_toc[m_currentTrack];
                msf.m = psyqo::btoi(response[1]);
                msf.s = psyqo::btoi(response[2]);
                msf.f = 0;
                if (++m_currentTrack <= m_lastTrack) {
                    psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::GETTD,
                                                         psyqo::itob(m_currentTrack));
                } else {
                    setSuccess(true);
                    return true;
                }
            } break;
            default:
                psyqo::Kernel::abort("ReadTOCAction got CDROM acknowledge in wrong state");
                break;
        }
        return false;
    }
    psyqo::MSF *m_toc = nullptr;
    uint8_t m_currentTrack = 0;
    uint8_t m_lastTrack = 0;
};

ReadTOCAction readTOCAction;

}  // namespace

void psyqo::CDRomDevice::reset(eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::reset called with pending action");
    resetAction.start(this, eastl::move(callback));
}

psyqo::TaskQueue::Task psyqo::CDRomDevice::scheduleReset() {
    return TaskQueue::Task([this](auto task) { reset([task](bool success) { task->complete(success); }); });
}

void psyqo::CDRomDevice::readSectors(uint32_t sector, uint32_t count, void *buffer,
                                     eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::readSectors called with pending action");
    readSectorsAction.start(this, sector, count, buffer, eastl::move(callback));
}

psyqo::TaskQueue::Task psyqo::CDRomDevice::scheduleReadSectors(uint32_t sector, uint32_t count, void *buffer) {
    return TaskQueue::Task([this, sector, count, buffer](auto task) {
        readSectors(sector, count, buffer, [task](bool success) { task->complete(success); });
    });
}

void psyqo::CDRomDevice::readTOC(MSF *toc, eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::readTOC called with pending action");
    readTOCAction.start(this, toc, eastl::move(callback));
}

psyqo::TaskQueue::Task psyqo::CDRomDevice::scheduleReadTOC(MSF *toc) {
    return TaskQueue::Task([this, toc](auto task) { readTOC(toc, [task](bool success) { task->complete(success); }); });
}

void psyqo::CDRomDevice::switchAction(ActionBase *action) {
    Kernel::assert(m_action == nullptr, "CDRomDevice can only have one action active at a given time");
    m_action = action;
}

void psyqo::CDRomDevice::irq() {
    Kernel::assert(m_action != nullptr, "CDRomDevice::irq() called with no action - spurious interrupt?");
    uint8_t cause = Hardware::CDRom::Cause;

    if (cause & 7) {
        Hardware::CDRom::Cause = 7;
    }

    if (cause & 0x18) {
        Hardware::CDRom::Cause = 0x18;
    }

    bool callCallback = false;
    Response response;
    while ((Hardware::CDRom::Ctrl.access() & 0x20) && (response.size() < 16)) {
        response.push_back(Hardware::CDRom::Response);
    }

    switch (cause & 7) {
        case 1:
            callCallback = m_action->dataReady(response);
            break;
        case 2:
            callCallback = m_action->complete(response);
            break;
        case 3:
            callCallback = m_action->acknowledge(response);
            break;
        case 4:
            callCallback = m_action->end(response);
            break;
        case 5:
            m_success = false;
            callCallback = true;
            break;
        default:
            Kernel::abort("CDRomDevice::irq() invoked with unknown cause");
            break;
    }

    if (callCallback) {
        Kernel::assert(!!m_callback, "Wrong CDRomDevice state");
        m_action = nullptr;
        eastl::atomic_signal_fence(eastl::memory_order_acquire);
        Kernel::queueCallbackFromISR([this]() {
            auto callback = eastl::move(m_callback);
            auto success = m_success;
            m_success = false;
            m_state = 0;
            callback(success);
        });
    }
}

void psyqo::CDRomDevice::ActionBase::setCallback(eastl::function<void(bool)> &&callback) {
    auto &deviceCallback = m_device->m_callback;
    Kernel::assert(!deviceCallback && m_device->m_state == 0, "Action setup called with pending action");
    m_device->m_callback = eastl::move(callback);
}
void psyqo::CDRomDevice::ActionBase::setSuccess(bool success) { m_device->m_success = success; }
bool psyqo::CDRomDevice::ActionBase::dataReady(const Response &) {
    Kernel::abort("Action::dataReady() not implemented");
}
bool psyqo::CDRomDevice::ActionBase::complete(const Response &) { Kernel::abort("Action::complete() not implemented"); }
bool psyqo::CDRomDevice::ActionBase::acknowledge(const Response &) {
    Kernel::abort("Action::acknowledge() not implemented");
}
bool psyqo::CDRomDevice::ActionBase::end(const Response &) { Kernel::abort("Action::end() not implemented"); }
