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
#include "psyqo/gpu.hh"
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
    ResetAction() : Action("ResetAction") {}
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

ResetAction s_resetAction;

}  // namespace

void psyqo::CDRomDevice::reset(eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::reset called with pending action");
    s_resetAction.start(this, eastl::move(callback));
}

psyqo::TaskQueue::Task psyqo::CDRomDevice::scheduleReset() {
    return TaskQueue::Task([this](auto task) { reset([task](bool success) { task->complete(success); }); });
}

namespace {

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
    ReadSectorsAction() : Action("ReadSectorsAction") {}
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

ReadSectorsAction s_readSectorsAction;

}  // namespace

void psyqo::CDRomDevice::readSectors(uint32_t sector, uint32_t count, void *buffer,
                                     eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::readSectors called with pending action");
    s_readSectorsAction.start(this, sector, count, buffer, eastl::move(callback));
}

psyqo::TaskQueue::Task psyqo::CDRomDevice::scheduleReadSectors(uint32_t sector, uint32_t count, void *buffer) {
    if (count == 0) {
        return TaskQueue::Task([this](auto task) { task->complete(true); });
    }
    uint32_t *storage = reinterpret_cast<uint32_t *>(buffer);
    storage[0] = sector;
    storage[1] = count;
    return TaskQueue::Task([this, buffer](auto task) {
        uint32_t *storage = reinterpret_cast<uint32_t *>(buffer);
        uint32_t sector = storage[0];
        uint32_t count = storage[1];
        readSectors(sector, count, buffer, [task](bool success) { task->complete(success); });
    });
}

namespace {

enum class GetTNActionEnum : uint8_t {
    IDLE,
    GETTN,
};

class GetTNAction : public psyqo::CDRomDevice::Action<GetTNActionEnum> {
  public:
    GetTNAction() : Action("GetTNAction") {}
    void start(psyqo::CDRomDevice *device, unsigned *size, eastl::function<void(bool)> &&callback) {
        psyqo::Kernel::assert(getState() == GetTNActionEnum::IDLE,
                              "CDRomDevice::getTOCSize() called while another action is in progress");
        registerMe(device);
        setCallback(eastl::move(callback));
        setState(GetTNActionEnum::GETTN);
        m_size = size;
        eastl::atomic_signal_fence(eastl::memory_order_release);
        psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::GETTN);
    }
    bool acknowledge(const psyqo::CDRomDevice::Response &response) override {
        *m_size = response[2];
        setSuccess(true);
        return true;
    }

  private:
    unsigned *m_size = nullptr;
};

GetTNAction s_getTNAction;

}  // namespace

void psyqo::CDRomDevice::getTOCSize(unsigned *size, eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::getTOCSize called with pending action");
    s_getTNAction.start(this, size, eastl::move(callback));
}

psyqo::TaskQueue::Task psyqo::CDRomDevice::scheduleGetTOCSize(unsigned *size) {
    return TaskQueue::Task(
        [this, size](auto task) { getTOCSize(size, [task](bool success) { task->complete(success); }); });
}

unsigned psyqo::CDRomDevice::getTOCSizeBlocking(GPU &gpu) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::getTOCSizeBlocking called with pending action");
    unsigned size = 0;
    bool success = false;
    {
        BlockingAction blocking(this, gpu);
        s_getTNAction.start(this, &size, [&success](bool success_) { success = success_; });
    }
    if (!success) return 0;
    return size;
}

namespace {

enum class ReadTOCActionState : uint8_t {
    IDLE,
    GETTN,
    GETTD,
};

class ReadTOCAction : public psyqo::CDRomDevice::Action<ReadTOCActionState> {
  public:
    ReadTOCAction() : Action("ReadTOCAction") {}
    void start(psyqo::CDRomDevice *device, psyqo::MSF *toc, unsigned size, eastl::function<void(bool)> &&callback) {
        psyqo::Kernel::assert(getState() == ReadTOCActionState::IDLE,
                              "CDRomDevice::readTOC() called while another action is in progress");
        registerMe(device);
        setCallback(eastl::move(callback));
        setState(ReadTOCActionState::GETTN);
        m_toc = toc;
        m_size = size;
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
                m_currentTrack++;
                if ((m_currentTrack <= m_lastTrack) && (m_currentTrack < m_size)) {
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
    unsigned m_size = 0;
    uint8_t m_currentTrack = 0;
    uint8_t m_lastTrack = 0;
};

ReadTOCAction s_readTOCAction;

}  // namespace

void psyqo::CDRomDevice::readTOC(MSF *toc, unsigned size, eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::readTOC called with pending action");
    s_readTOCAction.start(this, toc, size, eastl::move(callback));
}

psyqo::TaskQueue::Task psyqo::CDRomDevice::scheduleReadTOC(MSF *toc, unsigned size) {
    if (size == 0) {
        return TaskQueue::Task([this](auto task) { task->complete(true); });
    }
    size = eastl::min(size, 100u);
    toc[0].m = size;
    return TaskQueue::Task([this, toc](auto task) {
        unsigned size = toc[0].m;
        toc[0].m = 0;
        readTOC(toc, size, [task](bool success) { task->complete(success); });
    });
}

bool psyqo::CDRomDevice::readTOCBlocking(MSF *toc, unsigned size, GPU &gpu) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::readTOCBlocking called with pending action");
    bool success = false;
    {
        BlockingAction blocking(this, gpu);
        readTOC(toc, size, [&success](bool success_) { success = success_; });
    }
    return success;
}

namespace {

enum class MuteActionState : uint8_t {
    IDLE,
    MUTE,
};

class MuteAction : public psyqo::CDRomDevice::Action<MuteActionState> {
  public:
    MuteAction() : Action("MuteAction") {}
    void start(psyqo::CDRomDevice *device, eastl::function<void(bool)> &&callback) {
        psyqo::Kernel::assert(getState() == MuteActionState::IDLE,
                              "CDRomDevice::mute() called while another action is in progress");
        registerMe(device);
        setCallback(eastl::move(callback));
        setState(MuteActionState::MUTE);
        eastl::atomic_signal_fence(eastl::memory_order_release);
        psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::MUTE);
    }
    bool complete(const psyqo::CDRomDevice::Response &) override {
        setSuccess(true);
        return true;
    }
};

MuteAction s_muteAction;

}  // namespace

void psyqo::CDRomDevice::mute(eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::mute called with pending action");
    s_muteAction.start(this, eastl::move(callback));
}

psyqo::TaskQueue::Task psyqo::CDRomDevice::scheduleMute() {
    return TaskQueue::Task([this](auto task) { mute([task](bool success) { task->complete(success); }); });
}

namespace {

enum class UnmuteActionState : uint8_t {
    IDLE,
    UNMUTE,
};

class UnmuteAction : public psyqo::CDRomDevice::Action<UnmuteActionState> {
  public:
    UnmuteAction() : Action("UnmuteAction") {}
    void start(psyqo::CDRomDevice *device, eastl::function<void(bool)> &&callback) {
        psyqo::Kernel::assert(getState() == UnmuteActionState::IDLE,
                              "CDRomDevice::unmute() called while another action is in progress");
        registerMe(device);
        setCallback(eastl::move(callback));
        setState(UnmuteActionState::UNMUTE);
        eastl::atomic_signal_fence(eastl::memory_order_release);
        psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::UNMUTE);
    }
    bool complete(const psyqo::CDRomDevice::Response &) override {
        setSuccess(true);
        return true;
    }
};

UnmuteAction s_unmuteAction;

}  // namespace

void psyqo::CDRomDevice::unmute(eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::unmute called with pending action");
    s_unmuteAction.start(this, eastl::move(callback));
}

psyqo::TaskQueue::Task psyqo::CDRomDevice::scheduleUnmute() {
    return TaskQueue::Task([this](auto task) { unmute([task](bool success) { task->complete(success); }); });
}

namespace {

enum class PlayCDDAActionState : uint8_t {
    IDLE,
    GETTD,
    SETMODE,
    SETLOC,
    SEEK,
    SEEK_ACK,
    PLAY,
    PLAYING,
};

class PlayCDDAAction : public psyqo::CDRomDevice::Action<PlayCDDAActionState> {
  public:
    PlayCDDAAction() : Action("PlayCDDAAction") {}
    void start(psyqo::CDRomDevice *device, unsigned track, bool stopAtEndOfTrack,
               eastl::function<void(bool)> &&callback) {
        psyqo::Kernel::assert(getState() == PlayCDDAActionState::IDLE,
                              "CDRomDevice::playCDDA() called while another action is in progress");
        registerMe(device);
        setCallback(eastl::move(callback));
        setState(PlayCDDAActionState::GETTD);
        m_stopAtEndOfTrack = stopAtEndOfTrack;
        eastl::atomic_signal_fence(eastl::memory_order_release);
        psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::GETTD, psyqo::itob(track));
    }
    void start(psyqo::CDRomDevice *device, psyqo::MSF msf, bool stopAtEndOfTrack,
               eastl::function<void(bool)> &&callback) {
        psyqo::Kernel::assert(getState() == PlayCDDAActionState::IDLE,
                              "CDRomDevice::playCDDA() called while another action is in progress");
        registerMe(device);
        setCallback(eastl::move(callback));
        setState(PlayCDDAActionState::SEEK);
        m_start = msf;
        eastl::atomic_signal_fence(eastl::memory_order_release);
        psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::SETMODE, stopAtEndOfTrack ? 0x02 : 0);
    }
    bool complete(const psyqo::CDRomDevice::Response &) override {
        psyqo::Kernel::assert(getState() == PlayCDDAActionState::SEEK_ACK,
                              "PlayCDDAAction got CDROM complete in wrong state");
        setState(PlayCDDAActionState::PLAY);
        psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::PLAY);
        return false;
    }
    bool acknowledge(const psyqo::CDRomDevice::Response &response) override {
        switch (getState()) {
            case PlayCDDAActionState::GETTD:
                m_start.m = psyqo::btoi(response[1]);
                m_start.s = psyqo::btoi(response[2]);
                m_start.f = 0;
                setState(PlayCDDAActionState::SETMODE);
                psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::SETMODE,
                                                     m_stopAtEndOfTrack ? 0x02 : 0);
                break;
            case PlayCDDAActionState::SETMODE:
                setState(PlayCDDAActionState::SETLOC);
                psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::SETLOC, m_start.m, m_start.s,
                                                     m_start.f);
                break;
            case PlayCDDAActionState::SETLOC:
                setState(PlayCDDAActionState::SEEK);
                psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::SEEKP);
                break;
            case PlayCDDAActionState::SEEK:
                setState(PlayCDDAActionState::SEEK_ACK);
                break;
            case PlayCDDAActionState::PLAY:
                setState(PlayCDDAActionState::PLAYING);
                break;
            default:
                psyqo::Kernel::abort("PlayCDDAAction got CDROM acknowledge in wrong state");
                break;
        }
        return false;
    }
    bool end(const psyqo::CDRomDevice::Response &) override {
        psyqo::Kernel::assert(getState() == PlayCDDAActionState::PLAYING,
                              "PlayCDDAAction got CDROM end in wrong state");
        setSuccess(true);
        return true;
    }
    psyqo::MSF m_start;
    bool m_stopAtEndOfTrack = false;
};

}  // namespace

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

#ifdef DEBUG_CDROM_RESPONSES
    if (m_blocking) {
        ramsyscall_printf("Got CD-Rom response:");
        for (auto byte : response) {
            ramsyscall_printf(" %02x", byte);
        }
        syscall_puts("\n");
    } else {
        Kernel::queueCallbackFromISR([response]() {
            ramsyscall_printf("Got CD-Rom response:");
            for (auto byte : response) {
                ramsyscall_printf(" %02x", byte);
            }
            syscall_puts("\n");
        });
    }
#endif

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
        case 5: {
            m_success = false;
            callCallback = true;
#ifdef DEBUG_CDROM_ERRORS
            m_callback = [callback = eastl::move(m_callback), name = m_action->name(),
                          response = eastl::move(response)](bool) {
                ramsyscall_printf("Got CD-Rom error during action %s:", name);
                for (auto byte : response) {
                    ramsyscall_printf(" %02x", byte);
                }
                syscall_puts("\n");
                callback(false);
            };
#endif
        } break;
        default:
            Kernel::abort("CDRomDevice::irq() invoked with unknown cause");
            break;
    }

    if (callCallback) {
        Kernel::assert(!!m_callback, "Wrong CDRomDevice state");
        m_action = nullptr;
        if (m_blocking) {
            actionComplete();
        } else {
            eastl::atomic_signal_fence(eastl::memory_order_acquire);
            Kernel::queueCallbackFromISR([this]() { actionComplete(); });
        }
    }
}

psyqo::CDRomDevice::BlockingAction::BlockingAction(CDRomDevice *device, GPU &gpu) : m_device(device), m_gpu(gpu) {
    device->m_blocking = true;
    Hardware::CPU::IMask.clear(Hardware::CPU::IRQ::CDRom);
}

psyqo::CDRomDevice::BlockingAction::~BlockingAction() {
    auto device = m_device;
    auto gpu = &m_gpu;
    while (device->m_state != 0) {
        if (Hardware::CPU::IReg.isSet(Hardware::CPU::IRQ::CDRom)) {
            Hardware::CPU::IReg.clear(Hardware::CPU::IRQ::CDRom);
            device->irq();
        }
        gpu->pumpCallbacks();
    }
    device->m_blocking = false;
    Hardware::CPU::IMask.set(Hardware::CPU::IRQ::CDRom);
}

void psyqo::CDRomDevice::actionComplete() {
    auto callback = eastl::move(m_callback);
    m_callback = nullptr;
    auto success = m_success;
    m_success = false;
    m_state = 0;
    callback(success);
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
