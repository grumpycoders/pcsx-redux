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
#include "psyqo/hardware/cdrom.hh"
#include "psyqo/hardware/sbus.hh"
#include "psyqo/kernel.hh"
#include "psyqo/msf.hh"


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
