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

#include <EASTL/atomic.h>

#include "psyqo/cdrom-device.hh"
#include "psyqo/gpu.hh"
#include "psyqo/hardware/cdrom.hh"
#include "psyqo/kernel.hh"
#include "psyqo/msf.hh"

namespace {

enum class GetTNActionEnum : uint8_t {
    IDLE,
    GETTN,
};

class GetTNAction : public psyqo::CDRomDevice::Action<GetTNActionEnum> {
  public:
    GetTNAction() : Action("GetTNAction") {}
    void start(psyqo::CDRomDevice *device, unsigned *size, eastl::function<void(bool)> &&callback) {
        psyqo::Kernel::assert(device->isIdle(),
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
        psyqo::Kernel::assert(device->isIdle(),
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
