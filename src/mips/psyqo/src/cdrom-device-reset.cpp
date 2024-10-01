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
#include "psyqo/hardware/cdrom.hh"
#include "psyqo/kernel.hh"

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

bool psyqo::CDRomDevice::resetBlocking(GPU &gpu) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::resetBlocking called with pending action");
    unsigned size = 0;
    bool success = false;
    {
        BlockingAction blocking(this, gpu);
        s_resetAction.start(this, [&success](bool success_) { success = success_; });
    }
    return success;
}
