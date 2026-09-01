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

enum class MuteActionState : uint8_t {
    IDLE,
    MUTE,
};

class MuteAction : public psyqo::CDRomDevice::Action<MuteActionState> {
  public:
    MuteAction() : Action("MuteAction") {}
    void start(psyqo::CDRomDevice *device, eastl::function<void(bool)> &&callback) {
        psyqo::Kernel::assert(device->isIdle(), "CDRomDevice::mute() called while another action is in progress");
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
        psyqo::Kernel::assert(device->isIdle(), "CDRomDevice::unmute() called while another action is in progress");
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
