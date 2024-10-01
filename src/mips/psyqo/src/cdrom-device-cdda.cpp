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
#include "psyqo/msf.hh"

namespace {

enum class PlayCDDAActionState : uint8_t {
    IDLE,
    GETTD,
    SETMODE,
    SETLOC,
    SEEK,
    SEEK_ACK,
    PLAY,
    // needs to stay unique across all actions, and
    // will be hardcoded in the pause command
    PLAYING = 100,
    STOPPING = 101,
    STOPPING_ACK,
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
        psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::SETMODE, stopAtEndOfTrack ? 3 : 1);
    }
    void start(psyqo::CDRomDevice *device, eastl::function<void(bool)> &&callback) {
        psyqo::Kernel::assert(getState() == PlayCDDAActionState::IDLE,
                              "CDRomDevice::playCDDA() called while another action is in progress");
        registerMe(device);
        setCallback(eastl::move(callback));
        setState(PlayCDDAActionState::PLAY);
        eastl::atomic_signal_fence(eastl::memory_order_release);
        psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::PLAY);
    }
    bool complete(const psyqo::CDRomDevice::Response &) override {
        switch (getState()) {
            case PlayCDDAActionState::SEEK_ACK:
                setState(PlayCDDAActionState::PLAY);
                psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::PLAY);
                break;
            case PlayCDDAActionState::STOPPING_ACK:
                setSuccess(true);
                return true;
            default:
                psyqo::Kernel::abort("PlayCDDAAction got CDROM complete in wrong state");
                break;
        }
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
                psyqo::Hardware::CDRom::Command.send(psyqo::Hardware::CDRom::CDL::SETLOC, psyqo::itob(m_start.m),
                                                     psyqo::itob(m_start.s), psyqo::itob(m_start.f));
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
                queueCallbackFromISR(true);
                break;
            case PlayCDDAActionState::PLAYING: {
                auto locationPtr = getPendingLocationPtr();
                psyqo::Kernel::assert((response.size() == 8) && locationPtr,
                                      "PlayCDDAAction got unexpected CDROM acknowledge");
                locationPtr->track = psyqo::btoi(response[0]);
                locationPtr->index = psyqo::btoi(response[1]);
                locationPtr->relative.m = psyqo::btoi(response[2]);
                locationPtr->relative.s = psyqo::btoi(response[3]);
                locationPtr->relative.f = psyqo::btoi(response[4]);
                locationPtr->absolute.m = psyqo::btoi(response[5]);
                locationPtr->absolute.s = psyqo::btoi(response[6]);
                locationPtr->absolute.f = psyqo::btoi(response[7]);
                queueGetLocationCallback();
            } break;
            case PlayCDDAActionState::STOPPING:
                setState(PlayCDDAActionState::STOPPING_ACK);
                break;
            default:
                psyqo::Kernel::abort("PlayCDDAAction got CDROM acknowledge in wrong state");
                break;
        }
        return false;
    }
    bool end(const psyqo::CDRomDevice::Response &) override {
        // We got raced to the end of the track and/or disc by the
        // pause command, so we should just ignore this.
        if (getState() == PlayCDDAActionState::STOPPING) return false;
        // We got raced to the end of the track and/or disc by the
        // get location command, and we need to signal the callback.
        if (getPendingLocationPtr()) {
            queueGetLocationCallback(false);
        }
        psyqo::Kernel::assert(getState() == PlayCDDAActionState::PLAYING,
                              "PlayCDDAAction got CDROM end in wrong state");
        setSuccess(true);
        return true;
    }
    psyqo::MSF m_start;
    bool m_stopAtEndOfTrack = false;
};

PlayCDDAAction s_playCDDAAction;

}  // namespace

void psyqo::CDRomDevice::playCDDATrack(unsigned track, eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::playCDDATrack called with pending action");
    s_playCDDAAction.start(this, track, true, eastl::move(callback));
}

void psyqo::CDRomDevice::playCDDATrack(MSF start, eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::playCDDATrack called with pending action");
    s_playCDDAAction.start(this, start, true, eastl::move(callback));
}

void psyqo::CDRomDevice::playCDDADisc(unsigned track, eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::playCDDADisc called with pending action");
    s_playCDDAAction.start(this, track, false, eastl::move(callback));
}

void psyqo::CDRomDevice::playCDDADisc(MSF start, eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::playCDDADisc called with pending action");
    s_playCDDAAction.start(this, start, false, eastl::move(callback));
}

void psyqo::CDRomDevice::resumeCDDA(eastl::function<void(bool)> &&callback) {
    Kernel::assert(m_callback == nullptr, "CDRomDevice::resumeCDDA called with pending action");
    s_playCDDAAction.start(this, eastl::move(callback));
}

void psyqo::CDRomDevice::getPlaybackLocation(eastl::function<void(PlaybackLocation *)> &&callback) {
    Kernel::assert(m_locationCallback == nullptr, "CDRomDevice::getPlaybackLocation while another one is pending");
    m_locationCallback = eastl::move(callback);
    m_locationPtr = &m_locationStorage;
    __asm__ volatile("break 14, 3");
}

void psyqo::CDRomDevice::getPlaybackLocation(PlaybackLocation *location,
                                             eastl::function<void(PlaybackLocation *)> &&callback) {
    Kernel::assert(m_locationCallback == nullptr, "CDRomDevice::getPlaybackLocation while another one is pending");
    m_locationCallback = eastl::move(callback);
    m_locationPtr = location ? location : &m_locationStorage;
    __asm__ volatile("break 14, 3");
}

psyqo::TaskQueue::Task psyqo::CDRomDevice::scheduleGetPlaybackLocation(PlaybackLocation *location) {
    return TaskQueue::Task([this, location](auto task) {
        getPlaybackLocation(location, [task](PlaybackLocation *loc) { task->complete(loc != nullptr); });
    });
}

psyqo::CDRomDevice::PlaybackLocation *psyqo::CDRomDevice::ActionBase::getPendingLocationPtr() const {
    return m_device->m_pendingGetLocation ? m_device->m_locationPtr : nullptr;
}

void psyqo::CDRomDevice::ActionBase::queueGetLocationCallback(bool success) {
    auto device = m_device;
    device->m_pendingGetLocation = false;
    if (!success) device->m_locationPtr = nullptr;
    Kernel::queueCallbackFromISR([device]() {
        auto callback = eastl::move(device->m_locationCallback);
        callback(device->m_locationPtr);
    });
}

void psyqo::CDRomDevice::setVolume(uint8_t leftToLeft, uint8_t rightToLeft, uint8_t leftToRight, uint8_t rightToRight) {
    m_leftToLeft = leftToLeft;
    m_rightToLeft = rightToLeft;
    m_leftToRight = leftToRight;
    m_rightToRight = rightToRight;
    __asm__ volatile("break 14, 4");
}
