/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#pragma once

#include <stdint.h>

#include <array>
#include <atomic>

#define MA_NO_DECODING
#define MA_NO_ENCODING
#define MA_NO_WAV
#define MA_NO_FLAC
#define MA_NO_MP3
#define MA_NO_GENERATION

#include "miniaudio/miniaudio.h"
#include "support/circular.h"
#include "support/eventbus.h"

#ifdef _MSC_VER
#define HAS_ATOMIC_WAIT 1
#else
#define HAS_ATOMIC_WAIT 0
#endif

namespace PCSX {
namespace SPU {

class MiniAudio {
  public:
    struct Frame {
        int16_t L = 0, R = 0;
    };
    MiniAudio(bool& muted);
    void setup() {}
    void remove();
    bool feedStreamData(const Frame* data, size_t frames, unsigned streamId = 0) {
        switch (streamId) {
            case 0:
                return m_voicesStream.enqueue(data, frames);
                break;
            case 1:
                return m_audioStream.enqueue(data, frames);
                break;
            default:
                throw std::runtime_error("Invalid stream ID");
                return false;
        }
    }
    size_t getBytesBuffered(unsigned streamId = 0) {
        switch (streamId) {
            case 0:
                return m_voicesStream.buffered();
                break;
            case 1:
                return m_audioStream.buffered();
                break;
            default:
                throw std::runtime_error("Invalid stream ID");
                return false;
        }
    }
    uint32_t getCurrentFrames() { return m_frames.load(); }
    void waitForGoal(uint32_t goal) {
#if HAS_ATOMIC_WAIT
        // for once, Visual Studio is better than clang/gcc/libc++/libstdc++. Its C++20
        // support contain the appropriate wait/notify on atomics, so we can do this:
        auto triggered = m_triggered.load();
        m_goalpost.store(goal);
        m_triggered.wait(triggered);
#else
        // and until the rest of the world catches on, we'll have to do this instead:
        std::unique_lock<std::mutex> l(m_mu);
        auto triggered = m_triggered;
        m_goalpost = goal;
        m_cv.wait(l, [this, triggered]() { return m_triggered != triggered; });
#endif
    }

  private:
    static constexpr unsigned STREAMS = 2;
    bool& m_muted;
    void callback(ma_device* device, float* output, ma_uint32 frameCount);

    ma_device m_device;
    EventBus::Listener m_listener;

    typedef Circular<Frame> VoiceStream;
    VoiceStream m_voicesStream;
    Circular<Frame, 16 * 1024> m_audioStream;
    typedef std::array<Frame, VoiceStream::BUFFER_SIZE> Buffer;
    std::atomic<uint32_t> m_frames = 0;
#if HAS_ATOMIC_WAIT
    std::atomic<uint32_t> m_goalpost = 0;
    std::atomic<uint32_t> m_triggered = 0;
#else
    uint32_t m_goalpost = 0;
    uint32_t m_triggered = 0;
    std::mutex m_mu;
    std::condition_variable m_cv;
#endif
    uint32_t m_previousGoalpost = 0;
};

}  // namespace SPU
}  // namespace PCSX
