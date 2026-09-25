/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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
#include <condition_variable>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <SDL3/SDL.h>

#include "lua/luawrapper.h"
#include "spu/settings.h"
#include "support/circular.h"
#include "support/eventbus.h"
#include "supportpsx/adpcm.h"

#if defined(_MSC_VER) || defined(__linux__)
#define HAS_ATOMIC_WAIT 1
#else
#define HAS_ATOMIC_WAIT 0
#endif

namespace PCSX {
namespace SPU {

class SDLAudio {
  public:
    struct Frame {
        int16_t L = 0, R = 0;
    };

    // Standalone sound playback, independent of the emulated SPU. These sounds go through a second
    // logical SDL audio device, opened on the same physical device as the emulator's output, and which
    // is not paused along with the emulation. Each sound gets its own SDL audio stream, so SDL takes
    // care of the format conversion, resampling, and mixing.
    struct SoundDescriptor {
        enum class Format { PCM, SPU, XA };
        Format format = Format::PCM;
        // PCM: 8 or 16. XA: 4 or 8. Unused for SPU.
        unsigned bits = 16;
        // PCM only. 16-bit samples are little endian.
        bool isSigned = true;
        // PCM and XA: 1 or 2. SPU is always mono.
        unsigned channels = 1;
        // Sample rate in Hz. XA: 37800 or 18900.
        unsigned rate = 44100;
        // XA only: the data is made of CD sectors instead of raw 128-byte sound groups, and the format
        // is read from the sectors' subheaders instead of the fields above.
        bool sectors = false;
        // XA sectors only: if not negative, only play the sectors with this file / channel number.
        int xaFile = -1;
        int xaChannel = -1;
        float gain = 1.0f;
    };

    class Sound {
      public:
        ~Sound();
        void stop();
        bool isPlaying();
        void setGain(float gain);

      private:
        friend class SDLAudio;
        Sound() = default;
        void detach();
        void spuCallback(SDL_AudioStream* stream, int additionalBytes);

        SDLAudio* m_owner = nullptr;
        SDL_AudioStream* m_stream = nullptr;
        float m_gain = 1.0f;
        // True while the SPU refill callback still has data to produce.
        std::atomic<bool> m_feeding = false;
        // SPU decoding state. Once the stream is bound, this is only touched from the SDL audio thread,
        // by the stream callback, until the stream is destroyed.
        std::vector<uint8_t> m_spuData;
        size_t m_spuPosition = 0;
        size_t m_spuLoopStart = 0;
        ADPCM::Decoder m_decoder;
    };

    // Starts playing the given data. The data is copied or decoded before this returns, so the caller
    // doesn't need to keep it alive. On error, returns nullptr, and sets the error string.
    std::shared_ptr<Sound> playSound(const uint8_t* data, size_t size, const SoundDescriptor& descriptor,
                                     std::string& error);
    // Applies the Mute setting to the sounds played through playSound.
    void updatePlaybackMute();
    // Exposes the above to Lua, as PCSX.SPU.playAudio.
    void setLua(Lua L);

    SDLAudio(SettingsType& settings);
    ~SDLAudio() { uninit(); }
    uint32_t getFrameCount() { return m_frameCount.load(); }
    void reinit() {
        uninit();
        init();
        maybeRestart();
    }
    const std::vector<std::string>& getBackends() { return m_backends; }
    const std::vector<std::string>& getDevices() { return m_devices; }
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
    static constexpr int kSampleRate = 44100;
    static constexpr int kChannels = 2;
    static constexpr int kPeriodFrames = 64;

    SettingsType& m_settings;

    void streamCallback(SDL_AudioStream* stream, int additionalBytes);
    void advanceFrames(uint32_t frameCount);
    void init(bool safe = false);
    void uninit();
    void maybeRestart();
    void startNullThread();
    void stopNullThread();
    void nullThreadLoop();

    SDL_AudioDeviceID m_device = 0;
    SDL_AudioStream* m_stream = nullptr;
    bool m_audioInitialized = false;

    // Second logical device for standalone sounds, and the sounds currently attached to it.
    // Only touched from the main thread.
    void openPlaybackDevice(SDL_AudioDeviceID physical);
    void closePlaybackDevice();
    SDL_AudioDeviceID m_playbackDevice = 0;
    std::set<Sound*> m_sounds;

    std::thread m_nullThread;
    std::atomic<bool> m_nullThreadStop{false};
    bool m_nullThreadActive = false;

    EventBus::Listener m_listener;

    typedef Circular<Frame, 2 * 1024> VoiceStream;
    VoiceStream m_voicesStream;
    Circular<Frame, 16 * 1024> m_audioStream;
    typedef std::array<Frame, VoiceStream::BUFFER_SIZE> Buffer;

    // Mixing scratch space, only ever touched from the SDL audio thread.
    std::array<Buffer, STREAMS> m_mixBuffers;
    std::array<float, VoiceStream::BUFFER_SIZE * kChannels> m_outputBuffer;

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

    std::vector<std::string> m_backends;
    std::vector<std::string> m_devices;

    std::atomic<uint32_t> m_frameCount{0};
};

}  // namespace SPU
}  // namespace PCSX
