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

#include "spu/sdlaudio.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>

#include "core/psxemulator.h"
#include "core/system.h"
#include "spu/interface.h"

uint32_t PCSX::SPU::SDLAudio::sourceFramesForOutput(uint32_t outN, int scale) {
    if (outN == 0) return 0;
    if (scale <= 0) scale = 1;
    const uint32_t inN = static_cast<uint32_t>((static_cast<uint64_t>(outN) * static_cast<uint32_t>(scale)) / 100);
    return inN < 1 ? 1 : inN;
}

void PCSX::SPU::SDLAudio::scalerSelfCheck() {
    assert(sourceFramesForOutput(100, 100) == 100);
    assert(sourceFramesForOutput(100, 200) == 200);
    assert(sourceFramesForOutput(100, 50) == 50);
    assert(sourceFramesForOutput(1, 200) == 2);
    assert(sourceFramesForOutput(0, 200) == 0);
}

PCSX::SPU::SDLAudio::SDLAudio(PCSX::SPU::SettingsType& settings)
    : m_settings(settings), m_listener(g_system->m_eventBus) {
    // Enumerate compiled-in drivers. This is static information available before
    // SDL_InitSubSystem(SDL_INIT_AUDIO), so we can present the list in the UI without
    // forcing an early audio init.
    int n = SDL_GetNumAudioDrivers();
    for (int i = 0; i < n; i++) {
        const char* name = SDL_GetAudioDriver(i);
        if (name) m_backends.emplace_back(name);
    }

    m_listener.listen<Events::ExecutionFlow::Run>([this](const auto& event) {
        if (!m_audioInitialized) return;
        if (!SDL_ResumeAudioDevice(m_device)) {
            uninit();
            init(true);
        }
        if (m_settings.get<NullSync>()) startNullThread();
    });
    m_listener.listen<Events::ExecutionFlow::Pause>([this](const auto& event) {
        if (!m_audioInitialized) return;
        SDL_PauseAudioDevice(m_device);
        stopNullThread();
    });
    m_listener.listen<Events::SettingsLoaded>([this](const auto& event) { init(event.safe); });
}

void PCSX::SPU::SDLAudio::init(bool safe) {
    scalerSelfCheck();

    // Pick the audio driver. SDL_HINT_AUDIO_DRIVER must be set before SDL_InitSubSystem.
    if (safe) {
        SDL_SetHint(SDL_HINT_AUDIO_DRIVER, "dummy");
    } else {
        const std::string& wanted = m_settings.get<Backend>().value;
        bool found = false;
        for (const auto& b : m_backends) {
            if (b == wanted) {
                SDL_SetHint(SDL_HINT_AUDIO_DRIVER, b.c_str());
                found = true;
                break;
            }
        }
        if (!found) {
            m_settings.get<Backend>().reset();
            // Empty string lets SDL pick whatever default it likes.
            SDL_SetHint(SDL_HINT_AUDIO_DRIVER, "");
        }
    }

    // Suggest a small period to keep latency low. SDL treats this as a hint; the actual
    // callback chunk size may differ, which is why streamCallback handles arbitrary sizes.
    SDL_SetHint(SDL_HINT_AUDIO_DEVICE_SAMPLE_FRAMES, "64");

    if (!SDL_InitSubSystem(SDL_INIT_AUDIO)) {
        if (safe) {
            throw std::runtime_error(std::string("Unable to initialize SDL audio: ") + SDL_GetError());
        }
        uninit();
        init(true);
        return;
    }
    m_audioInitialized = true;

    // Enumerate playback devices and locate the user's saved choice, if any.
    m_devices.clear();
    SDL_AudioDeviceID chosen = SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK;
    bool deviceFound = false;
    int devCount = 0;
    SDL_AudioDeviceID* ids = SDL_GetAudioPlaybackDevices(&devCount);
    if (ids) {
        const std::string& wantedDev = m_settings.get<Device>().value;
        for (int i = 0; i < devCount; i++) {
            const char* name = SDL_GetAudioDeviceName(ids[i]);
            if (!name) continue;
            m_devices.emplace_back(name);
            if (name == wantedDev) {
                chosen = ids[i];
                deviceFound = true;
            }
        }
        SDL_free(ids);
    }
    if (!deviceFound) {
        m_settings.get<Device>().reset();
    }

    SDL_AudioSpec spec;
    spec.format = SDL_AUDIO_F32;
    spec.channels = kChannels;
    spec.freq = kSampleRate;

    m_device = SDL_OpenAudioDevice(chosen, &spec);
    if (m_device == 0) {
        if (safe) {
            throw std::runtime_error(std::string("Unable to open SDL audio device: ") + SDL_GetError());
        }
        uninit();
        init(true);
        return;
    }

    m_stream = SDL_CreateAudioStream(&spec, &spec);
    if (!m_stream) {
        const std::string err = SDL_GetError();
        SDL_CloseAudioDevice(m_device);
        m_device = 0;
        if (safe) {
            throw std::runtime_error("Unable to create SDL audio stream: " + err);
        }
        uninit();
        init(true);
        return;
    }

    auto trampoline = [](void* userdata, SDL_AudioStream* stream, int additional, int /*total*/) {
        static_cast<SDLAudio*>(userdata)->streamCallback(stream, additional);
    };
    if (!SDL_SetAudioStreamGetCallback(m_stream, trampoline, this)) {
        const std::string err = SDL_GetError();
        SDL_DestroyAudioStream(m_stream);
        m_stream = nullptr;
        SDL_CloseAudioDevice(m_device);
        m_device = 0;
        throw std::runtime_error("Unable to set SDL audio stream callback: " + err);
    }

    if (!SDL_BindAudioStream(m_device, m_stream)) {
        const std::string err = SDL_GetError();
        SDL_DestroyAudioStream(m_stream);
        m_stream = nullptr;
        SDL_CloseAudioDevice(m_device);
        m_device = 0;
        throw std::runtime_error("Unable to bind SDL audio stream: " + err);
    }

    // Devices come up in the resumed state; pause until execution actually starts so
    // we don't burn cycles streaming silence at boot.
    SDL_PauseAudioDevice(m_device);
}

void PCSX::SPU::SDLAudio::uninit() {
    stopNullThread();
    if (m_stream) {
        SDL_DestroyAudioStream(m_stream);
        m_stream = nullptr;
    }
    if (m_device) {
        SDL_CloseAudioDevice(m_device);
        m_device = 0;
    }
    if (m_audioInitialized) {
        SDL_QuitSubSystem(SDL_INIT_AUDIO);
        m_audioInitialized = false;
    }
}

void PCSX::SPU::SDLAudio::maybeRestart() {
    if (!g_system->running()) return;
    if (!m_audioInitialized) return;
    if (!SDL_ResumeAudioDevice(m_device)) {
        uninit();
        init(true);
        return;
    }
    if (m_settings.get<NullSync>()) startNullThread();
}

void PCSX::SPU::SDLAudio::streamCallback(SDL_AudioStream* stream, int additionalBytes) {
    constexpr int kFrameSizeBytes = sizeof(float) * kChannels;
    int requested = additionalBytes / kFrameSizeBytes;
    if (requested <= 0) return;

    const bool mono = m_settings.get<Mono>();
    const bool muted = m_settings.get<Mute>();
    const int scale = g_emulator ? g_emulator->getScaler() : 100;

    static_assert(STREAMS == 2);

    // SDL doesn't promise a fixed callback chunk size, so feed in slices that fit our
    // mixing scratch buffer. When speeding up, source frames exceed output frames, so
    // shrink the output chunk until sourceFramesForOutput fits in BUFFER_SIZE.
    while (requested > 0) {
        uint32_t outN = std::min<uint32_t>(requested, VoiceStream::BUFFER_SIZE);
        if (scale > 100) {
            const uint32_t maxOut = std::max<uint32_t>(1, (VoiceStream::BUFFER_SIZE * 100u) / static_cast<uint32_t>(scale));
            outN = std::min(outN, maxOut);
        }
        const uint32_t inN = sourceFramesForOutput(outN, scale);

        for (unsigned i = 0; i < STREAMS; i++) {
            size_t a = (i == 0) ? m_voicesStream.dequeue(m_mixBuffers[i].data(), inN)
                                : m_audioStream.dequeue(m_mixBuffers[i].data(), inN);
            for (size_t f = (muted ? 0 : a); f < inN; f++) {
                // Same as the previous backend: silently zero-fill on underflow.
                // CDDA underflow on stream 1 is expected and fine.
                m_mixBuffers[i][f] = {};
            }
        }

        for (uint32_t o = 0; o < outN; o++) {
            float l = 0.0f, r = 0.0f;
            if (scale == 100) {
                for (unsigned i = 0; i < STREAMS; i++) {
                    l += static_cast<float>(m_mixBuffers[i][o].L) /
                         static_cast<float>(std::numeric_limits<int16_t>::max());
                    r += static_cast<float>(m_mixBuffers[i][o].R) /
                         static_cast<float>(std::numeric_limits<int16_t>::max());
                }
            } else {
                // Linear resample source → device rate so pitch tracks speed.
                const float srcPos = (static_cast<float>(o) * static_cast<float>(inN)) / static_cast<float>(outN);
                const uint32_t i0 = std::min(static_cast<uint32_t>(srcPos), inN - 1);
                const uint32_t i1 = std::min(i0 + 1, inN - 1);
                const float t = srcPos - static_cast<float>(i0);
                for (unsigned i = 0; i < STREAMS; i++) {
                    const float l0 = static_cast<float>(m_mixBuffers[i][i0].L);
                    const float l1 = static_cast<float>(m_mixBuffers[i][i1].L);
                    const float r0 = static_cast<float>(m_mixBuffers[i][i0].R);
                    const float r1 = static_cast<float>(m_mixBuffers[i][i1].R);
                    l += (l0 + (l1 - l0) * t) / static_cast<float>(std::numeric_limits<int16_t>::max());
                    r += (r0 + (r1 - r0) * t) / static_cast<float>(std::numeric_limits<int16_t>::max());
                }
            }

            if (mono) {
                const float lr = (l + r) * 0.5f;
                m_outputBuffer[o * 2 + 0] = lr;
                m_outputBuffer[o * 2 + 1] = lr;
            } else {
                m_outputBuffer[o * 2 + 0] = l;
                m_outputBuffer[o * 2 + 1] = r;
            }
        }

        SDL_PutAudioStreamData(stream, m_outputBuffer.data(), outN * kFrameSizeBytes);

        // When NullSync is off, the real audio callback is the timing source. When it's
        // on, the dedicated null thread drives timing instead. Advance by source frames
        // so waitForGoal completes sooner/later with speed.
        if (!m_settings.get<NullSync>()) {
            advanceFrames(inN);
        }

        requested -= outN;
    }
}

void PCSX::SPU::SDLAudio::advanceFrames(uint32_t frameCount) {
    m_frameCount.store(frameCount);

    auto total = m_frames.fetch_add(frameCount);

#if HAS_ATOMIC_WAIT
    auto goalpost = m_goalpost.load();
    if (goalpost == m_previousGoalpost) return;

    if (((int32_t)(goalpost - total)) > 0) return;
    m_previousGoalpost = goalpost;
    m_triggered++;
    m_triggered.notify_one();
#else
    std::unique_lock<std::mutex> l(m_mu);
    auto goalpost = m_goalpost;
    if (goalpost == m_previousGoalpost) return;

    if (((int32_t)(goalpost - total)) > 0) return;
    m_previousGoalpost = goalpost;
    m_triggered++;
    m_cv.notify_one();
#endif
}

void PCSX::SPU::SDLAudio::startNullThread() {
    if (m_nullThreadActive) return;
    m_nullThreadStop.store(false);
    m_nullThreadActive = true;
    m_nullThread = std::thread([this]() { nullThreadLoop(); });
}

void PCSX::SPU::SDLAudio::stopNullThread() {
    if (!m_nullThreadActive) return;
    m_nullThreadStop.store(true);
    if (m_nullThread.joinable()) m_nullThread.join();
    m_nullThreadActive = false;
}

void PCSX::SPU::SDLAudio::nullThreadLoop() {
    using namespace std::chrono;
    // 64 frames at 44100 Hz ~= 1.451 ms per tick. We pretend to consume that many frames
    // each tick, mirroring what miniaudio's null backend used to do for a stable timing
    // source independent of the real device's bursty callbacks. Scale the advance by the
    // effective speed so Null Sync honors turbo / Speed Scaler.
    constexpr double periodSeconds = static_cast<double>(kPeriodFrames) / kSampleRate;
    const auto periodNs = duration_cast<nanoseconds>(duration<double>(periodSeconds));
    auto next = steady_clock::now();
    while (!m_nullThreadStop.load()) {
        next += periodNs;
        std::this_thread::sleep_until(next);
        const int scale = g_emulator ? g_emulator->getScaler() : 100;
        advanceFrames(sourceFramesForOutput(kPeriodFrames, scale));
    }
}
