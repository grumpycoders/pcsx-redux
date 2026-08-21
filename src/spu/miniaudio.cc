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

#include "spu/miniaudio.h"

#include <limits>
#include <stdexcept>

#include "core/system.h"
#include "spu/interface.h"

#define MINIAUDIO_IMPLEMENTATION
#include "miniaudio/miniaudio.h"

// Upper clamp for the sink speed multiplier. Any host is emulation-bound long before this, so a value
// at or beyond it behaves as "unbounded" (the CPU's audio goalpost is always already satisfied and the
// producer rings are drained dry every callback). A configured speed <= 0 is treated as unbounded too.
static constexpr int kMaxSpeed = 1024;

static int effectiveSpeed(int configured) {
    if (configured <= 0 || configured > kMaxSpeed) return kMaxSpeed;
    return configured;
}

PCSX::SPU::MiniAudio::MiniAudio(PCSX::SPU::SettingsType& settings)
    : m_settings(settings), m_listener(g_system->m_eventBus) {
    for (unsigned i = 0; i <= ma_backend_null; i++) {
        ma_backend b = ma_backend(i);
        if (ma_is_backend_enabled(b)) {
            m_backends.push_back(ma_get_backend_name(b));
        }
    }
    m_listener.listen<Events::ExecutionFlow::Run>([this](const auto& event) {
        if (ma_device_start(&m_device) != MA_SUCCESS) {
            uninit();
            init(true);
        }
        if (!m_settings.get<NullSync>()) return;
        if (ma_device_start(&m_deviceNull) != MA_SUCCESS) {
            throw std::runtime_error("Unable to start NULL audio device");
        }
    });
    m_listener.listen<Events::ExecutionFlow::Pause>([this](const auto& event) {
        if (ma_device_stop(&m_device) != MA_SUCCESS) {
            throw std::runtime_error("Unable to stop audio device");
        };
        if (!ma_device_is_started(&m_deviceNull)) return;
        if (ma_device_stop(&m_deviceNull) != MA_SUCCESS) {
            throw std::runtime_error("Unable to stop NULL audio device");
        };
    });
    m_listener.listen<Events::SettingsLoaded>([this](const auto& event) { init(event.safe); });
}

void PCSX::SPU::MiniAudio::init(bool safe) {
    // First, initialize NULL device
    ma_backend nullContext = ma_backend_null;
    if (ma_context_init(&nullContext, 1, NULL, &m_contextNull) != MA_SUCCESS) {
        throw std::runtime_error("Error initializing NULL miniaudio context");
    }

    m_configNull = ma_device_config_init(ma_device_type_playback);
    m_configNull.playback.format = ma_format_f32;
    m_configNull.playback.channels = 2;
    m_configNull.sampleRate = 44100;
    m_configNull.periodSizeInFrames = 64;
    m_configNull.periods = 2;
    m_configNull.pUserData = this;

    m_configNull.dataCallback = [](ma_device* device, void* output, const void* input, ma_uint32 frameCount) {
        MiniAudio* self = reinterpret_cast<MiniAudio*>(device->pUserData);
        self->callbackNull(device, reinterpret_cast<float*>(output), frameCount);
    };

    if (ma_device_init(&m_contextNull, &m_configNull, &m_deviceNull) != MA_SUCCESS) {
        throw std::runtime_error("Unable to initialize NULL audio device");
    }

    // Then probe for actual device, and initialize it
    ma_backend backends[ma_backend_null + 1];
    unsigned count = 0;
    if (safe) {
        backends[0] = ma_backend_null;
        count = 1;
    } else {
        bool found = false;
        for (unsigned i = 0; i <= ma_backend_null; i++) {
            ma_backend b = ma_backend(i);
            if (!ma_is_backend_enabled(b)) continue;
            backends[count++] = b;
            if (ma_get_backend_name(b) == m_settings.get<Backend>().value) {
                found = true;
                count = 1;
                backends[0] = b;
                break;
            }
        }
        if (!found) {
            m_settings.get<Backend>().reset();
        }
    }
    if (ma_context_init(backends, count, NULL, &m_context) != MA_SUCCESS) {
        throw std::runtime_error("Error initializing miniaudio context");
    }

    m_devices.clear();
    struct UserContext {
        MiniAudio* miniAudio;
        ma_device_config& config;
        bool found = false;
    };
    UserContext userContext = {this, m_config};

    ma_context_enumerate_devices(
        &m_context,
        [](ma_context* pContext, ma_device_type deviceType, const ma_device_info* pInfo, void* pUserData) -> ma_bool32 {
            if (deviceType != ma_device_type_playback) return true;
            UserContext* userContext = reinterpret_cast<UserContext*>(pUserData);
            userContext->miniAudio->m_devices.push_back(pInfo->name);
            if (pInfo->name == userContext->miniAudio->m_settings.get<Device>().value) {
                userContext->config.playback.pDeviceID = &pInfo->id;
                userContext->found = true;
            }
            return true;
        },
        &userContext);

    if (!userContext.found) {
        m_settings.get<Device>().reset();
    }

    m_config = ma_device_config_init(ma_device_type_playback);
    m_config.playback.format = ma_format_f32;
    m_config.playback.channels = 2;
    m_config.sampleRate = 44100;
    m_config.periodSizeInFrames = 64;
    m_config.periods = 2;
    m_config.pUserData = this;
    m_config.aaudio.usage = ma_aaudio_usage_game;
    m_config.wasapi.noAutoConvertSRC = true;

    m_config.dataCallback = [](ma_device* device, void* output, const void* input, ma_uint32 frameCount) {
        MiniAudio* self = reinterpret_cast<MiniAudio*>(device->pUserData);
        self->callback(device, reinterpret_cast<float*>(output), frameCount);
    };

    if (ma_device_init(&m_context, &m_config, &m_device) != MA_SUCCESS) {
        if (safe) {
            throw std::runtime_error("Unable to initialize NULL audio device");
        }
        uninit();
        init(true);
    }
}

void PCSX::SPU::MiniAudio::uninit() {
    ma_device_uninit(&m_device);
    ma_device_uninit(&m_deviceNull);
    ma_context_uninit(&m_context);
}

void PCSX::SPU::MiniAudio::maybeRestart() {
    if (!g_system->running()) return;

    if (ma_device_start(&m_device) != MA_SUCCESS) {
        uninit();
        init(true);
    }
    if (!m_settings.get<NullSync>()) return;
    if (ma_device_start(&m_deviceNull) != MA_SUCCESS) {
        throw std::runtime_error("Unable to start NULL audio device");
    }
}

void PCSX::SPU::MiniAudio::callback(ma_device* device, float* output, ma_uint32 frameCount) {
    if (frameCount > VoiceStream::BUFFER_SIZE) {
        throw std::runtime_error("Too many frames requested by miniaudio");
    }
    static std::array<Buffer, STREAMS> buffers;
    const bool mono = m_settings.get<Mono>();
    const bool muted = m_settings.get<Mute>();

    static_assert(STREAMS == 2);

    for (unsigned i = 0; i < STREAMS; i++) {
        size_t a = i == 0 ? m_voicesStream.dequeue(buffers[i].data(), frameCount)
                          : m_audioStream.dequeue(buffers[i].data(), frameCount);
        for (size_t f = (muted ? 0 : a); f < frameCount; f++) {
            // maybe warn about underflow? tho it's fine if it happens on stream 1 (cdda)
            buffers[i][f] = {};
        }
    }

    for (ma_uint32 f = 0; f < frameCount; f++) {
        float l = 0.0f, r = 0.0f;
        for (unsigned i = 0; i < STREAMS; i++) {
            l += static_cast<float>(buffers[i][f].L) / static_cast<float>(std::numeric_limits<int16_t>::max());
            r += static_cast<float>(buffers[i][f].R) / static_cast<float>(std::numeric_limits<int16_t>::max());
        }

        if (mono) {
            const float lr = (l + r) * 0.5f;
            output[f * 2 + 0] = lr;
            output[f * 2 + 1] = lr;
        } else {
            output[f * 2 + 0] = l;
            output[f * 2 + 1] = r;
        }
    }

    // Fast-forward lives at the sink (the master clock). We have already kept the first frameCount
    // frames of each stream for playback at native 44.1kHz -- pitch is preserved. To run the whole
    // emulator `speed` times faster we drain the producer rings `speed` times faster: discard the
    // additional (speed - 1) frame-runs from BOTH streams (SPU voices and CD-ROM XA). Draining the
    // rings faster paces the SPU thread faster, which through waitForGoal paces the CPU thread faster.
    // dequeue() naturally caps at what is available, so this is safe (and self-limits) at any speed.
    const int speed = effectiveSpeed(m_settings.get<Speed>().value);
    for (int rep = 1; rep < speed; rep++) {
        m_voicesStream.dequeue(buffers[0].data(), frameCount);
        m_audioStream.dequeue(buffers[1].data(), frameCount);
    }

    if (m_settings.get<NullSync>()) return;

    callbackNull(device, output, frameCount);
}

void PCSX::SPU::MiniAudio::callbackNull(ma_device* device, float* output, ma_uint32 frameCount) {
    m_frameCount.store(frameCount);

    // Advance the master clock `speed` times faster than realtime. m_frames is the frame counter the
    // CPU thread waits on in waitForGoal(); the CPU's goalpost grows at the realtime rate per emulated
    // cycle, so advancing m_frames `speed` times faster makes the CPU reach its goalpost (and thus run)
    // `speed` times faster. At speed == 1 this is byte-identical to the previous fetch_add(frameCount).
    const int speed = effectiveSpeed(m_settings.get<Speed>().value);
    auto total = m_frames.fetch_add(frameCount * static_cast<uint32_t>(speed));

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
