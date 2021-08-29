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

#define MINIAUDIO_IMPLEMENTATION
#include "miniaudio/miniaudio.h"

PCSX::SPU::MiniAudio::MiniAudio(bool& muted) : m_muted(muted), m_listener(g_system->m_eventBus) {
    ma_device_config config = ma_device_config_init(ma_device_type_playback);
    config.playback.format = ma_format_f32;
    config.playback.channels = 2;
    config.sampleRate = 44100;
    config.periodSizeInFrames = 128;
    config.periods = 2;
    config.dataCallback = [](ma_device* device, void* output, const void* input, ma_uint32 frameCount) {
        MiniAudio* self = reinterpret_cast<MiniAudio*>(device->pUserData);
        self->callback(device, reinterpret_cast<float*>(output), frameCount);
    };
    config.pUserData = this;

    if (ma_device_init(NULL, &config, &m_device) != MA_SUCCESS) {
        throw std::runtime_error("Unable to initialize audio device");
    }

    m_listener.listen<Events::ExecutionFlow::Run>([this](const auto& event) {
        if (ma_device_start(&m_device) != MA_SUCCESS) {
            throw std::runtime_error("Unable to start audio device");
        }
    });
    m_listener.listen<Events::ExecutionFlow::Pause>([this](const auto& event) {
        if (ma_device_stop(&m_device) != MA_SUCCESS) {
            throw std::runtime_error("Unable to stop audio device");
        };
    });
}

void PCSX::SPU::MiniAudio::remove() { ma_device_uninit(&m_device); }

void PCSX::SPU::MiniAudio::callback(ma_device* device, float* output, ma_uint32 frameCount) {
    if (frameCount > Stream::BUFFER_SIZE) {
        throw std::runtime_error("Too many frames requested by miniaudio");
    }
    std::array<Buffer, STREAMS> buffers;
    const bool muted = m_muted;

    for (unsigned i = 0; i < STREAMS; i++) {
        size_t a = m_streams[i].dequeue(buffers[i].data(), frameCount);
        for (size_t f = a; a < frameCount; a++) {
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
        output[f * 2 + 0] = l;
        output[f * 2 + 1] = r;
    }

    auto total = m_frames.fetch_add(frameCount);
    auto goalpost = m_goalpost.load();
    if (goalpost == m_previousGoalpost) return;

    if (((int32_t)(goalpost - total)) > 0) return;
    m_previousGoalpost = goalpost;
    m_triggered++;
    m_triggered.notify_one();
}
