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

#include <stdexcept>

#define MINIAUDIO_IMPLEMENTATION
#include "miniaudio/miniaudio.h"

void PCSX::SPU::MiniAudio::setup() {
    ma_device_config config = ma_device_config_init(ma_device_type_playback);
    config.playback.format = ma_format_f32;
    config.playback.channels = 2;
    config.sampleRate = 44100;
    config.dataCallback = [](ma_device* device, void* output, const void* input, ma_uint32 frameCount) {
        MiniAudio* self = reinterpret_cast<MiniAudio*>(device->pUserData);
        self->callback(device, output, input, frameCount);
    };
    config.pUserData = this;

    if (ma_device_init(NULL, &config, &m_device) != MA_SUCCESS) {
        throw std::runtime_error("Unable to initialize audio device");
    }

    ma_device_start(&m_device);
}

void PCSX::SPU::MiniAudio::remove() { ma_device_uninit(&m_device); }
