/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include <SDL.h>
#include <assert.h>
#include <memory.h>
#include <stdint.h>
#include <stdio.h>

#include "core/psxemulator.h"
#include "spu/sdlsound.h"

void PCSX::SPU::SDLsound::dequeueLocked(uint8_t* stream, size_t len) {
    if ((BUFFER_SIZE - s_ptrBegin) < len) {
        size_t subLen = BUFFER_SIZE - s_ptrBegin;
        dequeueLocked(stream, subLen);
        len -= subLen;
        dequeueLocked(stream + subLen, len);
        return;
    }
    memcpy(stream, s_buffer + s_ptrBegin, len);
    s_ptrBegin += len;
    if (s_ptrBegin == BUFFER_SIZE) s_ptrBegin = 0;
}

void PCSX::SPU::SDLsound::callback(Uint8* stream, int len) {
    SDL_LockMutex(s_mutex);
    size_t available;
    if (s_ptrEnd >= s_ptrBegin) {
        available = s_ptrEnd - s_ptrBegin;
    } else {
        available = s_ptrEnd + BUFFER_SIZE - s_ptrBegin;
    }

    if (available < len) {
        dequeueLocked(stream, available);
        memset(stream + available, 0, len - available);
    } else {
        dequeueLocked(stream, len);
    }
    SDL_UnlockMutex(s_mutex);
}

void PCSX::SPU::SDLsound::setup() {
    SDL_zero(s_specs);
    s_specs.freq = 44100;
    s_specs.format = AUDIO_S16LSB;
    s_specs.channels = 2;
    s_specs.samples = 1024;
    s_specs.callback = callbackTrampoline;
    s_specs.userdata = this;
    s_dev = SDL_OpenAudioDevice(NULL, 0, &s_specs, NULL, 0 /* SDL_AUDIO_ALLOW_SAMPLES_CHANGE */);
    if (s_dev) SDL_PauseAudioDevice(s_dev, 0);

    s_mutex = SDL_CreateMutex();
    assert(s_mutex);
}

void PCSX::SPU::SDLsound::remove() {
    if (s_dev) SDL_CloseAudioDevice(s_dev);
    s_dev = 0;
    SDL_DestroyMutex(s_mutex);
}

unsigned long PCSX::SPU::SDLsound::getBytesBuffered(void) {
    unsigned long r;

    SDL_LockMutex(s_mutex);

    if (s_ptrEnd >= s_ptrBegin) {
        r = s_ptrEnd - s_ptrBegin;
    } else {
        r = s_ptrEnd + BUFFER_SIZE - s_ptrBegin;
    }

    SDL_UnlockMutex(s_mutex);

    return r;
}

void PCSX::SPU::SDLsound::enqueueLocked(const uint8_t* data, size_t len) {
    if (len > (BUFFER_SIZE - s_ptrEnd)) {
        size_t subLen = BUFFER_SIZE - s_ptrEnd;
        enqueueLocked(data, subLen);
        len -= subLen;
        enqueueLocked(data + subLen, len);
        return;
    }

    memcpy(s_buffer + s_ptrEnd, data, len);
    if (g_emulator.settings.get<Emulator::SettingMute>()) memset(s_buffer + s_ptrEnd, 0, len);
    s_ptrEnd += len;
    if (s_ptrEnd == BUFFER_SIZE) s_ptrEnd = 0;
}

void PCSX::SPU::SDLsound::feedStreamData(unsigned char* pSound, long lBytes) {
    SDL_LockMutex(s_mutex);
    enqueueLocked(pSound, lBytes);
    SDL_UnlockMutex(s_mutex);
}
