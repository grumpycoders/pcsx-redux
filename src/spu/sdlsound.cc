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

#include "spu/sdlsound.h"

#include <SDL.h>
#include <assert.h>
#include <memory.h>
#include <stdint.h>
#include <stdio.h>

void PCSX::SPU::SDLsound::dequeueLocked(uint8_t* stream, size_t len, unsigned streamId) {
    auto& str = m_streams[streamId];
    if ((BUFFER_SIZE - str.ptrBegin) < len) {
        size_t subLen = BUFFER_SIZE - str.ptrBegin;
        dequeueLocked(stream, subLen, streamId);
        len -= subLen;
        dequeueLocked(stream + subLen, len, streamId);
        return;
    }
    memcpy(stream, str.buffer + str.ptrBegin, len);
    str.ptrBegin += len;
    if (str.ptrBegin == BUFFER_SIZE) str.ptrBegin = 0;
    SDL_CondSignal(str.condition);
}

void PCSX::SPU::SDLsound::callback(Uint8* stream, int len) {
    if (m_muted) {
        memset(stream, 0, len);
        return;
    }

    auto str = m_streams;

    SDL_LockMutex(str->mutex);
    size_t available;
    if (str->ptrEnd >= str->ptrBegin) {
        available = str->ptrEnd - str->ptrBegin;
    } else {
        available = str->ptrEnd + BUFFER_SIZE - str->ptrBegin;
    }

    if (available < len) {
        dequeueLocked(stream, available, 0);
    } else {
        dequeueLocked(stream, len, 0);
    }
    SDL_UnlockMutex(str->mutex);
    if (available < len) {
        memset(stream + available, 0, len - available);
    }

    str = m_streams + 1;

    SDL_LockMutex(str->mutex);
    if (str->ptrEnd >= str->ptrBegin) {
        available = str->ptrEnd - str->ptrBegin;
    } else {
        available = str->ptrEnd + BUFFER_SIZE - str->ptrBegin;
    }
    if (available == 0) {
        SDL_UnlockMutex(str->mutex);
        return;
    }
    Uint8 xaStream[0x1000];
    SDL_assert_always(len <= 0x1000);
    if (available < len) {
        len = available;
    }
    dequeueLocked(xaStream, len, 1);
    SDL_UnlockMutex(str->mutex);
    SDL_MixAudioFormat(stream, xaStream, m_specs.format, len, SDL_MIX_MAXVOLUME);
}

void PCSX::SPU::SDLsound::setup() {
    SDL_zero(m_specs);
    m_specs.freq = 44100;
    m_specs.format = AUDIO_S16LSB;
    m_specs.channels = 2;
    m_specs.samples = 1024;
    m_specs.callback = callbackTrampoline;
    m_specs.userdata = this;
    m_dev = SDL_OpenAudioDevice(NULL, 0, &m_specs, NULL, 0 /* SDL_AUDIO_ALLOW_SAMPLES_CHANGE */);
    if (m_dev) SDL_PauseAudioDevice(m_dev, 0);

    m_streams[0].mutex = SDL_CreateMutex();
    m_streams[1].mutex = SDL_CreateMutex();
    m_streams[0].condition = SDL_CreateCond();
    m_streams[1].condition = SDL_CreateCond();
    SDL_assert_always(m_streams[0].mutex);
    SDL_assert_always(m_streams[1].mutex);
    SDL_assert_always(m_streams[0].condition);
    SDL_assert_always(m_streams[1].condition);
}

void PCSX::SPU::SDLsound::remove() {
    if (m_dev) SDL_CloseAudioDevice(m_dev);
    m_dev = 0;
    SDL_DestroyMutex(m_streams[0].mutex);
    SDL_DestroyMutex(m_streams[1].mutex);
    SDL_DestroyCond(m_streams[0].condition);
    SDL_DestroyCond(m_streams[1].condition);
}

unsigned long PCSX::SPU::SDLsound::getBytesBuffered(unsigned streamId) {
    unsigned long r;

    SDL_LockMutex(m_streams[streamId].mutex);

    if (m_streams[streamId].ptrEnd >= m_streams[streamId].ptrBegin) {
        r = m_streams[streamId].ptrEnd - m_streams[streamId].ptrBegin;
    } else {
        r = m_streams[streamId].ptrEnd + BUFFER_SIZE - m_streams[streamId].ptrBegin;
    }

    SDL_UnlockMutex(m_streams[streamId].mutex);

    return r;
}

void PCSX::SPU::SDLsound::enqueueLocked(const uint8_t* data, size_t len, unsigned streamId) {
    auto& str = m_streams[streamId];

    while (true) {
        size_t available;
        if (str.ptrEnd >= str.ptrBegin) {
            available = BUFFER_SIZE - (str.ptrEnd - str.ptrBegin);
        } else {
            available = str.ptrBegin - str.ptrEnd;
        }

        if (len >= available) {
            SDL_CondWait(str.condition, str.mutex);
        } else {
            break;
        }
    }

    if (len > (BUFFER_SIZE - str.ptrEnd)) {
        size_t subLen = BUFFER_SIZE - str.ptrEnd;
        enqueueLocked(data, subLen, streamId);
        len -= subLen;
        enqueueLocked(data + subLen, len, streamId);
        return;
    }

    memcpy(str.buffer + str.ptrEnd, data, len);
    str.ptrEnd += len;
    if (str.ptrEnd == BUFFER_SIZE) str.ptrEnd = 0;
}

void PCSX::SPU::SDLsound::feedStreamData(unsigned char* pSound, long lBytes, unsigned streamId) {
    SDL_LockMutex(m_streams[streamId].mutex);
    enqueueLocked(pSound, lBytes, streamId);
    SDL_UnlockMutex(m_streams[streamId].mutex);
}
