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

#pragma once

#include <SDL.h>

namespace PCSX {

namespace SPU {

class SDLsound {
  public:
    SDLsound(bool& muted) : m_muted(muted) {}
    void setup();
    void remove();
    unsigned long getBytesBuffered(unsigned streamId = 0);
    unsigned long getFreeBytes(unsigned streamId = 0) { return BUFFER_SIZE - getBytesBuffered(streamId); }
    void feedStreamData(unsigned char* pSound, long lBytes, unsigned streamId = 0);

  private:
    void callback(Uint8* stream, int len);
    static void callbackTrampoline(void* userdata, Uint8* stream, int len) {
        SDLsound* that = static_cast<SDLsound*>(userdata);
        that->callback(stream, len);
    }
    void dequeueLocked(uint8_t* stream, size_t len, unsigned streamId);
    void enqueueLocked(const uint8_t* data, size_t len, unsigned streamId);

    static const size_t BUFFER_SIZE = 32 * 1024 * 4;

    SDL_AudioDeviceID m_dev = 0;

    struct {
        uint32_t ptrBegin = 0, ptrEnd = 0;
        uint8_t buffer[BUFFER_SIZE];
        SDL_mutex* mutex;
        SDL_cond* condition;
    } m_streams[2];

    SDL_AudioSpec m_specs;
    bool& m_muted;
};

}  // namespace SPU

}  // namespace PCSX
