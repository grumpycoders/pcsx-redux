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

#include <stdint.h>
#include <SDL.h>
#include "imgui.h" // for joypad config menu
#include "core/system.h" // for configure() function

struct PadDataS;

namespace PCSX {
class PAD {
  public:
    enum pad_t { PAD1, PAD2 };
    PAD(pad_t pad);
    ~PAD();
    void init();
    void shutdown();
    unsigned char startPoll();
    unsigned char poll(unsigned char);
    bool configure();
    bool m_showCfg = false;

  private:
    void readPort(PadDataS *pad);
    unsigned char startPoll(PadDataS *pad);
    uint16_t getButtons();

    pad_t m_padIdx = PAD1;

    bool m_connected = false;
    bool m_isKeyboard = false;
    int m_joystick = -1;
    int m_scancodes[16];
    SDL_GameController *m_pad = NULL;

    unsigned char m_buf[256];
    unsigned char m_stdpar[10] = {0x00, 0x41, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char m_mousepar[8] = {0x00, 0x12, 0x5a, 0xff, 0xff, 0xff, 0xff};
    unsigned char m_analogpar[9] = {0x00, 0xff, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    int m_bufcount, m_bufc;
};

}  // namespace PCSX
