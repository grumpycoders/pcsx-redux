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

#include "core/pad.h"

static const SDL_Scancode scancodes[] = {
    SDL_SCANCODE_BACKSPACE,  // Select
    SDL_SCANCODE_UNKNOWN,    // n/a
    SDL_SCANCODE_UNKNOWN,    // n/a
    SDL_SCANCODE_RETURN,     // Start
    SDL_SCANCODE_UP,         // Up
    SDL_SCANCODE_RIGHT,      // Right
    SDL_SCANCODE_DOWN,       // Down
    SDL_SCANCODE_LEFT,       // Left
    SDL_SCANCODE_A,          // L2
    SDL_SCANCODE_F,          // R2
    SDL_SCANCODE_Q,          // L1
    SDL_SCANCODE_R,          // R1
    SDL_SCANCODE_S,          // Triangle
    SDL_SCANCODE_D,          // Circle
    SDL_SCANCODE_X,          // Cross
    SDL_SCANCODE_Z,          // Square
};

uint16_t PCSX::PAD::getButtons() {
    const Uint8* keys = SDL_GetKeyboardState(NULL);

    uint16_t result = 0;
    for (unsigned i = 0; i < 16; i++) result |= !(keys[scancodes[i]]) << i;

    return result;
}
