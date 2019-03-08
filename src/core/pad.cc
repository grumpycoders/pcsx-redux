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

#include <memory.h>

#include <SDL.h>

#include "core/pad.h"
#include "core/psemu_plugin_defs.h"

static const SDL_Scancode s_defaultScancodes[16] = {
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

static const SDL_GameControllerButton s_padMapping[16] = {
    SDL_CONTROLLER_BUTTON_BACK,           // Select
    SDL_CONTROLLER_BUTTON_INVALID,        // n/a
    SDL_CONTROLLER_BUTTON_INVALID,        // n/a
    SDL_CONTROLLER_BUTTON_START,          // Start
    SDL_CONTROLLER_BUTTON_DPAD_UP,        // Up
    SDL_CONTROLLER_BUTTON_DPAD_RIGHT,     // Right
    SDL_CONTROLLER_BUTTON_DPAD_DOWN,      // Down
    SDL_CONTROLLER_BUTTON_DPAD_LEFT,      // Left
    SDL_CONTROLLER_BUTTON_INVALID,        // L2
    SDL_CONTROLLER_BUTTON_INVALID,        // R2
    SDL_CONTROLLER_BUTTON_LEFTSHOULDER,   // L1
    SDL_CONTROLLER_BUTTON_RIGHTSHOULDER,  // R1
    SDL_CONTROLLER_BUTTON_Y,              // Triangle
    SDL_CONTROLLER_BUTTON_B,              // Circle
    SDL_CONTROLLER_BUTTON_A,              // Cross
    SDL_CONTROLLER_BUTTON_X,              // Square
};

PCSX::PAD::PAD(pad_t pad) : m_padIdx(pad), m_connected(pad == PAD1), m_isKeyboard(pad == PAD1), m_pad(nullptr) {
    memcpy(m_scancodes, s_defaultScancodes, sizeof(s_defaultScancodes));
}

void PCSX::PAD::init() {
    bool foundOne = false;
    for (int i = 0; i < SDL_NumJoysticks(); ++i) {
        if (SDL_IsGameController(i)) {
            if (!foundOne && m_padIdx == PAD2) {
                foundOne = true;
                continue;
            }
            m_pad = SDL_GameControllerOpen(i);
            m_isKeyboard = false;
            if (m_pad) break;
        }
    }
}

void PCSX::PAD::shutdown() {
    if (m_pad) SDL_GameControllerClose(m_pad);
}

PCSX::PAD::~PAD() {}

static const int16_t threshold = 28000;

uint16_t PCSX::PAD::getButtons() {
    uint16_t result = 0xffff;
    if (!m_connected) return result;

    if (m_isKeyboard) {
        const Uint8* keys = SDL_GetKeyboardState(NULL);
        result = 0;
        for (unsigned i = 0; i < 16; i++) result |= !(keys[m_scancodes[i]]) << i;
    } else if (m_pad) {
        bool buttons[16];
        for (unsigned i = 0; i < 16; i++) buttons[i] = (SDL_GameControllerGetButton(m_pad, s_padMapping[i]));
        Sint16 axisX, axisY, trL, trR;
        axisX = SDL_GameControllerGetAxis(m_pad, SDL_CONTROLLER_AXIS_LEFTX);
        axisY = SDL_GameControllerGetAxis(m_pad, SDL_CONTROLLER_AXIS_LEFTY);
        trL = SDL_GameControllerGetAxis(m_pad, SDL_CONTROLLER_AXIS_TRIGGERLEFT);
        trR = SDL_GameControllerGetAxis(m_pad, SDL_CONTROLLER_AXIS_TRIGGERRIGHT);
        if (axisY >= threshold) buttons[4] = true;
        if (axisX >= threshold) buttons[5] = true;
        if (axisY <= -threshold) buttons[6] = true;
        if (axisX <= -threshold) buttons[7] = true;
        if (trL >= threshold) buttons[8] = true;
        if (trR >= threshold) buttons[9] = true;
        result = 0;
        for (unsigned i = 0; i < 16; i++) result |= !buttons[i] << i;
    }

    return result;
}

void PCSX::PAD::readPort(PadDataS* data) {
    memset(data, 0, sizeof(PadDataS));
    data->buttonStatus = getButtons();
}

unsigned char PCSX::PAD::startPoll() {
    PadDataS padd;

    readPort(&padd);

    return startPoll(&padd);
}
unsigned char PCSX::PAD::poll(unsigned char value) {
    if (m_bufc > m_bufcount) return 0;
    return m_buf[m_bufc++];
}

unsigned char PCSX::PAD::startPoll(PadDataS* pad) {
    m_bufc = 0;

    switch (pad->controllerType) {
        case PSE_PAD_TYPE_MOUSE:
            m_mousepar[3] = pad->buttonStatus & 0xff;
            m_mousepar[4] = pad->buttonStatus >> 8;
            m_mousepar[5] = pad->moveX;
            m_mousepar[6] = pad->moveY;

            memcpy(m_buf, m_mousepar, 7);
            m_bufcount = 6;
            break;
        case PSE_PAD_TYPE_NEGCON:  // npc101/npc104(slph00001/slph00069)
            m_analogpar[1] = 0x23;
            m_analogpar[3] = pad->buttonStatus & 0xff;
            m_analogpar[4] = pad->buttonStatus >> 8;
            m_analogpar[5] = pad->rightJoyX;
            m_analogpar[6] = pad->rightJoyY;
            m_analogpar[7] = pad->leftJoyX;
            m_analogpar[8] = pad->leftJoyY;

            memcpy(m_buf, m_analogpar, 9);
            m_bufcount = 8;
            break;
        case PSE_PAD_TYPE_ANALOGPAD:  // scph1150
            m_analogpar[1] = 0x73;
            m_analogpar[3] = pad->buttonStatus & 0xff;
            m_analogpar[4] = pad->buttonStatus >> 8;
            m_analogpar[5] = pad->rightJoyX;
            m_analogpar[6] = pad->rightJoyY;
            m_analogpar[7] = pad->leftJoyX;
            m_analogpar[8] = pad->leftJoyY;

            memcpy(m_buf, m_analogpar, 9);
            m_bufcount = 8;
            break;
        case PSE_PAD_TYPE_ANALOGJOY:  // scph1110
            m_analogpar[1] = 0x53;
            m_analogpar[3] = pad->buttonStatus & 0xff;
            m_analogpar[4] = pad->buttonStatus >> 8;
            m_analogpar[5] = pad->rightJoyX;
            m_analogpar[6] = pad->rightJoyY;
            m_analogpar[7] = pad->leftJoyX;
            m_analogpar[8] = pad->leftJoyY;

            memcpy(m_buf, m_analogpar, 9);
            m_bufcount = 8;
            break;
        case PSE_PAD_TYPE_STANDARD:
        default:
            m_stdpar[3] = pad->buttonStatus & 0xff;
            m_stdpar[4] = pad->buttonStatus >> 8;

            memcpy(m_buf, m_stdpar, 5);
            m_bufcount = 4;
    }

    return m_buf[m_bufc++];
}
