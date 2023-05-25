/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
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

#include <stdbool.h>
#include <stdint.h>

#include "core/sstate.h"

namespace PCSX {

class Pad {
  public:
    struct PadState {
        // status of buttons - every controller fills this field
        uint16_t digital_switches = 0xffff;

        // overriding from Lua
        uint16_t overrides = 0xffff;

        // Analog stick values in range (0 - 255) where 128 = center
        union {
            uint8_t adc[4] = {0x80, 0x80, 0x80, 0x80};
            struct {
                uint8_t rightJoyX, rightJoyY, leftJoyX, leftJoyY;
            };
        };

        // Motor values
        union {
            uint8_t motors[2] = {0x00, 0x00};
            struct {
                uint8_t rightMotor, leftMotor;
            };
        };
    };

    enum class Types : uint16_t {
        Mouse = 0x5A12,           // (two button mouse)
        NegCon = 0x5A23,          // (steering twist/wheel/paddle)
        KonamiLightgun = 0x5A31,  // (IRQ10-type)
        DigitalPad = 0x5A41,      // (or analog pad/stick in digital mode; LED=Off)
        AnalogStick = 0x5A53,     // (or analog pad in "flight mode"; LED=Green)
        NamcoLightgun = 0x5A63,   // (Cinch-type)
        AnalogPad = 0x5A73,       // (in normal analog mode; LED=Red)
        Multitap = 0x5A80,        // (multiplayer adaptor) (when activated)
        Jogcon = 0x5AE3,          // (steering dial)
        ConfigMode = 0x5AF3,      // (when in config mode; see rumble command 43h)
        None = 0xFFFF             // (no controller connected, pins floating High-Z)
    };

    Pad() : m_padIndex(0xff) {}
    Pad(uint8_t pad_index) : m_padIndex(pad_index) {}

    void deselect();

    // State machine / handlers
    uint8_t transceive(uint8_t value);

    PadState getPadState() { return m_padState; }
    void setPadState(PadState state) { m_padState = state; }
    void setPadType(Types type) { m_padType = type; }

  private:
    enum Commands : uint8_t {
        None = 0x00,
        Access = 0x01,
        Read = 0x42,
        SetConfigMode = 0x43,
        SetAnalogMode = 0x44,
        GetAnalogMode = 0x45,
        Unknown46 = 0x46,
        Unknown47 = 0x47,
        Unknown4C = 0x4C,
        UnlockRumble = 0x4D,
        Error = 0xFF
    };

    enum Responses : uint8_t {
        IdleHighZ = 0xFF,  // High default state
    };

    friend class SIO;
    friend SaveStates::SaveState SaveStates::constructSaveState();

    void acknowledge();

    uint8_t tickRead(uint8_t value);
    uint8_t tickSetConfigMode(uint8_t value) {
        uint8_t data_out = 0xff;

        switch (m_commandTicks) {
            case 0:  // 0x42
                data_out = (static_cast<uint16_t>(m_padType) >> 8) & 0xff;
                break;

            default:
                break;
        }

        return data_out;
    }

    uint8_t tickSetAnalogMode(uint8_t value) { return 0xff; }
    uint8_t tickGetAnalogMode(uint8_t value) { return 0xff; }
    uint8_t tickUnknown46(uint8_t value) { return 0xff; }
    uint8_t tickUnknown47(uint8_t value) { return 0xff; }
    uint8_t tickUnknown4C(uint8_t value) { return 0xff; }
    uint8_t tickUnlockRumble(uint8_t value) { return 0xff; }

    Pad::Types m_padType = Pad::Types::DigitalPad;

    uint16_t m_commandTicks = 0;
    bool m_configMode = false;
    bool m_analongEnabled = false;
    uint8_t m_currentCommand = Pad::Commands::None;
    uint8_t m_spdr = Pad::Responses::IdleHighZ;

    PadState m_padState;

    uint8_t m_padIndex;
};
}  // namespace PCSX
