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

#include "core/pads.h"

#include "core/sio.h"

void PCSX::Pad::deselect() {
    m_currentCommand = Commands::None;
    m_commandTicks = 0;
    m_spdr = Responses::IdleHighZ;
}


uint8_t PCSX::Pad::tickRead(uint8_t value) {
    uint8_t data_out = 0xff;

    switch (m_commandTicks) {
        case 0:  // 0x42
            data_out = (static_cast<uint16_t>(m_padType) >> 8) & 0xff;
            break;

        case 1:  // TAP
            data_out = m_padState.digital_switches & 0xff;
            break;

        case 2:  // MOT
            m_padState.motors[0] = value;
            data_out = (m_padState.digital_switches >> 8) & 0xff;
            break;

        default:
            if (m_padType == Types::DigitalPad) {
                data_out = 0xff; // derp?
            } else {
                switch (m_commandTicks) {
                    case 3:  // MOT
                        m_padState.motors[1] |= (uint16_t)value << 8;
                        data_out = m_padState.adc[0];
                        break;

                    case 4:  // 00
                        data_out = m_padState.adc[1];
                        break;

                    case 5:  // 00
                        data_out = m_padState.adc[2];
                        break;

                    case 6:  // 00
                        data_out = m_padState.adc[3];
                        break;
                        
                    default:
                        break;
                }
            }
            break;
    }

    m_commandTicks++;
    //acknowledge();

    return data_out;
}

uint8_t PCSX::Pad::transceive(uint8_t value) {
    uint8_t data_out = m_spdr;

    if (m_currentCommand == Commands::None || m_currentCommand == Commands::Access) {
        m_currentCommand = value;
    }

    switch (m_currentCommand) {
        case Commands::Access:
            // Update button state
            m_spdr = static_cast<uint16_t>(m_padType) & 0xff;
            //acknowledge();
            break;

        case Commands::Read:
            m_spdr = tickRead(value);
            break;

        case Commands::GetAnalogMode:
            m_spdr = tickGetAnalogMode(value);
            break;

        case Commands::SetConfigMode:
            m_spdr = tickSetConfigMode(value);
            break;

        case Commands::SetAnalogMode:
            m_spdr = tickSetAnalogMode(value);
            break;

        case Commands::Unknown46:
            m_spdr = tickUnknown46(value);
            break;

        case Commands::Unknown47:
            m_spdr = tickUnknown47(value);
            break;

        case Commands::UnlockRumble:
            m_spdr = tickUnlockRumble(value);
            break;

        case Commands::Error:
        default:
            m_spdr = Responses::IdleHighZ;
            break;
    }

    return data_out;
}
