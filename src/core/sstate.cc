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

#include "core/sstate.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"

std::string PCSX::SaveStates::save() {
    // clang-format off
    SaveState state{
        VersionString {std::string("PCSX-Redux SaveState v1")},
        Version {1},
        Thumbnail {},
        Memory {
            g_emulator.m_psxMem->g_psxM,
            g_emulator.m_psxMem->g_psxR,
            g_emulator.m_psxMem->g_psxP,
            g_emulator.m_psxMem->g_psxH
        },
        Registers {
            g_emulator.m_psxCpu->m_psxRegs.GPR.r,
            g_emulator.m_psxCpu->m_psxRegs.CP0.r,
            g_emulator.m_psxCpu->m_psxRegs.CP2D.r,
            g_emulator.m_psxCpu->m_psxRegs.CP2C.r,
            g_emulator.m_psxCpu->m_psxRegs.pc,
            g_emulator.m_psxCpu->m_psxRegs.code,
            g_emulator.m_psxCpu->m_psxRegs.cycle,
            g_emulator.m_psxCpu->m_psxRegs.interrupt,
            {}
        }
    };
    // clang-format on
    Protobuf::OutSlice slice;
    state.serialize(&slice);
    return slice.finalize();
}
