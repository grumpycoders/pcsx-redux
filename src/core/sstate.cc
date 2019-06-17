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
#include "core/gpu.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "spu/interface.h"

PCSX::SaveStates::SaveState PCSX::SaveStates::constructSaveState() {
    // clang-format off
    uint8_t * icacheAddr = g_emulator.m_psxCpu->m_psxRegs.ICache_Addr;
    uint8_t * icacheCode = g_emulator.m_psxCpu->m_psxRegs.ICache_Code;
    return SaveState {
        VersionString {},
        Version {},
        Thumbnail {},
        Memory {
            RAM { g_emulator.m_psxMem->g_psxM },
            ROM { g_emulator.m_psxMem->g_psxR },
            Parallel { g_emulator.m_psxMem->g_psxP },
            Hardware { g_emulator.m_psxMem->g_psxH }
        },
        Registers {
            GPR { g_emulator.m_psxCpu->m_psxRegs.GPR.r },
            CP0 { g_emulator.m_psxCpu->m_psxRegs.CP0.r },
            CP2D { g_emulator.m_psxCpu->m_psxRegs.CP2D.r },
            CP2C { g_emulator.m_psxCpu->m_psxRegs.CP2C.r },
            PC { g_emulator.m_psxCpu->m_psxRegs.pc },
            Code { g_emulator.m_psxCpu->m_psxRegs.code },
            Cycle { g_emulator.m_psxCpu->m_psxRegs.cycle },
            Interrupt { g_emulator.m_psxCpu->m_psxRegs.interrupt },
            IntCyclesField {},
            ICacheAddr { icacheAddr },
            ICacheCode { icacheCode },
            ICacheValid { g_emulator.m_psxCpu->m_psxRegs.ICache_valid }
        },
        GPU {},
        SPU {},
    };
    // clang-format on
}

static void intCyclesFromState(const PCSX::SaveStates::SaveState& state) {
    auto& intCyclesState = state.get<PCSX::SaveStates::RegistersField>().get<PCSX::SaveStates::IntCyclesField>();
    auto& intCycles = PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle;
    for (unsigned i = 0; i < 32; i++) {
        intCycles[i].sCycle = intCyclesState.value[i].get<PCSX::SaveStates::IntSCycle>().value;
        intCycles[i].cycle = intCyclesState.value[i].get<PCSX::SaveStates::IntCycle>().value;
    }
}

static void intCyclesToState(PCSX::SaveStates::SaveState& state) {
    auto& intCyclesState = state.get<PCSX::SaveStates::RegistersField>().get<PCSX::SaveStates::IntCyclesField>();
    auto& intCycles = PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle;
    intCyclesState.value.resize(32);
    for (unsigned i = 0; i < 32; i++) {
        intCyclesState.value[i].get<PCSX::SaveStates::IntSCycle>().value = intCycles[i].sCycle;
        intCyclesState.value[i].get<PCSX::SaveStates::IntCycle>().value = intCycles[i].cycle;
    }
}

std::string PCSX::SaveStates::save() {
    SaveState state = constructSaveState();

    state.get<VersionString>().value = "PCSX-Redux SaveState v1";
    state.get<Version>().value = 1;

    intCyclesToState(state);
    g_emulator.m_gpu->save(state.get<GPUField>());
    g_emulator.m_spu->save(state.get<SPUField>());

    Protobuf::OutSlice slice;
    state.serialize(&slice);
    return slice.finalize();
}
