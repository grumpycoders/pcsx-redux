/***************************************************************************
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
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

#include "core/psxemulator.h"
#include "core/cheat.h"
#include "core/ppf.h"
#include "core/psxbios.h"
#include "core/r3000a.h"
#include "core/gte.h"

PCSX::Emulator::Emulator() {
    m_psxMem = new PCSX::Memory();
    m_psxCounters = new PCSX::Counters();
    m_psxBios = PCSX::Bios::factory();
    m_gte = new PCSX::GTE();
}

PCSX::Emulator::~Emulator() {
    delete m_psxMem;
    delete m_psxCounters;
    delete m_psxBios;
    delete m_gte;
}

int PCSX::Emulator::EmuInit() {
    assert(g_system);
    if (m_psxMem->psxMemInit() == -1) return -1;
    int ret = PCSX::R3000Acpu::psxInit();
    EmuSetPGXPMode(m_config.PGXP_Mode);
    return ret;
}

void PCSX::Emulator::EmuReset() {
    FreeCheatSearchResults();
    FreeCheatSearchMem();
    m_psxMem->psxMemReset();

    PCSX::g_emulator.m_psxCpu->psxReset();
}

void PCSX::Emulator::EmuShutdown() {
    ClearAllCheats();
    FreeCheatSearchResults();
    FreeCheatSearchMem();

    FreePPFCache();
    m_psxMem->psxMemShutdown();
    PCSX::g_emulator.m_psxCpu->psxShutdown();

    CleanupMemSaveStates();
}

void PCSX::Emulator::EmuUpdate() {
    // Do not allow hotkeys inside a softcall from HLE BIOS
    if (!m_config.HLE || !PCSX::g_emulator.m_psxBios->m_hleSoftCall) PCSX::g_system->SysUpdate();

    ApplyCheats();

    if (m_vblank_count_hideafter) {
        if (!(--m_vblank_count_hideafter)) {
            GPU_showScreenPic(NULL);
        }
    }

    if (m_config.RewindInterval > 0 && !(++m_rewind_counter % m_config.RewindInterval)) {
        CreateRewindState();
    }
}

void PCSX::Emulator::EmuSetPGXPMode(uint32_t pgxpMode) { PCSX::g_emulator.m_psxCpu->psxSetPGXPMode(pgxpMode); }

PCSX::Emulator & PCSX::g_emulator = PCSX::Emulator::getEmulator();
