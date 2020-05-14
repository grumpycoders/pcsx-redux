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

#include "core/cdrom.h"
#include "core/cheat.h"
#include "core/debug.h"
#include "core/gdb-server.h"
#include "core/gpu.h"
#include "core/gte.h"
#include "core/mdec.h"
#include "core/pad.h"
#include "core/ppf.h"
#include "core/r3000a.h"
#include "core/uv_wrapper.h"
#include "gpu/soft/interface.h"
#include "spu/interface.h"

PCSX::Emulator::Emulator()
    : m_psxMem(new PCSX::Memory()),
      m_psxCounters(new PCSX::Counters()),
      m_gte(new PCSX::GTE()),
      m_sio(new PCSX::SIO()),
      m_cdrom(PCSX::CDRom::factory()),
      m_cheats(new PCSX::Cheats()),
      m_mdec(new PCSX::MDEC()),
      m_gpu(new PCSX::SoftGPU::impl()),
      m_gdbServer(new PCSX::GdbServer()),
      m_debug(new PCSX::Debug()),
      m_hw(new PCSX::HW()),
      m_spu(new PCSX::SPU::impl()),
      m_pad1(new PCSX::PAD(PAD::PAD1)),
      m_pad2(new PCSX::PAD(PAD::PAD2)),
      m_uv(new PCSX::UV()) {}

PCSX::Emulator::~Emulator() {}

int PCSX::Emulator::EmuInit() {
    assert(g_system);
    if (m_psxMem->psxMemInit() == -1) return -1;
    int ret = PCSX::R3000Acpu::psxInit();
    EmuSetPGXPMode(m_config.PGXP_Mode);
    m_pad1->init();
    m_pad2->init();
    return ret;
}

void PCSX::Emulator::EmuReset() {
    m_cheats->FreeCheatSearchResults();
    m_cheats->FreeCheatSearchMem();
    m_psxMem->psxMemReset();

    m_psxCpu->psxReset();
    m_pad1->shutdown();
    m_pad2->shutdown();
    m_pad1->init();
    m_pad2->init();
}

void PCSX::Emulator::EmuShutdown() {
    m_cheats->ClearAllCheats();
    m_cheats->FreeCheatSearchResults();
    m_cheats->FreeCheatSearchMem();

    m_cdrom->m_ppf.FreePPFCache();
    m_psxMem->psxMemShutdown();
    m_psxCpu->psxShutdown();

    m_pad1->shutdown();
    m_pad2->shutdown();
}

void PCSX::Emulator::EmuUpdate() {
    PCSX::g_system->update();
    m_cheats->ApplyCheats();

    if (m_vblank_count_hideafter) {
        if (!(--m_vblank_count_hideafter)) {
            PCSX::g_emulator->m_gpu->showScreenPic(NULL);
        }
    }

    if (m_config.RewindInterval > 0 && !(++m_rewind_counter % m_config.RewindInterval)) {
        // CreateRewindState();
    }
}

void PCSX::Emulator::EmuSetPGXPMode(uint32_t pgxpMode) { m_psxCpu->psxSetPGXPMode(pgxpMode); }

PCSX::Emulator* PCSX::g_emulator;
