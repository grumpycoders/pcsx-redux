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

#include <curl/curl.h>

#include "core/callstacks.h"
#include "core/cdrom.h"
#include "core/cheat.h"
#include "core/debug.h"
#include "core/gdb-server.h"
#include "core/gpu.h"
#include "core/gte.h"
#include "core/mdec.h"
#include "core/pad.h"
#include "core/pcsxlua.h"
#include "core/ppf.h"
#include "core/r3000a.h"
#include "core/sio1-server.h"
#include "core/sio1.h"
#include "core/web-server.h"
#include "gpu/soft/interface.h"
#include "lua/extra.h"
#include "lua/luafile.h"
#include "lua/luawrapper.h"
#include "lua/zlibffi.h"
extern "C" {
#include "luv/src/luv.h"
}
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
      m_webServer(new PCSX::WebServer()),
      m_sio1(new PCSX::SIO1()),
      m_sio1Server(new PCSX::SIO1Server()),
      m_debug(new PCSX::Debug()),
      m_hw(new PCSX::HW()),
      m_spu(new PCSX::SPU::impl()),
      m_pads(new PCSX::Pads()),
      m_lua(new PCSX::Lua()),
      m_callStacks(new PCSX::CallStacks) {
    uv_loop_init(&m_loop);
    curl_global_init(CURL_GLOBAL_ALL);
}

void PCSX::Emulator::setLua() {
    m_lua->open_base();
    m_lua->open_bit();
    m_lua->open_debug();
    m_lua->open_ffi();
    m_lua->open_jit();
    m_lua->open_math();
    // m_lua->open_package();
    m_lua->open_string();
    m_lua->open_table();
    LuaFFI::open_zlib(m_lua.get());
    luv_set_loop(m_lua->getState(), &m_loop);
    m_lua->push("luv");
    luaopen_luv(m_lua->getState());
    m_lua->settable(LUA_GLOBALSINDEX);
    LuaFFI::open_pcsx(m_lua.get());
    LuaFFI::open_file(m_lua.get());
    LuaFFI::open_extra(m_lua.get());
}

PCSX::Emulator::~Emulator() {
    // TODO: move Lua and uv_loop to g_system.
    curl_global_cleanup();
    m_lua->close();
    uv_loop_close(&g_emulator->m_loop);
}

int PCSX::Emulator::EmuInit() {
    assert(g_system);
    if (m_psxMem->psxMemInit() == -1) return -1;
    int ret = PCSX::R3000Acpu::psxInit();
    EmuSetPGXPMode(m_config.PGXP_Mode);
    m_pads->init();
    return ret;
}

void PCSX::Emulator::EmuReset() {
    m_cheats->FreeCheatSearchResults();
    m_cheats->FreeCheatSearchMem();
    m_psxMem->psxMemReset();
    m_spu->resetCaptureBuffer();
    m_psxCpu->psxReset();
    m_gpu->clearVRAM();
    m_pads->shutdown();
    m_pads->init();
    m_sio1->sio1Reset();
}

void PCSX::Emulator::EmuShutdown() {
    m_cheats->ClearAllCheats();
    m_cheats->FreeCheatSearchResults();
    m_cheats->FreeCheatSearchMem();

    m_cdrom->m_ppf.FreePPFCache();
    m_psxMem->psxMemShutdown();
    m_psxCpu->psxShutdown();

    m_pads->shutdown();
}

void PCSX::Emulator::vsync() {
    g_system->update(true);
    m_cheats->ApplyCheats();

    if (m_config.RewindInterval > 0 && !(++m_rewind_counter % m_config.RewindInterval)) {
        // CreateRewindState();
    }
}

void PCSX::Emulator::EmuSetPGXPMode(uint32_t pgxpMode) { m_psxCpu->psxSetPGXPMode(pgxpMode); }

PCSX::Emulator* PCSX::g_emulator;
