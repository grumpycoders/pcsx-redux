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

#include "core/callstacks.h"
#include "core/cdrom.h"
#include "core/cheat.h"
#include "core/debug.h"
#include "core/eventslua.h"
#include "core/gdb-server.h"
#include "core/gpu.h"
#include "core/gte.h"
#include "core/luaiso.h"
#include "core/mdec.h"
#include "core/pad.h"
#include "core/pcsxlua.h"
#include "core/r3000a.h"
#include "core/sio.h"
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
    : m_mem(new PCSX::Memory()),
      m_counters(new PCSX::Counters()),
      m_gte(new PCSX::GTE()),
      m_sio(new PCSX::SIO()),
      m_cdrom(PCSX::CDRom::factory()),
      m_cheats(new PCSX::Cheats()),
      m_mdec(new PCSX::MDEC()),
      m_gdbServer(new PCSX::GdbServer()),
      m_webServer(new PCSX::WebServer()),
      m_sio1(new PCSX::SIO1()),
      m_sio1Server(new PCSX::SIO1Server()),
      m_sio1Client(new PCSX::SIO1Client()),
      m_debug(new PCSX::Debug()),
      m_hw(new PCSX::HW()),
      m_spu(new PCSX::SPU::impl()),
      m_pads(new PCSX::Pads()),
      m_lua(new PCSX::Lua()),
      m_callStacks(new PCSX::CallStacks) {}

void PCSX::Emulator::setLua() {
    auto L = *m_lua;
    L.declareFunc("t_", [](lua_State* L_) -> int {
        Lua L(L_);
        if (L.gettop() != 1) {
            return L.error("t_ expects 1 argument");
        }
        if (!L.isstring(1)) {
            return L.error("t_ expects a string");
        }
        auto str = L.tostring(1);
        L.push(g_system->getStr(djbHash::hash(str), str.c_str()));
        return 1;
    });
    L.openlibs();
    L.load("ffi = require('ffi')", "internal:setffi.lua");
    LuaFFI::open_zlib(L);
    luv_set_loop(L.getState(), g_system->getLoop());
    L.push("luv");
    luaopen_luv(L.getState());
    L.settable(LUA_GLOBALSINDEX);
    LuaFFI::open_file(L);
    LuaFFI::open_pcsx(L);
    LuaFFI::open_iso(L);
    LuaFFI::open_extra(L);
    LuaBindings::open_events(L);

    L.getfieldtable("PCSX", LUA_GLOBALSINDEX);
    L.getfieldtable("settings");
    L.push("emulator");
    settings.pushValue(L);
    L.settable();
    L.pop();
    L.pop();

    m_pads->setLua(L);

    assert(L.gettop() == 0);
}

PCSX::Emulator::~Emulator() {
    // TODO: move Lua to g_system.
    m_lua->close();
}

int PCSX::Emulator::init() {
    assert(g_system);
    if (m_mem->init() == -1) return -1;
    int ret = R3000Acpu::psxInit();

    const auto& args = g_system->getArgs();

    if (args.get<bool>("openglgpu")) {
        settings.get<SettingHardwareRenderer>() = true;
    }
    if (args.get<bool>("softgpu")) {
        settings.get<SettingHardwareRenderer>() = false;
    }

    m_gpu = settings.get<SettingHardwareRenderer>() ? GPU::getOpenGL() : GPU::getSoft();

    // Enable or disable Kiosk Mode if command line flags are set
    if (args.get<bool>("kiosk")) {
        settings.get<SettingKioskMode>() = true;
    }
    if (args.get<bool>("no-kiosk")) {
        settings.get<SettingKioskMode>() = false;
    }

    setPGXPMode(m_config.PGXP_Mode);
    m_sio->init();
    return ret;
}

void PCSX::Emulator::reset() {
    m_cheats->FreeCheatSearchResults();
    m_cheats->FreeCheatSearchMem();
    m_mem->reset();
    m_spu->resetCaptureBuffer();
    m_cpu->psxReset();
    m_gpu->reset();
    m_pads->shutdown();
    m_pads->init();
    m_pads->reset();
    m_sio->reset();
    m_sio1->reset();
}

void PCSX::Emulator::shutdown() {
    m_cheats->ClearAllCheats();
    m_cheats->FreeCheatSearchResults();
    m_cheats->FreeCheatSearchMem();
    m_mem->shutdown();
    m_cpu->psxShutdown();

    m_pads->shutdown();
}

void PCSX::Emulator::vsync() {
    m_gpu->vblank();
    g_system->m_eventBus->signal<Events::GPU::VSync>({});
    g_system->update(true);
    m_cheats->ApplyCheats();

    if (m_config.RewindInterval > 0 && !(++m_rewind_counter % m_config.RewindInterval)) {
        // CreateRewindState();
    }
}

void PCSX::Emulator::setPGXPMode(uint32_t pgxpMode) { m_cpu->psxSetPGXPMode(pgxpMode); }

PCSX::Emulator* PCSX::g_emulator;
