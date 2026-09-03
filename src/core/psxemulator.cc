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

#include "core/psxemulator.h"

#include "core/callstacks.h"
#include "core/cdrom.h"
#include "core/cdromlogger.h"
#include "core/debug.h"
#include "core/eventslua.h"
#ifndef __EMSCRIPTEN__  // v1 wasm drops the three network servers (no libuv)
#include "core/gdb-server.h"
#endif
#include "core/gpu.h"
#include "core/gpulogger.h"
#include "core/gte.h"
#include "core/luaiso.h"
#include "core/mdec.h"
#include "core/pad.h"
#include "core/patchmanager.h"
#include "core/pcsxlua.h"
#include "core/pio-cart.h"
#include "core/r3000a.h"
#include "core/ramlogger.h"
#include "core/sio.h"
#ifndef __EMSCRIPTEN__  // v1 wasm drops the three network servers (no libuv)
#include "core/sio1-server.h"
#endif
#include "core/sio1.h"
#ifndef __EMSCRIPTEN__  // v1 wasm drops the three network servers (no libuv)
#include "core/web-server.h"
#endif
#include "gpu/soft/interface.h"
#include "lua/extra.h"
#include "lua/luafile.h"
#include "lua/luawrapper.h"
#include "lua/zlibffi.h"
#include "luafilesystem/src/lfs.h"
#ifndef __EMSCRIPTEN__  // third_party/luv is the Lua libuv binding; not in the wasm source list
extern "C" {
#include <luv.h>
}
#endif
#include "spu/interface.h"
#include "supportpsx/adpcmlua.h"
#include "supportpsx/assembler.h"
#include "supportpsx/binlua.h"

extern "C" int luaopen_lpeg(lua_State* L);

PCSX::Emulator::Emulator()
    : m_callStacks(new PCSX::CallStacks),
      m_cdrom(PCSX::CDRom::factory()),
      m_cdromLogger(new PCSX::CDRomLogger()),
      m_counters(new PCSX::Counters()),
      m_debug(new PCSX::Debug()),
#ifndef __EMSCRIPTEN__  // v1 wasm drops the three network servers (no libuv)
      m_gdbServer(new PCSX::GdbServer()),
#endif
      m_gpuLogger(new PCSX::GPULogger()),
      m_gte(new PCSX::GTE()),
      m_ramLogger(new PCSX::RAMLogger()),
      m_hw(new PCSX::HW()),
      m_lua(new PCSX::Lua()),
      m_mdec(new PCSX::MDEC()),
      m_mem(new PCSX::Memory()),
      m_pads(PCSX::Pads::factory()),
      m_patchManager(new PatchManager()),
      m_pioCart(new PCSX::PIOCart),
      m_sio(new PCSX::SIO()),
      m_sio1(new PCSX::SIO1()),
#ifndef __EMSCRIPTEN__  // v1 wasm drops the three network servers (no libuv)
      m_sio1Server(new PCSX::SIO1Server()),
#endif
#ifndef __EMSCRIPTEN__  // SIO1 over TCP is libuv-backed; v1 wasm drops it
      m_sio1Client(new PCSX::SIO1Client()),
#endif
      // Leading comma, not a reorder: m_webServer is declared AFTER m_spu in
      // psxemulator.h, and a mem-initializer list that disagrees with
      // declaration order earns -Wreorder while still initialising in
      // declaration order. Keeping the order costs one odd-looking comma.
      m_spu(new PCSX::SPU::impl())
#ifndef __EMSCRIPTEN__  // v1 wasm drops the three network servers (no libuv)
      ,
      m_webServer(new PCSX::WebServer())
#endif
{
    auto L = *m_lua;
    L.openlibs();
}

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
        L.push(g_system->getStr(djb::hash(str), str.c_str()));
        return 1;
    });
    L.load("ffi = require('ffi')", "internal:setffi.lua");
    // Before anything that consumes `bit`. src/core/pcsxffi.lua defines
    // bit.extract at file scope, so on a backend without the LuaJIT bit library
    // that is an index of a nil value and the whole chunk dies at startup.
    // No-op where `bit` already exists.
    {
        // The lualoader / paren dance is load-bearing: the .lua file is valid
        // Lua AND a C++ raw string literal at once, and the leading `--` of its
        // first line becomes a pre-decrement discarded by the comma operator.
        // Without the parentheses it is a syntax error, not a string.
        static int lualoader = 1;
        static const char* bitshim = (
#include "lua/bitshim.lua"
        );
        L.load(bitshim, "src:lua/bitshim.lua");
    }

    // The _CLIBS adapter, before ANY ffi file: it wraps ffi.cdef to accumulate
    // declarations, and a library cdef'd before the wrapper is installed would
    // be invisible to it. No-op on LuaJIT, where lj_clib.c does this in C.
    {
        static int lualoader = 1;
        static const char* clibs = (
#include "lua/clibs.lua"
        );
        L.load(clibs, "src:lua/clibs.lua");
    }
    LuaFFI::open_zlib(L);
#ifndef __EMSCRIPTEN__  // no libuv, so no luv global
    luv_set_loop(L.getState(), g_system->getLoop());
    L.push("luv");
    luaopen_luv(L.getState());
    L.settable(LUA_GLOBALSINDEX);
#endif
    luaopen_lfs(L.getState());
    L.pop(3);
    luaopen_lpeg(L.getState());
    L.pop(2);
    LuaFFI::open_file(L);
    LuaFFI::open_pcsx(L);
    LuaFFI::open_iso(L);
    LuaFFI::open_extra(L);
    LuaBindings::open_events(L);
    LuaSupportPSX::open_adpcm(L);
    LuaSupportPSX::open_assembler(L);
    LuaSupportPSX::open_binaries(L);

    L.getfieldtable("PCSX", LUA_GLOBALSINDEX);
    L.getfieldtable("settings");
    L.push("emulator");
    settings.pushValue(L);
    L.settable();
    L.pop();
    L.pop();

    L.getfieldtable("PCSX", LUA_GLOBALSINDEX);
    L.getfieldtable("CONSTS");
    L.getfieldtable("CPU");
    L.push(lua_Number(m_psxClockSpeed));
    L.setfield("CLOCKSPEED");
    L.pop();
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

    m_gpu = settings.get<SettingHardwareRenderer>() ? GPU::getOpenGL() : GPU::getSoft();

    setPGXPMode(m_config.PGXP_Mode);
    m_sio->init();
    return ret;
}

void PCSX::Emulator::reset() {
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
    m_mem->shutdown();
    m_cpu->psxShutdown();

    m_pads->shutdown();
}

void PCSX::Emulator::vsync() {
    m_gpu->vblank();
    g_system->m_eventBus->signal<Events::GPU::VSync>({});
    g_system->update(true);

    if (m_config.RewindInterval > 0 && !(++m_rewind_counter % m_config.RewindInterval)) {
        // CreateRewindState();
    }
}

void PCSX::Emulator::setPGXPMode(uint32_t pgxpMode) { m_cpu->psxSetPGXPMode(pgxpMode); }

PCSX::Emulator* PCSX::g_emulator;
