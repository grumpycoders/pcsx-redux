/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include "core/pcsxlua.h"

#include "core/debug.h"
#include "core/gpu.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/sstate.h"
#include "lua/luafile.h"
#include "lua/luawrapper.h"

namespace {

struct LuaBreakpoint {
    PCSX::Debug::BreakpointUserListType wrapper;
};

void* getMemPtr() { return PCSX::g_emulator->m_mem->m_psxM; }
void* getRomPtr() { return PCSX::g_emulator->m_mem->m_psxR; }
void* getScratchPtr() { return PCSX::g_emulator->m_mem->m_psxH; }
void* getRegisters() { return &PCSX::g_emulator->m_cpu->m_regs; }
LuaBreakpoint* addBreakpoint(uint32_t address, PCSX::Debug::BreakpointType type, unsigned width, const char* cause,
                             bool (*invoker)(uint32_t address, unsigned width, const char* cause)) {
    LuaBreakpoint* ret = new LuaBreakpoint();
    auto* bp = PCSX::g_emulator->m_debug->addBreakpoint(
        address, type, width, std::string("Lua Breakpoint ") + cause,
        [invoker](const PCSX::Debug::Breakpoint* self, uint32_t address, unsigned width, const char* cause) {
            return invoker(address, width, cause);
        });

    ret->wrapper.push_back(bp);
    return ret;
}
void enableBreakpoint(LuaBreakpoint* wrapper) {
    if (wrapper->wrapper.size() == 0) return;
    wrapper->wrapper.begin()->enable();
}
void disableBreakpoint(LuaBreakpoint* wrapper) {
    if (wrapper->wrapper.size() == 0) return;
    wrapper->wrapper.begin()->disable();
}
bool breakpointEnabled(LuaBreakpoint* wrapper) {
    if (wrapper->wrapper.size() == 0) return false;
    return wrapper->wrapper.begin()->enabled();
}
void removeBreakpoint(LuaBreakpoint* wrapper) {
    wrapper->wrapper.destroyAll();
    delete wrapper;
}
void pauseEmulator() { PCSX::g_system->pause(); }
void resumeEmulator() { PCSX::g_system->resume(); }
void softResetEmulator() { PCSX::g_system->softReset(); }
void hardResetEmulator() { PCSX::g_system->hardReset(); }
void luaMessage(const char* msg, bool error) { PCSX::g_system->luaMessage(msg, error); }
void luaLog(const char* msg) { PCSX::g_system->log(PCSX::LogClass::LUA, msg); }
void jumpToPC(uint32_t pc) { PCSX::g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToPC{pc}); }
void jumpToMemory(uint32_t address, unsigned width) {
    PCSX::g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToMemory{address, width});
}

struct LuaScreenShot {
    PCSX::Slice* data;
    uint16_t width, height;
    decltype(PCSX::GPU::ScreenShot::bpp) bpp;
};

LuaScreenShot takeScreenShot() {
    LuaScreenShot ret;
    auto ss = PCSX::g_emulator->m_gpu->takeScreenShot();
    ret.data = new PCSX::Slice(std::move(ss.data));
    ret.width = ss.width;
    ret.height = ss.height;
    ret.bpp = ss.bpp;
    return ret;
}

PCSX::Slice* createSaveState() {
    auto ss = PCSX::SaveStates::save();
    return new PCSX::Slice(std::move(ss));
}

void loadSaveStateFromSlice(PCSX::Slice* data) { PCSX::SaveStates::load(data->asStringView()); }

void loadSaveStateFromFile(PCSX::LuaFFI::LuaFile* file) {
    auto data = file->file->readAt(file->file->size(), 0);
    PCSX::SaveStates::load(data.asStringView());
}

}  // namespace

template <typename T, size_t S>
static void registerSymbol(PCSX::Lua L, const char (&name)[S], const T ptr) {
    L.push<S>(name);
    L.push((void*)ptr);
    L.settable();
}

#define REGISTER(L, s) registerSymbol(L, #s, s)

static void registerAllSymbols(PCSX::Lua L) {
    L.getfieldtable("_CLIBS", LUA_REGISTRYINDEX);
    L.push("PCSX");
    L.newtable();
    REGISTER(L, getMemPtr);
    REGISTER(L, getRomPtr);
    REGISTER(L, getScratchPtr);
    REGISTER(L, getRegisters);
    REGISTER(L, addBreakpoint);
    REGISTER(L, enableBreakpoint);
    REGISTER(L, disableBreakpoint);
    REGISTER(L, breakpointEnabled);
    REGISTER(L, removeBreakpoint);
    REGISTER(L, pauseEmulator);
    REGISTER(L, resumeEmulator);
    REGISTER(L, softResetEmulator);
    REGISTER(L, hardResetEmulator);
    REGISTER(L, luaMessage);
    REGISTER(L, luaLog);
    REGISTER(L, jumpToPC);
    REGISTER(L, jumpToMemory);
    REGISTER(L, takeScreenShot);
    REGISTER(L, createSaveState);
    REGISTER(L, loadSaveStateFromSlice);
    REGISTER(L, loadSaveStateFromFile);
    L.settable();
    L.pop();
}

void PCSX::LuaFFI::open_pcsx(Lua L) {
    static int lualoader = 1;
    static const char* pcsxFFI = (
#include "core/pcsxffi.lua"
    );
    registerAllSymbols(L);
    L.load(pcsxFFI, "internal:core/pcsxffi.lua");
}
