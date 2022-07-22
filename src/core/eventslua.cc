/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include "core/eventslua.h"

#include "core/system.h"
#include "support/eventbus.h"

namespace {

template <typename Event>
void pushEvent(PCSX::Lua L, const Event& e) {
    L.newtable();
}

template <>
void pushEvent(PCSX::Lua L, const PCSX::Events::ExecutionFlow::Pause& e) {
    L.newtable();
    L.push("exception");
    L.push(e.exception);
    L.settable();
}

template <>
void pushEvent(PCSX::Lua L, const PCSX::Events::ExecutionFlow::Reset& e) {
    L.newtable();
    L.push("hard");
    L.push(e.hard);
    L.settable();
}

template <>
void pushEvent(PCSX::Lua L, const PCSX::Events::GUI::JumpToPC& e) {
    L.newtable();
    L.push("pc");
    L.push(lua_Number(e.pc));
    L.settable();
}

template <>
void pushEvent(PCSX::Lua L, const PCSX::Events::GUI::JumpToMemory& e) {
    L.newtable();
    L.push("address");
    L.push(lua_Number(e.address));
    L.settable();
    L.push("size");
    L.push(lua_Number(e.size));
    L.settable();
}

template <>
void pushEvent(PCSX::Lua L, const PCSX::Events::Keyboard& e) {
    L.newtable();
    L.push("key");
    L.push(lua_Number(e.key));
    L.settable();
    L.push("scancode");
    L.push(lua_Number(e.scancode));
    L.settable();
    L.push("action");
    L.push(lua_Number(e.action));
    L.settable();
    L.push("mods");
    L.push(lua_Number(e.mods));
    L.settable();
}

template <typename Event>
void createListener(PCSX::Lua L) {
    L.getfieldtable("EVENT_LISTENERS", LUA_REGISTRYINDEX);
    L.newtable();

    L.push("callback");
    L.copy(2);
    L.settable();

    L.push("thread");
    auto t = L.thread(true);
    L.settable();

    int ref = L.ref();

    auto listener = new PCSX::EventBus::Listener(PCSX::g_system->m_eventBus);
    listener->listen<Event>([L = t, ref](auto e) mutable {
        L.getfieldtable("EVENT_LISTENERS", LUA_REGISTRYINDEX);
        L.getfield(ref, true);
        L.getfield("callback");
        pushEvent(L, e);
        L.pcall(1);
    });

    L.newtable();
    L.newtable();
    L.declareFunc(
        "__gc",
        [ref, listener](PCSX::Lua L) -> int {
            L.getfieldtable("EVENT_LISTENERS", LUA_REGISTRYINDEX);
            L.unref(ref);
            delete listener;
            return 0;
        },
        -1);
    L.setmetatable();

    L.declareFunc(
        "remove",
        [ref, listener](PCSX::Lua L) -> int {
            L.newtable();
            L.setmetatable();
            L.getfieldtable("EVENT_LISTENERS", LUA_REGISTRYINDEX);
            L.unref(ref);
            delete listener;
            return 0;
        },
        -1);
}

}  // namespace

void PCSX::LuaBindings::open_events(Lua L) {
    L.getfieldtable("PCSX", LUA_GLOBALSINDEX);
    L.getfieldtable("Events");

    L.declareFunc(
        "createEventListener",
        [](lua_State* L_) -> int {
            Lua L(L_);
            if (L.gettop() != 2) {
                return L.error("createEventListener: expected 2 arguments");
            }
            if (!L.isstring(1)) {
                return L.error("createEventListener: 1st argument needs to be a string");
            }
            auto name = L.tostring(1);
            if (name == "Quitting") {
                createListener<Events::Quitting>(L);
            } else if (name == "IsoMounted") {
                createListener<Events::IsoMounted>(L);
            } else if (name == "GPU::Vsync") {
                createListener<Events::GPU::VSync>(L);
            } else if (name == "ExecutionFlow::ShellReached") {
                createListener<Events::ExecutionFlow::ShellReached>(L);
            } else if (name == "ExecutionFlow::Run") {
                createListener<Events::ExecutionFlow::Run>(L);
            } else if (name == "ExecutionFlow::Pause") {
                createListener<Events::ExecutionFlow::Run>(L);
            } else if (name == "ExecutionFlow::Reset") {
                createListener<Events::ExecutionFlow::Reset>(L);
            } else if (name == "ExecutionFlow::SaveStateLoaded") {
                createListener<Events::ExecutionFlow::SaveStateLoaded>(L);
            } else if (name == "GUI::JumpToPC") {
                createListener<Events::GUI::JumpToPC>(L);
            } else if (name == "GUI::JumpToMemory") {
                createListener<Events::GUI::JumpToMemory>(L);
            } else if (name == "Keyboard") {
                createListener<Events::Keyboard>(L);
            } else {
                return L.error("createListener: unknown event name");
            }
            return 1;
        },
        -1);

    L.pop();
    L.pop();
}
