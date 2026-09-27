/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include "gui/widgets/fileviewers.h"

#include "core/psxemulator.h"
#include "fmt/format.h"
#include "imgui/imgui.h"
#include "lua/luafile.h"
#include "lua/luawrapper.h"

PCSX::Widgets::FileViewers::~FileViewers() { m_instances.destroyAll(); }

// The file viewers live in resources/fileviewers.lua, loaded at startup if it
// can be found. Without it, callers should not offer to open a viewer.
bool PCSX::Widgets::FileViewers::available() {
    if (!g_emulator->m_lua) return false;
    auto L = *g_emulator->m_lua;
    L.getfieldtable("PCSX", LUA_GLOBALSINDEX);
    L.getfield("FileViewers");
    bool ret = false;
    if (L.istable()) {
        L.getfield("open");
        ret = L.isfunction();
        L.pop();
    }
    L.pop(2);
    return ret;
}

void PCSX::Widgets::FileViewers::open(const std::string& title, IO<File> file) {
    if (!available()) return;
    auto L = *g_emulator->m_lua;
    L.getfieldtable("PCSX", LUA_GLOBALSINDEX);
    L.getfield("FileViewers");
    L.getfield("open");
    L.remove(-2);
    L.remove(-2);
    L.push(new LuaFFI::LuaFile(file));
    try {
        L.pcall(1);
    } catch (...) {
        return;
    }
    if (!L.istable()) {
        L.pop();
        return;
    }
    // luaL_ref pops the object.
    m_instances.push_back(new Instance(fmt::format(f_("View - {}"), title), L.ref(LUA_REGISTRYINDEX)));
}

void PCSX::Widgets::FileViewers::draw() {
    for (auto it = m_instances.begin(); it != m_instances.end();) {
        auto& inst = *it;
        if (!inst.m_open) {
            it = m_instances.erase(it);
            release(inst);
            continue;
        }
        ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
        if (ImGui::Begin(inst.m_title.c_str(), &inst.m_open)) {
            if (inst.m_failed) {
                ImGui::TextUnformatted(_("The viewer failed, see the Lua console."));
            } else if (!call(inst, "draw")) {
                inst.m_failed = true;
            }
        }
        ImGui::End();
        ++it;
    }
}

void PCSX::Widgets::FileViewers::release(Instance& inst) {
    if (g_emulator->m_lua) {
        call(inst, "close");
        auto L = *g_emulator->m_lua;
        L.unref(inst.m_ref, LUA_REGISTRYINDEX);
    }
    delete &inst;
}

bool PCSX::Widgets::FileViewers::call(Instance& inst, const char* method) {
    auto L = *g_emulator->m_lua;
    L.rawgeti(inst.m_ref, LUA_REGISTRYINDEX);
    L.getfield(method);
    L.remove(-2);
    if (!L.isfunction()) {
        L.pop();
        return true;
    }
    try {
        L.pcall();
    } catch (...) {
        return false;
    }
    return true;
}
