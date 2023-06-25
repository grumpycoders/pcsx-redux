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

#include "gui/luaimguiextra.h"

#include "imgui/imgui.h"
#include "lua/luawrapper.h"

namespace {

unsigned imguiGetCurrentViewportId() { return ImGui::GetWindowViewport()->ID; }
unsigned imguiGetViewportFlags(unsigned id) { return ImGui::FindViewportByID(id)->Flags; }
void imguiSetViewportFlags(unsigned id, unsigned flags) { ImGui::FindViewportByID(id)->Flags = flags; }
ImVec2 imguiGetViewportPos(unsigned id) { return ImGui::FindViewportByID(id)->Pos; }
ImVec2 imguiGetViewportSize(unsigned id) { return ImGui::FindViewportByID(id)->Size; }
ImVec2 imguiGetViewportWorkPos(unsigned id) { return ImGui::FindViewportByID(id)->WorkPos; }
ImVec2 imguiGetViewportWorkSize(unsigned id) { return ImGui::FindViewportByID(id)->WorkSize; }
float imguiGetViewportDpiScale(unsigned id) { return ImGui::FindViewportByID(id)->DpiScale; }

template <typename T, size_t S>
void registerSymbol(PCSX::Lua L, const char (&name)[S], const T ptr) {
    L.push<S>(name);
    L.push((void*)ptr);
    L.settable();
}

#define REGISTER(L, s) registerSymbol(L, #s, s)

void registerAllSymbols(PCSX::Lua L) {
    L.getfieldtable("_CLIBS", LUA_REGISTRYINDEX);
    L.push("IMGUIEXTRA");
    L.newtable();

    REGISTER(L, imguiGetCurrentViewportId);
    REGISTER(L, imguiGetViewportFlags);
    REGISTER(L, imguiSetViewportFlags);
    REGISTER(L, imguiGetViewportPos);
    REGISTER(L, imguiGetViewportSize);
    REGISTER(L, imguiGetViewportWorkPos);
    REGISTER(L, imguiGetViewportWorkSize);
    REGISTER(L, imguiGetViewportDpiScale);

    L.settable();
    L.pop();
}

}  // namespace

void PCSX::LuaFFI::open_imguiextra(Lua L) {
    registerAllSymbols(L);
    static int lualoader = 1;
    static const char* imguiextra = (
#include "gui/imguiextraffi.lua"
    );
    L.load(imguiextra, "internal:gui/imguiextraffi.lua");
}
