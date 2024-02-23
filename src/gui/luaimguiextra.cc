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

#include "gui/gui.h"
#include "imgui/imgui.h"
#include "imgui_stdlib.h"
#include "lua/luawrapper.h"

namespace {

PCSX::GUI* s_gui = nullptr;

unsigned imguiGetCurrentViewportId() { return ImGui::GetWindowViewport()->ID; }
unsigned imguiGetViewportFlags(unsigned id) { return ImGui::FindViewportByID(id)->Flags; }
void imguiSetViewportFlags(unsigned id, unsigned flags) { ImGui::FindViewportByID(id)->Flags = flags; }
void imguiGetViewportPos(unsigned id, ImVec2* ret) { *ret = ImGui::FindViewportByID(id)->Pos; }
void imguiGetViewportSize(unsigned id, ImVec2* ret) { *ret = ImGui::FindViewportByID(id)->Size; }
void imguiGetViewportWorkPos(unsigned id, ImVec2* ret) { *ret = ImGui::FindViewportByID(id)->WorkPos; }
void imguiGetViewportWorkSize(unsigned id, ImVec2* ret) { *ret = ImGui::FindViewportByID(id)->WorkSize; }
float imguiGetViewportDpiScale(unsigned id) { return ImGui::FindViewportByID(id)->DpiScale; }
void imguiLogText(const char* text) { ImGui::LogText("%s", text); }
void guiUseMainFont() { s_gui->useMainFont(); }
void guiUseMonoFont() { s_gui->useMonoFont(); }

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
    REGISTER(L, imguiLogText);
    REGISTER(L, guiUseMainFont);
    REGISTER(L, guiUseMonoFont);

    L.settable();
    L.pop();
}

}  // namespace

void PCSX::LuaFFI::open_imguiextra(GUI* gui, Lua L) {
    s_gui = gui;
    registerAllSymbols(L);
    static int lualoader = 2;
    static const char* imguiextra = (
#include "gui/imguiextraffi.lua"
    );
    L.load(imguiextra, "src:gui/imguiextraffi.lua");
    static const char* imguisafe = (
#include "gui/imguisafe.lua"
    );
    L.load(imguisafe, "src:gui/imguisafe.lua");

    L.getfieldtable("imgui", LUA_GLOBALSINDEX);
    L.getfieldtable("extra");
    L.declareFunc(
        "InputText",
        [](lua_State* L_) -> int {
            Lua L(L_);
            int n = L.gettop();
            if (n < 2) {
                return L.error("InputText: not enough arguments");
            }
            if (n > 3) {
                return L.error("InputText: too many arguments");
            }
            if (!L.isstring(1)) {
                return L.error("InputText: argument 1 must be a string");
            }
            if (!L.isstring(2)) {
                return L.error("InputText: argument 2 must be a string");
            }
            std::string label = L.tostring(1);
            std::string str = L.tostring(2);
            ImGuiInputTextFlags flags = 0;
            if (n == 3) {
                if (!L.isnumber(3)) {
                    return L.error("InputText: argument 3 must be a number");
                }
                flags = L.tonumber(3);
            }
            bool ret = ImGui::InputText(label.c_str(), &str, flags);
            L.push(ret);
            L.push(str);
            return 2;
        },
        -1);
    L.declareFunc(
        "InputTextWithHint",
        [](lua_State* L_) -> int {
            Lua L(L_);
            int n = L.gettop();
            if (n < 3) {
                return L.error("InputTextWithHint: not enough arguments");
            }
            if (n > 4) {
                return L.error("InputTextWithHint: too many arguments");
            }
            if (!L.isstring(1)) {
                return L.error("InputTextWithHint: argument 1 must be a string");
            }
            if (!L.isstring(2)) {
                return L.error("InputTextWithHint: argument 2 must be a string");
            }
            if (!L.isstring(3)) {
                return L.error("InputTextWithHint: argument 3 must be a string");
            }
            std::string label = L.tostring(1);
            std::string hint = L.tostring(2);
            std::string str = L.tostring(3);
            ImGuiInputTextFlags flags = 0;
            if (n == 4) {
                if (!L.isnumber(4)) {
                    return L.error("InputTextWithHint: argument 4 must be a number");
                }
                flags = L.tonumber(4);
            }
            bool ret = ImGui::InputTextWithHint(label.c_str(), hint.c_str(), &str, flags);
            L.push(ret);
            L.push(str);
            return 2;
        },
        -1);
    L.pop(2);
    assert(L.gettop() == 0);
}
