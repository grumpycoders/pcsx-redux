/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include "imgui.h"

#include "core/debug.h"
#include "gui/widgets/breakpoints.h"

void PCSX::Widgets::Breakpoints::draw(const char* title) {
    if (!ImGui::Begin(title, &m_show, ImGuiWindowFlags_MenuBar)) {
        ImGui::End();
        return;
    }
    ImGui::Text("Breakpoints");
    ImGui::BeginChild("BreakpointsList", ImVec2(0, 0), true);
    PCSX::g_emulator.m_debug->forEachBP([&](PCSX::Debug::bpiterator it) mutable {
        ImGui::Text("%8.8x - %s", it->first, PCSX::Debug::s_breakpoint_type_names[it->second.type()]);
        return true;
    });
    ImGui::EndChild();
    ImGui::End();
}
