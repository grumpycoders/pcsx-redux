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
    auto & debugger = PCSX::g_emulator.m_debug;
    ImGui::Checkbox("Map execution", &debugger->m_mapping_e);
    ImGui::Checkbox("Map byte reads         ", &debugger->m_mapping_r8);
    ImGui::SameLine();
    ImGui::Checkbox("Map half reads         ", &debugger->m_mapping_r16);
    ImGui::SameLine();
    ImGui::Checkbox("Map word reads         ", &debugger->m_mapping_r32);
    ImGui::Checkbox("Map byte writes        ", &debugger->m_mapping_w8);
    ImGui::SameLine();
    ImGui::Checkbox("Map half writes        ", &debugger->m_mapping_w16);
    ImGui::SameLine();
    ImGui::Checkbox("Map word writes        ", &debugger->m_mapping_w32);
    ImGui::Separator();
    ImGui::Checkbox("Break on execution map", &debugger->m_breakmp_e);
    ImGui::Checkbox("Break on byte read map ", &debugger->m_mapping_r8);
    ImGui::SameLine();
    ImGui::Checkbox("Break on half read map ", &debugger->m_mapping_r16);
    ImGui::SameLine();
    ImGui::Checkbox("Break on word read map ", &debugger->m_mapping_r32);
    ImGui::Checkbox("Break on byte write map", &debugger->m_mapping_w8);
    ImGui::SameLine();
    ImGui::Checkbox("Break on half write map", &debugger->m_mapping_w16);
    ImGui::SameLine();
    ImGui::Checkbox("Break on word write map", &debugger->m_mapping_w32);
    ImGui::Separator();
    ImGui::Text("Breakpoints");
    if (ImGui::Button("Show all breakpoints")) {
        m_filterE = m_filterR1 = m_filterR2 = m_filterR4 = m_filterW1 = m_filterW2 = m_filterW4 = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Show no breakpoints")) {
        m_filterE = m_filterR1 = m_filterR2 = m_filterR4 = m_filterW1 = m_filterW2 = m_filterW4 = false;
    }
    ImGui::Checkbox("Show exec BPs", &m_filterE);
    ImGui::Checkbox("Show byte read BPs     ", &m_filterR1);
    ImGui::SameLine();
    ImGui::Checkbox("Show half read BPs     ", &m_filterR2);
    ImGui::SameLine();
    ImGui::Checkbox("Show word read BPs     ", &m_filterR4);
    ImGui::Checkbox("Show byte write BPs    ", &m_filterW1);
    ImGui::SameLine();
    ImGui::Checkbox("Show half write BPs    ", &m_filterW2);
    ImGui::SameLine();
    ImGui::Checkbox("Show word write BPs    ", &m_filterW4);
    ImGui::BeginChild("BreakpointsList", ImVec2(0, 0), true);
    Debug::bpiterator eraseBP = debugger->endBP();
    debugger->forEachBP([&](PCSX::Debug::bpiterator it) mutable {
        switch (it->second.type()) {
            case Debug::BreakpointType::BE:
                if (!m_filterE) return true;
                break;
            case Debug::BreakpointType::BR1:
                if (!m_filterR1) return true;
                break;
            case Debug::BreakpointType::BR2:
                if (!m_filterR2) return true;
                break;
            case Debug::BreakpointType::BR4:
                if (!m_filterR4) return true;
                break;
            case Debug::BreakpointType::BW1:
                if (!m_filterW1) return true;
                break;
            case Debug::BreakpointType::BW2:
                if (!m_filterW2) return true;
                break;
            case Debug::BreakpointType::BW4:
                if (!m_filterW4) return true;
                break;
        }
        ImGui::Text("%8.8x - %s  ", it->first, PCSX::Debug::s_breakpoint_type_names[it->second.type()]);
        std::string buttonLabel = "Remove##";
        buttonLabel += it->first;
        buttonLabel += Debug::s_breakpoint_type_names[it->second.type()];
        if (ImGui::Button(buttonLabel.c_str())) {
            eraseBP = it;
        }
        return true;
    });
    ImGui::EndChild();
    if (debugger->isValidBP(eraseBP)) {
        debugger->eraseBP(eraseBP);
    }
    ImGui::InputText("Address", m_bpAddressString, 20, ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    if (ImGui::BeginCombo("Breakpoint Type", Debug::s_breakpoint_type_names[m_breakpointType])) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::Selectable(Debug::s_breakpoint_type_names[i], m_breakpointType == i)) {
                m_breakpointType = i;
            }
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    if (ImGui::Button("Add Breakpoint")) {
        char* endPtr;
        uint32_t breakpointAddress = strtoul(m_bpAddressString, &endPtr, 16);
        if (*m_bpAddressString && !*endPtr) {
            debugger->addBreakpoint(breakpointAddress, Debug::BreakpointType(m_breakpointType));
        }
    }
    ImGui::End();
}
