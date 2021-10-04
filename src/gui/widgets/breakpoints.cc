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

#include "gui/widgets/breakpoints.h"

#include "core/debug.h"
#include "imgui.h"

static ImVec4 s_currentColor = ImColor(0xff, 0xeb, 0x3b);

void PCSX::Widgets::Breakpoints::draw(const char* title) {
    ImGui::SetNextWindowPos(ImVec2(520, 30), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show, ImGuiWindowFlags_MenuBar)) {
        ImGui::End();
        return;
    }
    auto& debugger = PCSX::g_emulator->m_debug;
    ImGui::Checkbox(_("Map execution"), &debugger->m_mapping_e);
    ImGui::Checkbox(_("Map byte reads         "), &debugger->m_mapping_r8);
    ImGui::SameLine();
    ImGui::Checkbox(_("Map half reads         "), &debugger->m_mapping_r16);
    ImGui::SameLine();
    ImGui::Checkbox(_("Map word reads         "), &debugger->m_mapping_r32);
    ImGui::Checkbox(_("Map byte writes        "), &debugger->m_mapping_w8);
    ImGui::SameLine();
    ImGui::Checkbox(_("Map half writes        "), &debugger->m_mapping_w16);
    ImGui::SameLine();
    ImGui::Checkbox(_("Map word writes        "), &debugger->m_mapping_w32);
    ImGui::Separator();
    ImGui::Checkbox(_("Break on execution map"), &debugger->m_breakmp_e);
    ImGui::Checkbox(_("Break on byte read map "), &debugger->m_breakmp_r8);
    ImGui::SameLine();
    ImGui::Checkbox(_("Break on half read map "), &debugger->m_breakmp_r16);
    ImGui::SameLine();
    ImGui::Checkbox(_("Break on word read map "), &debugger->m_breakmp_r32);
    ImGui::Checkbox(_("Break on byte write map"), &debugger->m_breakmp_w8);
    ImGui::SameLine();
    ImGui::Checkbox(_("Break on half write map"), &debugger->m_breakmp_w16);
    ImGui::SameLine();
    ImGui::Checkbox(_("Break on word write map"), &debugger->m_breakmp_w32);
    ImGui::Separator();
    ImGui::TextUnformatted(_("Breakpoints"));

    ImGuiStyle& style = ImGui::GetStyle();
    const float heightSeparator = style.ItemSpacing.y;
    float footerHeight = 0;
    footerHeight += (heightSeparator * 2 + ImGui::GetTextLineHeightWithSpacing()) * 4;
    float glyphWidth = ImGui::GetFontSize();
    ImDrawList* drawList = ImGui::GetWindowDrawList();

    ImGui::BeginChild("BreakpointsList", ImVec2(0, -footerHeight), true);
    const Debug::Breakpoint* toErase = nullptr;
    auto& tree = debugger->getTree();
    for (auto bp = tree.begin(); bp != tree.end(); bp++) {
        ImVec2 pos = ImGui::GetCursorScreenPos();
        std::string name = bp->name();
        if (bp->enabled()) {
            ImGui::Text("  %s", name.c_str());
        } else {
            ImGui::TextDisabled("  %s", name.c_str());
        }
        ImGui::SameLine();
        std::string buttonLabel = _("Remove##") + name;
        if (ImGui::Button(buttonLabel.c_str())) toErase = &*bp;
        ImGui::SameLine();
        if (bp->enabled()) {
            buttonLabel = _("Disable##") + name;
            if (ImGui::Button(buttonLabel.c_str())) bp->disable();
        } else {
            buttonLabel = _("Enable##") + name;
            if (ImGui::Button(buttonLabel.c_str())) bp->enable();
        }
        if (debugger->lastBP() != &*bp) continue;
        ImVec2 a, b, c, d, e;
        const float dist = glyphWidth / 2;
        const float w2 = ImGui::GetTextLineHeight() / 4;
        a.x = pos.x + dist;
        a.y = pos.y;
        b.x = pos.x + dist;
        b.y = pos.y + ImGui::GetTextLineHeight();
        c.x = pos.x + glyphWidth;
        c.y = pos.y + ImGui::GetTextLineHeight() / 2;
        d.x = pos.x;
        d.y = pos.y + ImGui::GetTextLineHeight() / 2 - w2;
        e.x = pos.x + dist;
        e.y = pos.y + ImGui::GetTextLineHeight() / 2 + w2;
        drawList->AddTriangleFilled(a, b, c, ImColor(s_currentColor));
        drawList->AddRectFilled(d, e, ImColor(s_currentColor));
    }
    ImGui::EndChild();
    if (toErase) g_emulator->m_debug->removeBreakpoint(toErase);
    ImGui::InputText(_("Address"), m_bpAddressString, 20, ImGuiInputTextFlags_CharsHexadecimal);
    if (ImGui::BeginCombo(_("Breakpoint Type"), Debug::s_breakpoint_type_names[m_breakpointType]())) {
        for (int i = 0; i < 3; i++) {
            if (ImGui::Selectable(Debug::s_breakpoint_type_names[i](), m_breakpointType == i)) {
                m_breakpointType = i;
            }
        }
        ImGui::EndCombo();
    }
    ImGui::SliderInt(_("Breakpoint Width"), &m_breakpointWidth, 1, 4);
    if (ImGui::Button(_("Add Breakpoint"))) {
        char* endPtr;
        uint32_t breakpointAddress = strtoul(m_bpAddressString, &endPtr, 16);
        if (*m_bpAddressString && !*endPtr) {
            debugger->addBreakpoint(breakpointAddress, Debug::BreakpointType(m_breakpointType), m_breakpointWidth,
                                    _("GUI"));
        }
    }
    ImGui::End();
}
