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

#include "core/system.h"
#include "gpu/debug.h"

void PCSX::GPU::Debugger::show() {
    if (!ImGui::Begin(_("GPU Debugger"), &m_show, ImGuiWindowFlags_MenuBar)) {
        ImGui::End();
        return;
    }

    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu(_("File"))) {
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu(_("Debug"))) {
            ImGui::MenuItem(_("Enable frame capture"), nullptr, &m_frameCapture);
            ImGui::MenuItem(_("Capture invalid and empty commands"), nullptr, &m_captureInvalidAndEmpty);
            ImGui::Separator();
            ImGui::MenuItem(_("Breakpoint on end of frame"), nullptr, &m_breakOnFrame);
            ImGui::MenuItem(_("Only break on non-empty frame"), nullptr, &m_breakOnNonEmptyFrame);
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

    if (ImGui::Button(_("Resume"))) g_system->resume();

    for (const auto& cmd : m_lastFrameEvents) {
        std::string title = cmd->title();
        ImGui::Text("%s", title.c_str());
    }

    ImGui::End();
}

std::string PCSX::GPU::Debug::VRAMRead::title() {
    char address[9];
    std::snprintf(address, 9, "%08x", m_to);
    return std::string("VRAM read (") + std::to_string(m_x) + ", " + std::to_string(m_y) + ") +(" +
           std::to_string(m_width) + ", " + std::to_string(m_height) + ") " + std::to_string(m_size) + " bytes @0x" + address;
}

std::string PCSX::GPU::Debug::VRAMWrite::title() {
    char address[9];
    std::snprintf(address, 9, "%08x", m_from);
    return std::string("VRAM write (") + std::to_string(m_x) + ", " + std::to_string(m_y) + ") +(" +
           std::to_string(m_width) + ", " + std::to_string(m_height) + ") " + std::to_string(m_size) + " bytes @0x" + address;
}
