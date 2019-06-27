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
#include "gpu/prim.h"

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
            ImGui::MenuItem(_("Also break on empty frame"), nullptr, &m_breakOnEmptyFrame);
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

    if (ImGui::Button(_("Resume"))) g_system->resume();

    for (const auto &cmd : m_lastFrameEvents) {
        std::string title = cmd->title();
        ImGui::Text("%s", title.c_str());
    }

    ImGui::End();
}

std::string PCSX::GPU::Debug::VRAMRead::title() {
    char address[9];
    std::snprintf(address, 9, "%08x", m_to);
    return std::string("VRAM read (") + std::to_string(m_x) + ", " + std::to_string(m_y) + ") +(" +
           std::to_string(m_width) + ", " + std::to_string(m_height) + ") " + std::to_string(m_size) + " bytes @0x" +
           address;
}

std::string PCSX::GPU::Debug::VRAMWrite::title() {
    char address[9];
    std::snprintf(address, 9, "%08x", m_from);
    return std::string("VRAM write (") + std::to_string(m_x) + ", " + std::to_string(m_y) + ") +(" +
           std::to_string(m_width) + ", " + std::to_string(m_height) + ") " + std::to_string(m_size) + " bytes @0x" +
           address;
}

// ---- WriteStatus ----

std::string PCSX::GPU::Debug::DMASetup::title() {
    switch (m_direction) {
        case 0:
            return _("WriteStatus CMD 0x04 DMA Setup - disabled");
        case 2:
            return _("WriteStatus CMD 0x04 DMA Setup - CPU -> GPU");
        case 3:
            return _("WriteStatus CMD 0x04 DMA Setup - GPU -> CPU");
        default:
            return _("WriteStatus CMD 0x04 DMA Setup - unknown mode: ") + std::to_string(m_direction);
    }
}

std::string PCSX::GPU::Debug::DisplayStart::title() {
    uint16_t x = m_data & 0x3ff;
    uint16_t y = (m_data >> 10) & 0x1ff;
    uint16_t extra = m_data >> 19;
    if (extra) {
        char extraC[3];
        std::snprintf(extraC, 3, "%02x", extra);
        return _("WriteStatus CMD 0x05 Display Start (") + std::to_string(x) + ", " + std::to_string(y) +
               _(") extra: ") + extraC;
    } else {
        return _("WriteStatus CMD 0x05 Display Start (") + std::to_string(x) + ", " + std::to_string(y) + ")";
    }
}

std::string PCSX::GPU::Debug::HDispRange::title() {
    uint16_t x1 = m_data & 0xfff;
    uint16_t x2 = (m_data >> 12) & 0xfff;
    return _("WriteStatus CMD 0x06 Horizontal Display Range ") + std::to_string(x1) + " - " + std::to_string(x2);
}

std::string PCSX::GPU::Debug::VDispRange::title() {
    uint16_t y1 = m_data & 0x3ff;
    uint16_t y2 = (m_data >> 10) & 0x3ff;
    uint16_t extra = m_data >> 20;
    if (extra) {
        char extraC[3];
        std::snprintf(extraC, 3, "%02x", extra);
        return _("WriteStatus CMD 0x07 Vertical Display Range ") + std::to_string(y1) + " - " + std::to_string(y2) +
               _(" - extra: ") + extraC;
    } else {
        return _("WriteStatus CMD 0x07 Vertical Display Range ") + std::to_string(y1) + " - " + std::to_string(y2);
    }
}

std::string PCSX::GPU::Debug::SetDisplayMode::title() {
    uint8_t w = m_data & 3 | (m_data >> 4) & 4;
    bool h = (m_data >> 2) & 1;
    bool mode = (m_data >> 3) & 1;
    bool rgb = (m_data >> 4) & 1;
    bool inter = (m_data >> 5) & 1;
    bool reverse = (m_data >> 7) & 1;
    const char *widths[8] = {
        "256",
        "320",
        "512",
        "640",
        "384",
        "???(101)",
        "???(110)",
        "???(111)",
    };

    uint16_t extra = m_data >> 8;

    std::string ret = _("WriteSatus CMD 0x08 Set Display Mode; width: ");
    ret += widths[w];
    ret += _("; height: ");
    ret += h ? "480" : "240";
    ret += mode ? "; PAL" : "; NTSC";
    ret += rgb ? "; RGB888" : "; RGB555";
    if (inter) ret += _("; interlaced");
    if (reverse) ret += _("; reversed");
    if (extra) {
        char C[5];
        std::snprintf(C, 5, "%04x", extra);
        ret += _("; extra: ") + std::string(C);
    }

    return ret;
}

std::string PCSX::GPU::Debug::GetDisplayInfo::title() {
    return _("WriteStatus CMD 0x10 Get Display Info; index: ") + std::to_string(m_data);
}
