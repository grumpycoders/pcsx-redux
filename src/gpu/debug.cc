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
    if (m_to == 0xffffffff) {
        return std::string("VRAM direct read (") + std::to_string(m_x) + ", " + std::to_string(m_y) + ") +(" +
               std::to_string(m_width) + ", " + std::to_string(m_height) + ")";
    } else {
        char address[9];
        std::snprintf(address, 9, "%08x", m_to);
        return std::string("VRAM DMA read (") + std::to_string(m_x) + ", " + std::to_string(m_y) + ") +(" +
               std::to_string(m_width) + ", " + std::to_string(m_height) + ") " + std::to_string(m_size) +
               " bytes @0x" + address;
    }
}

std::string PCSX::GPU::Debug::VRAMWrite::title() {
    if (m_from == 0xffffffff) {
        return std::string("VRAM direct write (") + std::to_string(m_x) + ", " + std::to_string(m_y) + ") +(" +
               std::to_string(m_width) + ", " + std::to_string(m_height) + ")";
    } else {
        char address[9];
        std::snprintf(address, 9, "%08x", m_from);
        return std::string("VRAM DMA write (") + std::to_string(m_x) + ", " + std::to_string(m_y) + ") +(" +
               std::to_string(m_width) + ", " + std::to_string(m_height) + ") " + std::to_string(m_size) +
               " bytes @0x" + address;
    }
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
        "256", "320", "512", "640", "384", "???(101)", "???(110)", "???(111)",
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

std::string PCSX::GPU::Debug::BlockFill::title() {
    char C[7];
    std::snprintf(C, 7, "%06x", m_color);
    return _("DMA CMD - BlockFill(") + std::to_string(m_x) + ", " + std::to_string(m_y) + ") +(" + std::to_string(m_w) +
           ", " + std::to_string(m_h) + ") #" + C;
}

std::string PCSX::GPU::Debug::Polygon::title() {
    std::string ret = _("DMA CMD - Polygon; ");
    ret += m_iip ? _("shaded; ") : _("flat; ");
    ret += m_vtx ? "4" : "3";
    ret += _(" vertices");
    if (m_tme) ret += _("; textured");
    if (m_abe) ret += _("; semi transparent");
    if (m_tge) ret += _("; brightness correction");
    return ret;
}

std::string PCSX::GPU::Debug::Line::title() {
    std::string ret = _("DMA CMD - Line; ");
    ret += m_iip ? _("shaded; ") : _("flat; ");
    ret += std::to_string(m_x.size());
    ret += _(" vertices");
    if (m_abe) ret += _("; semi transparent");
    return ret;
}

std::string PCSX::GPU::Debug::Sprite::title() {
    std::string ret;
    if (m_tme) {
        ret = _("DMA CMD - Sprite; ");
    } else {
        ret = _("DMA CMD - Rectangle; ");
    }
    ret += "(" + std::to_string(m_x) + ", " + std::to_string(m_y) + ") +(" + std::to_string(m_w) + ", " +
           std::to_string(m_h) + ")";
    return ret;
}

std::string PCSX::GPU::Debug::Blit::title() {
    std::string ret = _("DMA CMD - Blit (");
    ret += std::to_string(m_sx) + ", " + std::to_string(m_sy) + ") -> (";
    ret += std::to_string(m_dx) + ", " + std::to_string(m_dy) + ") +(";
    ret += std::to_string(m_w) + ", " + std::to_string(m_h) + ")";
    return ret;
}

std::string PCSX::GPU::Debug::VRAMWriteCmd::title() {
    std::string ret = _("Preparing VRAM Write (");
    ret += std::to_string(m_x) + ", " + std::to_string(m_y) + ") +(";
    ret += std::to_string(m_w) + ", " + std::to_string(m_h) + ")";
    return ret;
}

std::string PCSX::GPU::Debug::VRAMReadCmd::title() {
    std::string ret = _("Preparing VRAM Read (");
    ret += std::to_string(m_x) + ", " + std::to_string(m_y) + ") +(";
    ret += std::to_string(m_w) + ", " + std::to_string(m_h) + ")";
    return ret;
}

std::string PCSX::GPU::Debug::DrawModeSetting ::title() {
    std::string ret = _("Draw Mode Setting - texture page: (");
    ret += std::to_string(m_tx);
    ret += ", ";
    ret += std::to_string(m_ty);
    ret += "); abr: ";
    ret += std::to_string(m_abr);
    ret += "; tp: ";
    ret += std::to_string(m_tp);
    ret += "; dtd: ";
    ret += m_dtd ? _("enabled") : _("disabled");
    ret += "; dfe: ";
    ret += m_dfe ? _("enabled") : _("disabled");
    ret += "; td: ";
    ret += m_td ? _("enabled") : _("disabled");
    ret += "; txflip: ";
    ret += m_txflip ? _("enabled") : _("disabled");
    ret += "; tyflip: ";
    ret += m_tyflip ? _("enabled") : _("disabled");
    return ret;
}
std::string PCSX::GPU::Debug::TextureWindowSetting::title() {
    std::string ret = _("Texture Window Setting - mask: (");
    ret += std::to_string(m_twmx);
    ret += ", ";
    ret += std::to_string(m_twmy);
    ret += _("); offset: (");
    ret += std::to_string(m_twox);
    ret += ", ";
    ret += std::to_string(m_twoy);
    ret += ")";
    return ret;
}
std::string PCSX::GPU::Debug::SetDrawingAreaTopLeft::title() {
    std::string ret = _("Set Drawing Area Top Left - (");
    ret += std::to_string(m_x);
    ret += ", ";
    ret += std::to_string(m_y);
    ret += ")";
    return ret;
}
std::string PCSX::GPU::Debug::SetDrawingAreaBottomRight::title() {
    std::string ret = _("Set Drawing Area Bottom Right - (");
    ret += std::to_string(m_x);
    ret += ", ";
    ret += std::to_string(m_y);
    ret += ")";
    return ret;
}
std::string PCSX::GPU::Debug::SetDrawingOffset::title() {
    std::string ret = _("Set Drawing Offset - (");
    ret += std::to_string(m_x);
    ret += ", ";
    ret += std::to_string(m_y);
    ret += ")";
    return ret;
}
std::string PCSX::GPU::Debug::SetMaskSettings::title() {
    std::string ret = _("Set Mask Settings - set mask: ");
    ret += m_setMask ? _("enabled") : _("disabled");
    ret += _("; use mask: ");
    ret += m_useMask ? _("enabled") : _("disabled");
    return ret;
}
