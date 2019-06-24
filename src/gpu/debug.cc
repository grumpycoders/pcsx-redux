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
            ImGui::MenuItem(_("Only break on non-empty frame"), nullptr, &m_breakOnNonEmptyFrame);
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

PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgCmdSTP(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgCmdTexturePage(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgCmdTextureWindow(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgCmdDrawAreaStart(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgCmdDrawAreaEnd(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgCmdDrawOffset(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimLoadImage(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimStoreImage(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimBlkFill(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimMoveImage(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimTileS(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimTile1(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimTile8(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimTile16(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimSprt8(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimSprt16(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimSprtS(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimPolyF4(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimPolyG4(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimPolyFT3(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimPolyFT4(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimPolyGT3(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimPolyG3(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimPolyGT4(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimPolyF3(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimLineGSkip(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimLineGEx(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimLineG2(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimLineFSkip(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimLineFEx(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimLineF2(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
PCSX::GPU::Debug::Command *PCSX::GPU::Prim::dbgPrimNI(uint8_t cmd, uint8_t *baseAddr) { return nullptr; }
