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

#include "core/disr3000a.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "gui/widgets/assembly.h"

void PCSX::Widgets::Assembly::draw(psxRegisters* registers, Memory* memory, const char* title) {
    ImGui::SetNextWindowPos(ImVec2(10, 30), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(1200, 500), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    uint32_t pc = registers->pc & 0x1fffff;
    ImGui::Checkbox("Follow PC", &m_followPC);
    ImGui::BeginChild("##ScrollingRegion", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
    ImGuiListClipper clipper(2 * 1024 * 1024 / 4);
    while (clipper.Step()) {
        bool skipNext = false;
        if (clipper.DisplayStart != 0) {
            uint32_t addr = clipper.DisplayStart * 4 - 4;
            uint32_t code = *reinterpret_cast<uint32_t*>(memory->g_psxM + addr);
            uint32_t nextCode = 0;
            if (addr <= 0x1ffff8) {
                nextCode = *reinterpret_cast<uint32_t*>(memory->g_psxM + addr + 4);
            }
            Disasm::asString(code, nextCode, addr | 0x80000000, &skipNext);
        }
        for (int x = clipper.DisplayStart; x < clipper.DisplayEnd; x++) {
            uint32_t addr = x * 4;
            uint32_t code = *reinterpret_cast<uint32_t*>(memory->g_psxM + addr);
            uint32_t nextCode = 0;
            if (addr <= 0x1ffff8) {
                nextCode = *reinterpret_cast<uint32_t*>(memory->g_psxM + addr + 4);
            }
            std::string ins = Disasm::asString(code, nextCode, addr | 0x80000000, &skipNext);
            ImGui::Text("%c %s", addr == pc ? '>' : ' ', ins.c_str());
        }
    }
    if (m_followPC) {
        uint64_t pctopx = pc / 4;
        uint64_t scroll_to_px = pctopx * static_cast<uint64_t>(ImGui::GetTextLineHeightWithSpacing());
        ImGui::SetScrollFromPosY(ImGui::GetCursorStartPos().y + scroll_to_px, 0.5f);
    }
    ImGui::EndChild();
    ImGui::End();
}
