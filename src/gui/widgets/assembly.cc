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

namespace {

class DummyAsm : public PCSX::Disasm {
    virtual void OpCode(const char* str) final {}
    virtual void GPR(uint8_t reg) final {}
    virtual void CP0(uint8_t reg) final {}
    virtual void CP2C(uint8_t reg) final {}
    virtual void CP2D(uint8_t reg) final {}
    virtual void HI() final {}
    virtual void LO() final {}
    virtual void Imm(uint16_t value) final {}
    virtual void Imm32(uint32_t value) final {}
    virtual void Target(uint32_t value) final {}
    virtual void Sa(uint8_t value) final {}
    virtual void OfB(int16_t offset, uint8_t reg, int size) final {}
    virtual void Offset(uint32_t offset) final {}
};

class ImGuiAsm : public PCSX::Disasm {
    void sameLine() { ImGui::SameLine(0.0f, 0.0f); }
    void comma() {
        if (m_gotArg) {
            sameLine();
            ImGui::Text(", ");
        }
        m_gotArg = true;
    }
    virtual void OpCode(const char* str) final {
        m_gotArg = false;
        sameLine();
        ImGui::Text("%-7s", str);
    }
    virtual void GPR(uint8_t reg) final {
        comma();
        sameLine();
        ImGui::Text("$");
        sameLine();
        ImGui::Text(s_disRNameGPR[reg]);
        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
            ImGui::Text("$%s = %8.8x", s_disRNameGPR[reg], m_registers->GPR.r[reg]);
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
    }
    virtual void CP0(uint8_t reg) final {
        comma();
        sameLine();
        ImGui::Text("$");
        sameLine();
        ImGui::Text(s_disRNameCP0[reg]);
        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
            ImGui::Text("$%s = %8.8x", s_disRNameCP0[reg], m_registers->CP0.r[reg]);
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
    }
    virtual void CP2C(uint8_t reg) final {
        comma();
        sameLine();
        ImGui::Text("$");
        sameLine();
        ImGui::Text(s_disRNameCP2C[reg]);
        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
            ImGui::Text("$%s = %8.8x", s_disRNameCP2C[reg], m_registers->CP2C.r[reg]);
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
    }
    virtual void CP2D(uint8_t reg) final {
        comma();
        sameLine();
        ImGui::Text("$");
        sameLine();
        ImGui::Text(s_disRNameCP2D[reg]);
        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
            ImGui::Text("$%s = %8.8x", s_disRNameCP2D[reg], m_registers->CP2D.r[reg]);
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
    }
    virtual void HI() final {
        comma();
        sameLine();
        ImGui::Text("$hi");
        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
            ImGui::Text("$hi = %8.8x", m_registers->GPR.n.hi);
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
    }
    virtual void LO() final {
        comma();
        sameLine();
        ImGui::Text("$lo");
        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
            ImGui::Text("$lo = %8.8x", m_registers->GPR.n.lo);
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
    }
    virtual void Imm(uint16_t value) final {
        comma();
        sameLine();
        ImGui::Text("0x%4.4x", value);
    }
    virtual void Imm32(uint32_t value) final {
        comma();
        sameLine();
        ImGui::Text("0x%8.8x", value);
    }
    virtual void Target(uint32_t value) final {
        comma();
        sameLine();
        ImGui::Text("0x%8.8x", value);
    }
    virtual void Sa(uint8_t value) final {
        comma();
        sameLine();
        ImGui::Text("0x%2.2x", value);
    }
    virtual void OfB(int16_t offset, uint8_t reg, int size) {
        comma();
        sameLine();
        ImGui::Text("0x%4.4x($%s)", offset, s_disRNameGPR[reg]);
        if (ImGui::IsItemHovered()) {
            uint32_t addr = m_registers->GPR.r[reg] + offset;
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
            switch (size) {
                case 1:
                    ImGui::Text("[%8.8x] = %2.2x", addr, psxMu8(addr));
                    break;
                case 2:
                    ImGui::Text("[%8.8x] = %4.4x", addr, psxMu16(addr));
                    break;
                case 4:
                    ImGui::Text("[%8.8x] = %8.8x", addr, psxMu32(addr));
                    break;
            }
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
    }
    virtual void Offset(uint32_t value) final {
        comma();
        sameLine();
        ImGui::Text("0x%8.8x", value);
    }
    bool m_gotArg = false;
    PCSX::psxRegisters* m_registers;
    PCSX::Memory* m_memory;

  public:
    ImGuiAsm(PCSX::psxRegisters* registers, PCSX::Memory* memory) : m_registers(registers), m_memory(memory) {}
};

}  // namespace

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
            DummyAsm dummy;
            dummy.process(code, nextCode, addr | 0x80000000, &skipNext);
        }
        ImGuiAsm imguiAsm(registers, memory);
        for (int x = clipper.DisplayStart; x < clipper.DisplayEnd; x++) {
            uint32_t addr = x * 4;
            uint32_t code = *reinterpret_cast<uint32_t*>(memory->g_psxM + addr);
            uint32_t nextCode = 0;
            if (addr <= 0x1ffff8) {
                nextCode = *reinterpret_cast<uint32_t*>(memory->g_psxM + addr + 4);
            }
            ImGui::Text("%c %8.8x %8.8x: ", addr == pc ? '>' : ' ', addr | 0x80000000, code);
            imguiAsm.process(code, nextCode, addr | 0x80000000, &skipNext);
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
