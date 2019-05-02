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

#include <SDL.h>

#include <functional>

#include "imgui.h"

#include "core/debug.h"
#include "core/disr3000a.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "gui/widgets/assembly.h"

namespace {

uint32_t virtToReal (uint32_t virt) {
    uint32_t base = (virt >> 20) & 0xffc;
    uint32_t real = virt & 0x1fffff;
    uint32_t pc = real;
    if ((base == 0x000) || (base == 0x800) || (base == 0xa00)) {
        // main memory first
        if (real >= 0x00200000) pc = 0;
    } else if (base == 0x1f0) {
        // parallel port second
        if (real >= 0x00010000) {
            pc = 0;
        } else {
            pc += 0x00200000;
        }
    } else if (base == 0xbfc) {
        // bios last
        if (real >= 0x00080000) {
            pc = 0;
        } else {
            pc += 0x00210000;
        }
    }
    return pc;
};


void DButton(const char* label, bool enabled, std::function<void(void)> clicked) {
    if (!enabled) {
        const ImVec4 lolight = ImGui::GetStyle().Colors[ImGuiCol_TextDisabled];
        ImGui::PushStyleColor(ImGuiCol_Button, lolight);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, lolight);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, lolight);
    }
    if (ImGui::Button(label) && enabled) clicked();
    if (!enabled) ImGui::PopStyleColor(3);
}

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
            ImGui::Text(",");
        }
        m_gotArg = true;
    }
    virtual void OpCode(const char* str) final {
        m_gotArg = false;
        sameLine();
        ImGui::Text("%-6s", str);
    }
    virtual void GPR(uint8_t reg) final {
        comma();
        sameLine();
        ImGui::Text(" $");
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
        ImGui::Text(" $");
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
        ImGui::Text(" $");
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
        ImGui::Text(" $");
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
        ImGui::Text(" $hi");
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
        ImGui::Text(" $lo");
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
        ImGui::Text(" 0x%4.4x", value);
    }
    virtual void Imm32(uint32_t value) final {
        comma();
        sameLine();
        ImGui::Text(" 0x%8.8x", value);
    }
    virtual void Target(uint32_t value) final {
        comma();
        sameLine();
        char label[21];
        std::snprintf(label, sizeof(label), "0x%8.8x##%8.8x", value, m_currentAddr);
        if (ImGui::SmallButton(label)) {
            m_jumpToPC = true;
            m_jumpToPCValue = virtToReal(value);
        }
    }
    virtual void Sa(uint8_t value) final {
        comma();
        sameLine();
        ImGui::Text(" 0x%2.2x", value);
    }
    inline uint8_t* ptr(uint32_t addr) {
        uint8_t* lut = m_memory->g_psxMemRLUT[addr >> 16];
        if (lut) {
            return lut + (addr & 0xffff);
        } else {
            static uint8_t dummy[4] = {0, 0, 0, 0};
            return dummy;
        }
    }
    inline uint8_t mem8(uint32_t addr) { return *ptr(addr); }
    inline uint16_t mem16(uint32_t addr) { return SWAP_LE16(*(int16_t*)ptr(addr)); }
    inline uint32_t mem32(uint32_t addr) { return SWAP_LE32(*(int32_t*)ptr(addr)); }
    virtual void OfB(int16_t offset, uint8_t reg, int size) {
        comma();
        sameLine();
        ImGui::Text(" 0x%4.4x($%s)", offset, s_disRNameGPR[reg]);
        if (ImGui::IsItemHovered()) {
            uint32_t addr = m_registers->GPR.r[reg] + offset;
            ImGui::BeginTooltip();
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
            switch (size) {
                case 1:
                    ImGui::Text("[%8.8x] = %2.2x", addr, mem8(addr));
                    break;
                case 2:
                    ImGui::Text("[%8.8x] = %4.4x", addr, mem16(addr));
                    break;
                case 4:
                    ImGui::Text("[%8.8x] = %8.8x", addr, mem32(addr));
                    break;
            }
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
    }
    virtual void Offset(uint32_t value) final {
        comma();
        sameLine();
        char label[21];
        std::snprintf(label, sizeof(label), "0x%8.8x##%8.8x", value, m_currentAddr);
        if (ImGui::SmallButton(label)) {
            m_jumpToPC = true;
            m_jumpToPCValue = virtToReal(value);
        }
    }
    bool m_gotArg = false;
    PCSX::psxRegisters* m_registers;
    PCSX::Memory* m_memory;

  public:
    ImGuiAsm(PCSX::psxRegisters* registers, PCSX::Memory* memory, bool& jumpToPC, uint32_t& jumpToPCValue)
        : m_registers(registers), m_memory(memory), m_jumpToPC(jumpToPC), m_jumpToPCValue(jumpToPCValue) {}
    uint32_t m_currentAddr;
    bool& m_jumpToPC;
    uint32_t& m_jumpToPCValue;
};

}  // namespace

void PCSX::Widgets::Assembly::draw(psxRegisters* registers, Memory* memory, const char* title) {
    ImGui::SetNextWindowPos(ImVec2(10, 30), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(1200, 500), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    DummyAsm dummy;
    bool jumpToPC = false;
    uint32_t jumpToPCValue = 0;
    ImGuiAsm imguiAsm(registers, memory, jumpToPC, jumpToPCValue);

    uint32_t pc = virtToReal(registers->pc);
    ImGui::Checkbox("Follow PC", &m_followPC);
    ImGui::SameLine();
    DButton("Step In", !g_system->running(), [&]() mutable { g_emulator.m_debug->stepIn(); });
    ImGui::SameLine();
    DButton("Step Over", !g_system->running(), [&]() mutable { g_emulator.m_debug->stepOver(); });
    ImGui::SameLine();
    DButton("Step Out", !g_system->running(), [&]() mutable { g_emulator.m_debug->stepOut(); });
    if (ImGui::IsKeyPressed(SDL_SCANCODE_F10)) {
        g_emulator.m_debug->stepOver();
    }
    ImGui::BeginChild("##ScrollingRegion", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
    ImGuiListClipper clipper(0x00290000 / 4);

    while (clipper.Step()) {
        bool skipNext = false;
        typedef std::function<void(uint32_t, const char*, uint32_t)> prependType;
        auto process = [&](uint32_t addr, prependType prepend, PCSX::Disasm* disasm) {
            uint32_t code = 0;
            uint32_t nextCode = 0;
            uint32_t base = 0;
            const char* section = "UNK";
            if (addr < 0x00200000) {
                section = "RAM";
                code = *reinterpret_cast<uint32_t*>(memory->g_psxM + addr);
                if (addr <= 0x001ffff8) {
                    nextCode = *reinterpret_cast<uint32_t*>(memory->g_psxM + addr + 4);
                }
                base = 0x80000000;
            } else if (addr < 0x00210000) {
                section = "PAR";
                addr -= 0x00200000;
                code = *reinterpret_cast<uint32_t*>(memory->g_psxP + addr);
                if (addr <= 0x0000fff8) {
                    nextCode = *reinterpret_cast<uint32_t*>(memory->g_psxP + addr + 4);
                }
                base = 0x1f000000;
            } else if (addr < 0x00290000) {
                section = "ROM";
                addr -= 0x00210000;
                code = *reinterpret_cast<uint32_t*>(memory->g_psxR + addr);
                if (addr <= 0x0007fff8) {
                    nextCode = *reinterpret_cast<uint32_t*>(memory->g_psxR + addr + 4);
                }
                base = 0xbfc00000;
            }
            prepend(code, section, addr | base);
            disasm->process(code, nextCode, addr | base, &skipNext);
        };
        if (clipper.DisplayStart != 0) {
            uint32_t addr = clipper.DisplayStart * 4 - 4;
            process(addr, [](uint32_t, const char*, uint32_t) {}, &dummy);
        }
        for (int x = clipper.DisplayStart; x < clipper.DisplayEnd; x++) {
            uint32_t addr = x * 4;
            Debug::bpiterator currentBP;
            prependType l = [&](uint32_t code, const char* section, uint32_t dispAddr) mutable {
                bool hasBP = false;
                PCSX::g_emulator.m_debug->ForEachBP([&](PCSX::Debug::bpiterator it) mutable {
                    uint32_t addr = dispAddr;
                    uint32_t bpAddr = it->Address();
                    uint32_t base = (addr >> 20) & 0xffc;
                    uint32_t bpBase = (bpAddr >> 20) & 0xffc;
                    if ((base == 0x000) || (base == 0x800) || (base == 0xa00)) {
                        addr &= 0x1fffff;
                    }
                    if ((bpBase == 0x000) || (bpBase == 0x800) || (bpBase == 0xa00)) {
                        bpAddr &= 0x1fffff;
                    }
                    if ((it->Type() == Debug::BE) && (addr == bpAddr)) {
                        hasBP = true;
                        currentBP = it;
                        return false;
                    }
                    return true;
                });

                char p = ' ';
                if (addr == pc) p = '>';
                if (hasBP) p = 'o';
                if (addr == pc && hasBP) p = 'X';

                imguiAsm.m_currentAddr = dispAddr;
                uint8_t b[4];
                auto tc = [](uint8_t c) -> char {
                    if (c <= 0x20) return '.';
                    if (c >= 0x7f) return '.';
                    return c;
                };
                b[0] = code & 0xff;
                code >>= 8;
                b[1] = code & 0xff;
                code >>= 8;
                b[2] = code & 0xff;
                code >>= 8;
                b[3] = code & 0xff;
                ImGui::Text("%c %s:%8.8x %c%c%c%c %8.8x: ", p, section, dispAddr, tc(b[0]), tc(b[1]), tc(b[2]), tc(b[3]), code);
                std::string contextMenuTitle = "assembly address menu ";
                contextMenuTitle += dispAddr;
                if (ImGui::BeginPopupContextItem(contextMenuTitle.c_str())) {
                    DButton("Run to cursor", !PCSX::g_system->running(), [&]() mutable {
                        PCSX::g_emulator.m_debug->AddBreakpoint(dispAddr, Debug::BE, true);
                        ImGui::CloseCurrentPopup();
                        PCSX::g_system->resume();
                    });
                    DButton("Set Breakpoint here", !hasBP, [&]() mutable {
                        PCSX::g_emulator.m_debug->AddBreakpoint(dispAddr, Debug::BE);
                        ImGui::CloseCurrentPopup();
                        hasBP = true;
                    });
                    DButton("Remove breakpoint from here", hasBP, [&]() mutable {
                        PCSX::g_emulator.m_debug->EraseBP(currentBP);
                        ImGui::CloseCurrentPopup();
                        hasBP = false;
                    });
                    ImGui::EndPopup();
                }
            };
            process(addr, l, &imguiAsm);
        }
    }
    if (m_followPC || jumpToPC) {
        uint64_t pctopx = (jumpToPC ? jumpToPCValue : pc) / 4;
        uint64_t scroll_to_px = pctopx * static_cast<uint64_t>(ImGui::GetTextLineHeightWithSpacing());
        ImGui::SetScrollFromPosY(ImGui::GetCursorStartPos().y + scroll_to_px, 0.5f);
    }
    ImGui::EndChild();
    ImGui::End();
}
