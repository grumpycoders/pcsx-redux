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

#include <fstream>
#include <functional>
#include <iostream>

#include "imgui.h"

#include "core/debug.h"
#include "core/disr3000a.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "gui/widgets/assembly.h"

#include "imgui_memory_editor/imgui_memory_editor.h"

static ImVec4 s_constantColor = ImColor(0x03, 0xda, 0xc6);
static ImVec4 s_invalidColor = ImColor(0xb0, 0x00, 0x20);
static ImVec4 s_labelColor = ImColor(0x01, 0x87, 0x86);
static ImVec4 s_bpColor = ImColor(0xba, 0x00, 0x0d);
static ImVec4 s_currentColor = ImColor(0xff, 0xeb, 0x3b);

namespace {

uint32_t virtToReal(uint32_t virt) {
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
    virtual void Invalid() final {}
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
    virtual void BranchDest(uint32_t offset) final {}
    virtual void Offset(uint32_t offset, int size) final {}
};

}  // namespace

uint8_t PCSX::Widgets::Assembly::mem8(uint32_t addr) { return *ptr(addr); }
uint16_t PCSX::Widgets::Assembly::mem16(uint32_t addr) { return SWAP_LE16(*(int16_t*)ptr(addr)); }
uint32_t PCSX::Widgets::Assembly::mem32(uint32_t addr) { return SWAP_LE32(*(int32_t*)ptr(addr)); }
void PCSX::Widgets::Assembly::sameLine() { ImGui::SameLine(0.0f, 0.0f); }
void PCSX::Widgets::Assembly::comma() {
    if (m_gotArg) {
        sameLine();
        ImGui::Text(",");
    }
    m_gotArg = true;
}
void PCSX::Widgets::Assembly::Invalid() {
    m_gotArg = false;
    sameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, s_invalidColor);
    ImGui::Text("(**invalid**)");
    ImGui::PopStyleColor();
}

void PCSX::Widgets::Assembly::OpCode(const char* str) {
    m_gotArg = false;
    sameLine();
    if (m_notch) {
        ImGui::TextDisabled("~");
        ImGui::SameLine();
        ImGui::Text("%-6s", str);
    } else {
        ImGui::Text("%-8s", str);
    }
}
void PCSX::Widgets::Assembly::GPR(uint8_t reg) {
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
void PCSX::Widgets::Assembly::CP0(uint8_t reg) {
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
void PCSX::Widgets::Assembly::CP2C(uint8_t reg) {
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
void PCSX::Widgets::Assembly::CP2D(uint8_t reg) {
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
void PCSX::Widgets::Assembly::HI() {
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
void PCSX::Widgets::Assembly::LO() {
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
void PCSX::Widgets::Assembly::Imm(uint16_t value) {
    comma();
    sameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, s_constantColor);
    ImGui::Text(" 0x%4.4x", value);
    ImGui::PopStyleColor();
}
void PCSX::Widgets::Assembly::Imm32(uint32_t value) {
    comma();
    sameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, s_constantColor);
    ImGui::Text(" 0x%8.8x", value);
    ImGui::PopStyleColor();
}
void PCSX::Widgets::Assembly::Target(uint32_t value) {
    comma();
    sameLine();
    char label[21];
    ImGui::Text("");
    ImGui::SameLine();
    std::snprintf(label, sizeof(label), "0x%8.8x##%8.8x", value, m_currentAddr);
    auto symbol = m_symbols.find(value);
    if (symbol == m_symbols.end()) {
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
        if (ImGui::Button(label)) {
            m_jumpToPC = true;
            m_jumpToPCValue = value;
        }
        ImGui::PopStyleVar();
    } else {
        std::string longLabel = symbol->second + " ;" + label;
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
        if (ImGui::Button(longLabel.c_str())) {
            m_jumpToPC = true;
            m_jumpToPCValue = value;
        }
        ImGui::PopStyleVar();
    }
}
void PCSX::Widgets::Assembly::Sa(uint8_t value) {
    comma();
    sameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, s_constantColor);
    ImGui::Text(" 0x%2.2x", value);
    ImGui::PopStyleColor();
}
uint8_t* PCSX::Widgets::Assembly::ptr(uint32_t addr) {
    uint8_t* lut = m_memory->g_psxMemRLUT[addr >> 16];
    if (lut) {
        return lut + (addr & 0xffff);
    } else {
        static uint8_t dummy[4] = {0, 0, 0, 0};
        return dummy;
    }
}
void PCSX::Widgets::Assembly::jumpToMemory(uint32_t addr, int size) {
    uint32_t base = (addr >> 20) & 0xffc;
    uint32_t real = addr & 0x1fffff;
    if ((base == 0x000) || (base == 0x800) || (base == 0xa00)) {
        if (real < 0x00200000) m_mainMemoryEditor->GotoAddrAndHighlight(real, real + size);
    } else if (base == 0x1f8) {
        if (real >= 0x1000 && real < 0x3000)
            m_hwMemoryEditor->GotoAddrAndHighlight(real - 0x1000, real - 0x1000 + size);
    }
}

void PCSX::Widgets::Assembly::OfB(int16_t offset, uint8_t reg, int size) {
    comma();
    sameLine();
    char label[32];
    if (offset < 0) {
        std::snprintf(label, sizeof(label), "-0x%4.4x($%s)##%08x", -offset, s_disRNameGPR[reg], m_currentAddr);
    } else {
        std::snprintf(label, sizeof(label), "0x%4.4x($%s)##%08x", offset, s_disRNameGPR[reg], m_currentAddr);
    }
    uint32_t addr = m_registers->GPR.r[reg] + offset;
    ImGui::Text("");
    ImGui::SameLine();
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
    if (ImGui::Button(label)) jumpToMemory(addr, size);
    ImGui::PopStyleVar();
    if (ImGui::IsItemHovered()) {
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
void PCSX::Widgets::Assembly::BranchDest(uint32_t value) {
    comma();
    sameLine();
    char label[21];
    ImGui::Text("");
    ImGui::SameLine();
    std::snprintf(label, sizeof(label), "0x%8.8x##%8.8x", value, m_currentAddr);
    auto symbol = m_symbols.find(value);
    if (symbol == m_symbols.end()) {
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
        if (ImGui::Button(label)) {
            m_jumpToPC = true;
            m_jumpToPCValue = value;
        }
        ImGui::PopStyleVar();
    } else {
        std::string longLabel = symbol->second + " ;" + label;
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
        if (ImGui::Button(longLabel.c_str())) {
            m_jumpToPC = true;
            m_jumpToPCValue = value;
        }
        ImGui::PopStyleVar();
    }
}
void PCSX::Widgets::Assembly::Offset(uint32_t addr, int size) {
    comma();
    sameLine();
    char label[32];
    std::snprintf(label, sizeof(label), "0x%8.8x##%8.8x", addr, m_currentAddr);
    ImGui::Text("");
    ImGui::SameLine();
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
    if (ImGui::Button(label)) jumpToMemory(addr, size);
    ImGui::PopStyleVar();
    if (ImGui::IsItemHovered()) {
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

void PCSX::Widgets::Assembly::draw(psxRegisters* registers, Memory* memory, const char* title) {
    m_registers = registers;
    m_memory = memory;
    ImGui::SetNextWindowPos(ImVec2(10, 30), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(500, 500), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show, ImGuiWindowFlags_MenuBar)) {
        ImGui::End();
        return;
    }

    float glyphWidth = ImGui::GetFontSize();

    bool openSymbolsDialog = false;

    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            openSymbolsDialog = ImGui::MenuItem("Load symbols map");
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Debug")) {
            if (ImGui::MenuItem("Pause", nullptr, nullptr, g_system->running())) g_system->pause();
            if (ImGui::MenuItem("Resume", nullptr, nullptr, !g_system->running())) g_system->resume();
            ImGui::Separator();
            if (ImGui::MenuItem("Step In", nullptr, nullptr, !g_system->running())) g_emulator.m_debug->stepIn();
            if (ImGui::MenuItem("Step Over", nullptr, nullptr, !g_system->running())) g_emulator.m_debug->stepOver();
            if (ImGui::MenuItem("Step Out", nullptr, nullptr, !g_system->running())) g_emulator.m_debug->stepOut();
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Options")) {
            ImGui::MenuItem("Combined pseudo-instructions", nullptr, &m_pseudo);
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(glyphWidth * 35.0f);
                ImGui::TextWrapped(
                    "When two instructions are detected to be a single pseudo-instruction, combine them into the "
                    "actual pseudo-instruction.");
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }
            ImGui::MenuItem("Pseudo-instrucitons filling", nullptr, &m_pseudoFilling, m_pseudo);
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(glyphWidth * 35.0f);
                ImGui::TextWrapped(
                    "When combining two instructions into a single pseudo-instruction, add a placeholder for the "
                    "second one.");
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }
            ImGui::MenuItem("Delay slot notch", nullptr, &m_delaySlotNotch);
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(glyphWidth * 35.0f);
                ImGui::TextWrapped(
                    "Add a small visible notch to indicate instructions that are on the delay slot of a branch.");
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

    DummyAsm dummy;

    uint32_t pc = virtToReal(m_registers->pc);
    ImGui::Checkbox("Follow PC", &m_followPC);
    ImGui::SameLine();
    DButton("Pause", g_system->running(), [&]() mutable { g_system->pause(); });
    ImGui::SameLine();
    DButton("Resume", !g_system->running(), [&]() mutable { g_system->resume(); });
    ImGui::SameLine();
    DButton("Step In", !g_system->running(), [&]() mutable { g_emulator.m_debug->stepIn(); });
    ImGui::SameLine();
    DButton("Step Over", !g_system->running(), [&]() mutable { g_emulator.m_debug->stepOver(); });
    ImGui::SameLine();
    DButton("Step Out", !g_system->running(), [&]() mutable { g_emulator.m_debug->stepOut(); });
    if (!g_system->running()) {
        if (ImGui::IsKeyPressed(SDL_SCANCODE_F10)) {
            g_emulator.m_debug->stepOver();
        } else if (ImGui::IsKeyPressed(SDL_SCANCODE_F11)) {
            if (ImGui::GetIO().KeyShift) {
                g_emulator.m_debug->stepOut();
            } else {
                g_emulator.m_debug->stepIn();
            }
        } else if (ImGui::IsKeyPressed(SDL_SCANCODE_F5)) {
            g_system->resume();
        }
    }
    ImGuiStyle& style = ImGui::GetStyle();
    const float heightSeparator = style.ItemSpacing.y;
    float footerHeight = 0;
    footerHeight += heightSeparator * 2 + ImGui::GetTextLineHeightWithSpacing();
    ImGui::BeginChild("##ScrollingRegion", ImVec2(0, -footerHeight), true, ImGuiWindowFlags_HorizontalScrollbar);
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    ImGuiListClipper clipper(0x00290000 / 4);

    char* endPtr;
    uint32_t jumpAddressValue = strtoul(m_jumpAddressString, &endPtr, 16);
    bool jumpAddressValid = *m_jumpAddressString && !*endPtr;

    while (clipper.Step()) {
        bool skipNext = false;
        bool delaySlotNext = false;
        typedef std::function<void(uint32_t, const char*, uint32_t)> prependType;
        auto process = [&](uint32_t addr, prependType prepend, PCSX::Disasm* disasm) {
            uint32_t code = 0;
            uint32_t nextCode = 0;
            uint32_t base = 0;
            const char* section = "UNK";
            if (addr < 0x00200000) {
                section = "RAM";
                code = *reinterpret_cast<uint32_t*>(m_memory->g_psxM + addr);
                if (addr <= 0x001ffff8) {
                    nextCode = *reinterpret_cast<uint32_t*>(m_memory->g_psxM + addr + 4);
                }
                base = 0x80000000;
            } else if (addr < 0x00210000) {
                section = "PAR";
                addr -= 0x00200000;
                code = *reinterpret_cast<uint32_t*>(m_memory->g_psxP + addr);
                if (addr <= 0x0000fff8) {
                    nextCode = *reinterpret_cast<uint32_t*>(m_memory->g_psxP + addr + 4);
                }
                base = 0x1f000000;
            } else if (addr < 0x00290000) {
                section = "ROM";
                addr -= 0x00210000;
                code = *reinterpret_cast<uint32_t*>(m_memory->g_psxR + addr);
                if (addr <= 0x0007fff8) {
                    nextCode = *reinterpret_cast<uint32_t*>(m_memory->g_psxR + addr + 4);
                }
                base = 0xbfc00000;
            }
            prepend(code, section, addr | base);
            disasm->process(code, nextCode, addr | base, m_pseudo ? &skipNext : nullptr, &delaySlotNext);
            m_notch = delaySlotNext & m_delaySlotNotch;
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

                m_currentAddr = dispAddr;
                uint8_t b[4];
                auto tc = [](uint8_t c) -> char {
                    if (c <= 0x20) return '.';
                    if (c >= 0x7f) return '.';
                    return c;
                };
                uint32_t tcode = code;
                b[0] = tcode & 0xff;
                tcode >>= 8;
                b[1] = tcode & 0xff;
                tcode >>= 8;
                b[2] = tcode & 0xff;
                tcode >>= 8;
                b[3] = tcode & 0xff;
                ImVec2 pos = ImGui::GetCursorScreenPos();
                if (jumpAddressValid && dispAddr == jumpAddressValue) {
                    const ImColor bgcolor = ImGui::GetStyle().Colors[ImGuiCol_FrameBg];
                    float height = ImGui::GetTextLineHeight();
                    float width = glyphWidth * 64;
                    drawList->AddRectFilled(pos, ImVec2(pos.x + width, pos.y + height), bgcolor);
                }
                auto symbol = m_symbols.find(dispAddr);
                if (symbol != m_symbols.end()) {
                    ImGui::PushStyleColor(ImGuiCol_Text, s_labelColor);
                    ImGui::Text("%s:", symbol->second.c_str());
                    ImGui::PopStyleColor();
                }
                if (hasBP) {
                    float x = pos.x + ImGui::GetTextLineHeight() / 2;
                    float y = pos.y + glyphWidth / 2;
                    drawList->AddCircleFilled(ImVec2(x, y), glyphWidth / 2, ImColor(s_bpColor));
                }
                if (addr == pc) {
                    /*
                       a
                    d  +
                    +--+\
                    |  | + c
                    +--+/e
                       +
                       b
                    */
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
                ImGui::Text("  %s:%8.8x %c%c%c%c %8.8x: ", section, dispAddr, tc(b[0]), tc(b[1]), tc(b[2]),
                            tc(b[3]), code);
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
                if (skipNext && m_pseudoFilling) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("(pseudo)");
                }
            };
            process(addr, l, this);
        }
    }
    ImGui::EndChild();
    if (m_jumpToPC) {
        std::snprintf(m_jumpAddressString, 19, "%08x", m_jumpToPCValue);
    }
    ImGui::PushItemWidth(10 * glyphWidth + style.FramePadding.x);
    if (ImGui::InputText("##address", m_jumpAddressString, 20,
                         ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue)) {
        char* endPtr;
        uint32_t jumpAddress = strtoul(m_jumpAddressString, &endPtr, 16);
        if (*m_jumpAddressString && !*endPtr) {
            m_jumpToPC = true;
            m_jumpToPCValue = jumpAddress;
        }
    }
    ImGui::PopItemWidth();
    ImGui::BeginChild("##ScrollingRegion", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
    if (m_followPC || m_jumpToPC) {
        uint64_t pctopx = (m_jumpToPC ? virtToReal(m_jumpToPCValue) : pc) / 4;
        uint64_t scroll_to_px = pctopx * static_cast<uint64_t>(ImGui::GetTextLineHeightWithSpacing());
        ImGui::SetScrollFromPosY(ImGui::GetCursorStartPos().y + scroll_to_px, 0.5f);
        m_jumpToPC = false;
    }
    ImGui::EndChild();
    ImGui::End();

    if (openSymbolsDialog) m_symbolsFileDialog.openDialog();
    if (m_symbolsFileDialog.draw()) {
        std::vector<std::string> filesToOpen = m_symbolsFileDialog.selected();
        for (auto fileName : filesToOpen) {
            std::ifstream file;
            file.open(fileName);
            if (!file) continue;
            while (!file.eof()) {
                std::string addressString;
                std::string name;
                file >> addressString >> name;
                char* endPtr;
                uint32_t address = strtoul(addressString.c_str(), &endPtr, 16);
                bool addressValid = addressString[0] && !*endPtr;
                if (!addressValid) continue;
                m_symbols[address] = name;
            }
        }
    }
}
