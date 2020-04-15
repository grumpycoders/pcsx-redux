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

#define GLFW_INCLUDE_NONE
#include <GL/gl3w.h>
#include <GLFW/glfw3.h>

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
static ImVec4 s_arrowColor = ImColor(0x61, 0x61, 0x61);
static ImVec4 s_arrowOutlineColor = ImColor(0x37, 0x37, 0x37);

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
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
        ImGui::Text("= %u", value);
        if (value >= 0x8000) {
            union {
                uint16_t x;
                int16_t y;
            } v;
            v.x = value;
            ImGui::Text("= -0x%4.4x", -v.y);
            ImGui::Text("= -%i", -v.y);
        }
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
    ImGui::PopStyleColor();
}
void PCSX::Widgets::Assembly::Imm32(uint32_t value) {
    comma();
    sameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, s_constantColor);
    ImGui::Text(" 0x%8.8x", value);
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
        ImGui::Text("= %u", value);
        if (value >= 0x80000000) {
            union {
                uint32_t x;
                int32_t y;
            } v;
            v.x = value;
            ImGui::Text("= -0x%8.8x", -v.y);
            ImGui::Text("= -%i", -v.y);
        }
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
    ImGui::PopStyleColor();
}
void PCSX::Widgets::Assembly::Target(uint32_t value) {
    comma();
    sameLine();
    char label[21];
    ImGui::Text("");
    ImGui::SameLine();
    if (m_displayArrowForJumps) m_arrows.push_back({m_currentAddr, value});
    std::snprintf(label, sizeof(label), "0x%8.8x##%8.8x", value, m_currentAddr);
    std::string longLabel = label;
    auto symbol = m_symbols.find(value);
    if (symbol != m_symbols.end()) longLabel = symbol->second + " ;" + label;
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
    if (ImGui::Button(longLabel.c_str())) {
        m_jumpToPC = true;
        m_jumpToPCValue = value;
    }
    ImGui::PopStyleVar();
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
    auto changeDataType = [](MemoryEditor* editor, int size) {
        bool isSigned = false;
        switch (editor->PreviewDataType) {
            case MemoryEditor::DataType_S8:
            case MemoryEditor::DataType_S16:
            case MemoryEditor::DataType_S32:
            case MemoryEditor::DataType_S64:
                isSigned = true;
                break;
        }
        switch (size) {
            case 1:
                editor->PreviewDataType = isSigned ? MemoryEditor::DataType_S8 : MemoryEditor::DataType_U8;
                break;
            case 2:
                editor->PreviewDataType = isSigned ? MemoryEditor::DataType_S16 : MemoryEditor::DataType_U16;
                break;
            case 4:
                editor->PreviewDataType = isSigned ? MemoryEditor::DataType_S32 : MemoryEditor::DataType_U32;
                break;
        }
    };
    if ((base == 0x000) || (base == 0x800) || (base == 0xa00)) {
        if (real < 0x00200000) {
            m_mainMemoryEditor->GotoAddrAndHighlight(real, real + size);
            changeDataType(m_mainMemoryEditor, size);
        }
    } else if (base == 0x1f8) {
        if (real >= 0x1000 && real < 0x3000) {
            m_hwMemoryEditor->GotoAddrAndHighlight(real - 0x1000, real - 0x1000 + size);
            changeDataType(m_hwMemoryEditor, size);
        }
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
    m_arrows.push_back({m_currentAddr, value});
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
    std::string longLabel = label;
    auto symbol = m_symbols.find(addr);
    if (symbol != m_symbols.end()) longLabel = symbol->second + " ;" + label;
    ImGui::Text("");
    ImGui::SameLine();
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
    if (ImGui::Button(longLabel.c_str())) jumpToMemory(addr, size);
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
        if (ImGui::BeginMenu(_("File"))) {
            openSymbolsDialog = ImGui::MenuItem(_("Load symbols map"));
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu(_("Debug"))) {
            if (ImGui::MenuItem(_("Pause"), nullptr, nullptr, g_system->running())) g_system->pause();
            if (ImGui::MenuItem(_("Resume"), nullptr, nullptr, !g_system->running())) g_system->resume();
            ImGui::Separator();
            if (ImGui::MenuItem(_("Step In"), nullptr, nullptr, !g_system->running())) g_emulator.m_debug->stepIn();
            if (ImGui::MenuItem(_("Step Over"), nullptr, nullptr, !g_system->running())) g_emulator.m_debug->stepOver();
            if (ImGui::MenuItem(_("Step Out"), nullptr, nullptr, !g_system->running())) g_emulator.m_debug->stepOut();
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu(_("Options"))) {
            ImGui::MenuItem(_("Combined pseudo-instructions"), nullptr, &m_pseudo);
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(glyphWidth * 35.0f);
                ImGui::TextWrapped(
                    _("When two instructions are detected to be a single pseudo-instruction, combine them into the "
                      "actual pseudo-instruction."));
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }
            ImGui::MenuItem(_("Pseudo-instrucitons filling"), nullptr, &m_pseudoFilling, m_pseudo);
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(glyphWidth * 35.0f);
                ImGui::TextWrapped(
                    _("When combining two instructions into a single pseudo-instruction, add a placeholder for the "
                      "second one."));
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }
            ImGui::MenuItem(_("Delay slot notch"), nullptr, &m_delaySlotNotch);
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(glyphWidth * 35.0f);
                ImGui::TextWrapped(
                    _("Add a small visible notch to indicate instructions that are on the delay slot of a branch."));
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }
            ImGui::MenuItem(_("Draw arrows for jumps"), nullptr, &m_displayArrowForJumps);
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(glyphWidth * 35.0f);
                ImGui::TextWrapped(_("Display arrows for jumps. This might crowd the display a bit too much."));
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }
            ImGui::SliderInt(_("Columns"), &m_numColumns, 0, 32);
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

    DummyAsm dummy;

    uint32_t pc = virtToReal(m_registers->pc);
    ImGui::Checkbox(_("Enable Debugger"), &PCSX::g_emulator.settings.get<PCSX::Emulator::SettingDebug>().value);
    ImGui::SameLine();
    ImGui::Checkbox(_("Follow PC"), &m_followPC);
    ImGui::SameLine();
    DButton(_("Pause"), g_system->running(), [&]() mutable { g_system->pause(); });
    ImGui::SameLine();
    DButton(_("Resume"), !g_system->running(), [&]() mutable { g_system->resume(); });
    ImGui::SameLine();
    DButton(_("Step In"), !g_system->running(), [&]() mutable { g_emulator.m_debug->stepIn(); });
    ImGui::SameLine();
    DButton(_("Step Over"), !g_system->running(), [&]() mutable { g_emulator.m_debug->stepOver(); });
    ImGui::SameLine();
    DButton(_("Step Out"), !g_system->running(), [&]() mutable { g_emulator.m_debug->stepOut(); });
    if (!g_system->running()) {
        if (ImGui::IsKeyPressed(GLFW_KEY_F10)) {
            g_emulator.m_debug->stepOver();
        } else if (ImGui::IsKeyPressed(GLFW_KEY_F11)) {
            if (ImGui::GetIO().KeyShift) {
                g_emulator.m_debug->stepOut();
            } else {
                g_emulator.m_debug->stepIn();
            }
        } else if (ImGui::IsKeyPressed(GLFW_KEY_F5)) {
            g_system->resume();
        }
    }

    ImGuiStyle& style = ImGui::GetStyle();
    const float heightSeparator = style.ItemSpacing.y;
    float footerHeight = 0;
    footerHeight += heightSeparator * 2 + ImGui::GetTextLineHeightWithSpacing();

    ImGui::BeginChild("##ScrollingRegion", ImVec2(0, -footerHeight), true, ImGuiWindowFlags_HorizontalScrollbar);
    ImGuiListClipper clipper(0x00290000 / 4);

    ImDrawList* drawList = ImGui::GetWindowDrawList();
    drawList->ChannelsSplit(129);
    drawList->ChannelsSetCurrent(128);
    ImVec2 topleft = drawList->GetClipRectMin();
    ImVec2 bottomright = drawList->GetClipRectMax();

    char* endPtr;
    uint32_t jumpAddressValue = strtoul(m_jumpAddressString, &endPtr, 16);
    bool jumpAddressValid = *m_jumpAddressString && !*endPtr;

    std::map<uint32_t, ImVec2> linesStartPos;
    m_arrows.clear();

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
                base = m_ramBase;
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
            process(
                addr, [](uint32_t, const char*, uint32_t) {}, &dummy);
        }
        for (int x = clipper.DisplayStart; x < clipper.DisplayEnd; x++) {
            uint32_t addr = x * 4;
            Debug::bpiterator currentBP;
            prependType l = [&](uint32_t code, const char* section, uint32_t dispAddr) mutable {
                bool hasBP = false;
                bool isBPEnabled = false;
                PCSX::g_emulator.m_debug->forEachBP([&](PCSX::Debug::bpiterator it) mutable {
                    uint32_t addr = dispAddr;
                    uint32_t bpAddr = it->first;
                    uint32_t base = (addr >> 20) & 0xffc;
                    uint32_t bpBase = (bpAddr >> 20) & 0xffc;
                    if ((base == 0x000) || (base == 0x800) || (base == 0xa00)) {
                        addr &= 0x1fffff;
                    }
                    if ((bpBase == 0x000) || (bpBase == 0x800) || (bpBase == 0xa00)) {
                        bpAddr &= 0x1fffff;
                    }
                    if ((it->second.type() == Debug::BE) && (addr == bpAddr)) {
                        hasBP = true;
                        isBPEnabled = it->second.enabled();
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

                auto symbol = m_symbols.find(dispAddr);
                if (symbol != m_symbols.end()) {
                    ImGui::PushStyleColor(ImGuiCol_Text, s_labelColor);
                    ImGui::Text("%s:", symbol->second.c_str());
                    ImGui::PopStyleColor();
                }

                for (int i = 0; i < m_numColumns * ImGui::GetWindowDpiScale(); i++) {
                    ImGui::Text("");
                    ImGui::SameLine();
                }

                ImVec2 pos = ImGui::GetCursorScreenPos();
                linesStartPos[dispAddr] = pos;

                if (jumpAddressValid && dispAddr == jumpAddressValue) {
                    const ImColor bgcolor = ImGui::GetStyle().Colors[ImGuiCol_FrameBg];
                    float height = ImGui::GetTextLineHeight();
                    float width = glyphWidth * 64;
                    drawList->AddRectFilled(pos, ImVec2(pos.x + width, pos.y + height), bgcolor);
                }
                if (hasBP) {
                    float x = pos.x + ImGui::GetTextLineHeight() / 2;
                    float y = pos.y + glyphWidth / 2;
                    if (isBPEnabled) {
                        drawList->AddCircleFilled(ImVec2(x, y), glyphWidth / 2, ImColor(s_bpColor));
                    } else {
                        drawList->AddCircle(ImVec2(x, y), glyphWidth / 2, ImColor(s_bpColor), 20, 1.5f);
                    }
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
                ImGui::Text("  %s:%8.8x %c%c%c%c %8.8x: ", section, dispAddr, tc(b[0]), tc(b[1]), tc(b[2]), tc(b[3]),
                            code);
                std::string contextMenuTitle = "assembly address menu ";
                contextMenuTitle += dispAddr;
                if (ImGui::BeginPopupContextItem(contextMenuTitle.c_str())) {
                    DButton(_("Run to cursor"), !PCSX::g_system->running(), [&]() mutable {
                        PCSX::g_emulator.m_debug->addBreakpoint(dispAddr, Debug::BE, true);
                        ImGui::CloseCurrentPopup();
                        PCSX::g_system->resume();
                    });
                    DButton(_("Set Breakpoint here"), !hasBP, [&]() mutable {
                        PCSX::g_emulator.m_debug->addBreakpoint(dispAddr, Debug::BE);
                        ImGui::CloseCurrentPopup();
                        hasBP = true;
                    });
                    DButton(_("Remove breakpoint from here"), hasBP, [&]() mutable {
                        PCSX::g_emulator.m_debug->eraseBP(currentBP);
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
    std::sort(m_arrows.begin(), m_arrows.end(), [](const auto& a, const auto& b) -> bool {
        int64_t distA = static_cast<int64_t>(a.first) - static_cast<int64_t>(a.second);
        int64_t distB = static_cast<int64_t>(b.first) - static_cast<int64_t>(b.second);
        return distA > distB;
    });
    std::map<unsigned, decltype(m_arrows)> allocated;
    for (auto& arrowData : m_arrows) {
        unsigned column = 0;
        bool found = false;
        uint32_t top = arrowData.first;
        uint32_t bottom = arrowData.second;
        if (top > bottom) std::swap(top, bottom);
        while (!found) {
            found = true;
            for (auto& toCompare : allocated[column]) {
                uint32_t topCompare = toCompare.first;
                uint32_t bottomCompare = toCompare.second;
                if (topCompare > bottomCompare) std::swap(topCompare, bottomCompare);
                if (((top < topCompare) && (topCompare < bottom)) ||
                    ((top < bottomCompare) && (bottomCompare < bottom)) ||
                    ((topCompare < top) && (bottom < bottomCompare))) {
                    found = false;
                    break;
                }
            }
            if (found || (column == 63)) {
                allocated[column].push_back(arrowData);
                break;
            } else {
                column++;
            }
        }
    }
    for (auto& columnData : allocated) {
        unsigned column = columnData.first;
        for (auto& arrowData : columnData.second) {
            const float thickness = glyphWidth / 4;
            auto src = linesStartPos.find(arrowData.first);
            auto dst = linesStartPos.find(arrowData.second);
            float sx = src->second.x + ImGui::GetTextLineHeight() / 2;
            float sy = src->second.y + glyphWidth / 2;
            float columnX = sx - glyphWidth * (column + 1);
            float direction = arrowData.first < arrowData.second ? 1.0f : -1.0f;
            ImVec2 p0, p1, cp0, cp1;
            p0.x = sx + glyphWidth / 4;
            p0.y = sy;
            p1.x = columnX;
            p1.y = sy + direction * ImGui::GetTextLineHeight() / 2;
            cp0.x = p1.x - thickness;
            cp0.y = p0.y;
            cp1.x = columnX;
            cp1.y = p0.y - thickness * direction;
            drawList->ChannelsSetCurrent(1 + column * 2);
            drawList->AddBezierCurve(p0, cp0, cp1, p1, ImColor(s_arrowColor), thickness);
            drawList->ChannelsSetCurrent(0 + column * 2);
            drawList->AddBezierCurve(p0, cp0, cp1, p1, ImColor(s_arrowOutlineColor), thickness + 4);
            if (dst != linesStartPos.end()) {
                float dx = dst->second.x + ImGui::GetTextLineHeight() / 2;
                float dy = dst->second.y + glyphWidth / 2;
                p0.x = columnX;
                p0.y = dy - direction * ImGui::GetTextLineHeight() / 2;
                drawList->ChannelsSetCurrent(1 + column * 2);
                drawList->AddBezierCurve(p0, p1, p0, p1, ImColor(s_arrowColor), thickness);
                drawList->ChannelsSetCurrent(0 + column * 2);
                drawList->AddBezierCurve(p0, p1, p0, p1, ImColor(s_arrowOutlineColor), thickness + 4);
                p1.x = dx + glyphWidth / 4;
                p1.y = dy;
                cp1.x = p0.x - thickness;
                cp1.y = p1.y;
                cp0.x = columnX;
                cp0.y = p1.y + thickness * direction;
                p1.x -= thickness;
                drawList->ChannelsSetCurrent(1 + column * 2);
                drawList->AddBezierCurve(p0, cp0, cp1, p1, ImColor(s_arrowColor), thickness);
                drawList->ChannelsSetCurrent(0 + column * 2);
                drawList->AddBezierCurve(p0, cp0, cp1, p1, ImColor(s_arrowOutlineColor), thickness + 4);
                ImVec2 a, b, c;
                a = b = c = p1;
                a.x += thickness;
                b.x -= thickness;
                b.y -= thickness;
                c.x -= thickness;
                c.y += thickness;
                drawList->ChannelsSetCurrent(1 + column * 2);
                drawList->AddTriangleFilled(a, b, c, ImColor(s_arrowColor));
                a.x += 2;
                b.x -= 2;
                b.y -= 2;
                c.x -= 2;
                c.y += 2;
                drawList->ChannelsSetCurrent(0 + column * 2);
                drawList->AddTriangleFilled(a, b, c, ImColor(s_arrowOutlineColor));
            } else {
                float height = bottomright.y - topleft.y;
                ImVec2 out;
                out.x = p1.x;
                out.y = height * 2 * direction;
                drawList->ChannelsSetCurrent(1 + column * 2);
                drawList->AddBezierCurve(p1, out, p1, out, ImColor(s_arrowColor), thickness);
                drawList->ChannelsSetCurrent(0 + column * 2);
                drawList->AddBezierCurve(p1, out, p1, out, ImColor(s_arrowOutlineColor), thickness + 4);
            }
        }
    }
    drawList->ChannelsMerge();
    ImGui::EndChild();
    if (m_jumpToPC) {
        std::snprintf(m_jumpAddressString, 19, "%08x", m_jumpToPCValue);
    }
    ImGui::PushItemWidth(10 * glyphWidth + style.FramePadding.x);
    if (ImGui::InputText(_("Address"), m_jumpAddressString, 20,
                         ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue)) {
        char* endPtr;
        uint32_t jumpAddress = strtoul(m_jumpAddressString, &endPtr, 16);
        if (*m_jumpAddressString && !*endPtr) {
            m_jumpToPC = true;
            m_jumpToPCValue = jumpAddress;
        }
    }
    static const char* baseStrs[] = {"00000000", "80000000", "a0000000"};
    static const uint32_t baseValues[] = {0x00000000, 0x80000000, 0xa0000000};
    int base = 0;
    if (m_ramBase == 0x80000000) base = 1;
    if (m_ramBase == 0xa0000000) base = 2;
    ImGui::SameLine();
    if (ImGui::BeginCombo(_("RAM base"), baseStrs[base])) {
        for (int i = 0; i < 3; i++) {
            if (ImGui::Selectable(baseStrs[i], base == i)) {
                m_ramBase = baseValues[i];
            }
        }
        ImGui::EndCombo();
    }
    ImGui::PopItemWidth();
    ImGui::BeginChild("##ScrollingRegion", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
    if (m_followPC || m_jumpToPC) {
        if (m_followPC) {
            uint32_t basePC = (m_registers->pc >> 20) & 0xffc;
            switch (basePC) {
                case 0x000:
                    m_ramBase = 0x00000000;
                    break;
                case 0x800:
                    m_ramBase = 0x80000000;
                    break;
                case 0xa00:
                    m_ramBase = 0xa0000000;
                    break;
            }
        }
        uint64_t pctopx = (m_jumpToPC ? virtToReal(m_jumpToPCValue) : pc) / 4;
        uint64_t scroll_to_px = pctopx * static_cast<uint64_t>(ImGui::GetTextLineHeightWithSpacing());
        ImGui::SetScrollFromPosY(ImGui::GetCursorStartPos().y + scroll_to_px, 0.5f);
        m_jumpToPC = false;
    }
    ImGui::EndChild();
    ImGui::End();

    if (openSymbolsDialog) m_symbolsFileDialog.openDialog();
    if (m_symbolsFileDialog.draw()) {
        std::vector<PCSX::u8string> filesToOpen = m_symbolsFileDialog.selected();
        for (auto fileName : filesToOpen) {
            std::ifstream file;
            // oh the irony
            file.open(reinterpret_cast<const char *>(fileName.c_str()));
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
