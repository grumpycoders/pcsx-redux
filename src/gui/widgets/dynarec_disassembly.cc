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

#include "gui/widgets/dynarec_disassembly.h"

#include <capstone/capstone.h>

#include "gui/gui.h"
#include "imgui.h"
#include "imgui_stdlib.h"
//#include <stdio.h>
#include <inttypes.h>

void PCSX::Widgets::Disassembly::draw(GUI* gui, const char* title) {
    ImGui::SetNextWindowSize(ImVec2(520, 600), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    if (ImGui::Button("Disassemble Buffer")) {
        m_tryDisassembly = true;
    }
    // Will re-enable once file handling is implemented
    // ImGui::Checkbox("Output to File", &m_outputFile);

    if (m_tryDisassembly) m_result = disassembleBuffer();

    if (m_showError) {
        ImGui::OpenPopup("Disassembler Error");
        if (ImGui::BeginPopupModal("Disassembler Error", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
            switch (m_result) {
                case disassemblerResult::INVALID_BFR:
                    ImGui::Text("Code buffer pointer is null");
                    break;
                case disassemblerResult::INVALID_BFR_SIZE:
                    ImGui::Text("Invalid buffer size\nCheck logs");
                    break;
                case disassemblerResult::CS_INIT_FAIL:
                    ImGui::Text("Failed to initialize Capstone Disassembler\nCheck logs");
                    break;
                case disassemblerResult::CS_DIS_FAIL:
                    ImGui::Text("Failed to disassemble buffer\nCheck logs");
                    break;
                default: {
                    ImGui::Text("Unknown Disassembler Error\nCheck logs");
                    break;
                }
            }
            if (ImGui::Button("Close")) {
                ImGui::CloseCurrentPopup();
                m_showError = false;
            }
        }
        ImGui::EndPopup();
    }

    if (ImGui::BeginPopupContextItem()) {
        if (ImGui::MenuItem("Close Disassembler")) m_show = false;
        ImGui::EndPopup();
    }

    ImGui::SameLine();
    if (ImGui::SmallButton("Clear")) m_items.clear();
    ImGui::SameLine();
    bool copy_to_clipboard = ImGui::SmallButton("Copy");

    ImGui::Separator();

    // Options menu
    if (ImGui::BeginPopup("Options")) {
        ImGui::Checkbox("Auto-scroll", &m_autoScroll);
        ImGui::Checkbox("Mono", &m_mono);
        ImGui::EndPopup();
    }

    // Options, Filter
    if (ImGui::Button("Options")) ImGui::OpenPopup("Options");
    ImGui::Separator();

    // Reserve enough left-over height for 1 separator + 1 input text
    if (m_mono) gui->useMonoFont();
    const float footer_height_to_reserve = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();
    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footer_height_to_reserve), false,
                      ImGuiWindowFlags_HorizontalScrollbar);

    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 1));  // Tighten spacing
    if (copy_to_clipboard) ImGui::LogToClipboard();
    for (auto& item : m_items) {
        ImGui::TextUnformatted(item.c_str());
    }

    if (copy_to_clipboard) ImGui::LogFinish();

    if (m_scrollToBottom || (m_autoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())) {
        ImGui::SetScrollHereY(1.0f);
    }
    m_scrollToBottom = false;

    ImGui::PopStyleVar();
    ImGui::EndChild();
    if (m_mono) ImGui::PopFont();
    ImGui::Separator();

    // Auto-focus on window apparition
    ImGui::SetItemDefaultFocus();

    ImGui::End();
}

PCSX::Widgets::Disassembly::disassemblerResult PCSX::Widgets::Disassembly::disassembleBuffer() {
    csh handle;
    cs_insn* insn;
    size_t count;

    // Get pointer to code buffer along with size of buffer
    const uint8_t* buffer = PCSX::g_emulator->m_psxCpu->getBufferPtr();
    const size_t bufferSize = PCSX::g_emulator->m_psxCpu->getBufferSize();
    // Check to ensure code buffer pointer is not null and size is not 0
    if (buffer == nullptr) {
        m_showError = true;
        m_tryDisassembly = false;
        return PCSX::Widgets::Disassembly::disassemblerResult::INVALID_BFR;
    } else if (bufferSize <= 0) {
        m_showError = true;
        m_tryDisassembly = false;
        return PCSX::Widgets::Disassembly::disassemblerResult::INVALID_BFR_SIZE;
    }
    // Attempt disassembly of code buffer
    if (m_tryDisassembly) {
        // Attempt to initialize Capstone disassembler, if error log it and return
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            PCSX::g_system->message("ERROR: Failed to initialize capstone disassembler!\n");
            m_tryDisassembly = false;
            return PCSX::Widgets::Disassembly::disassemblerResult::CS_INIT_FAIL;
        }
        // Set SKIPDATA option as to not break disassembler
        cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
        // Walk code buffer and try to disassemble
        count = cs_disasm(handle, buffer, bufferSize, 0x0, 0, &insn);
        if (count > 0) {
            size_t j;
            for (j = 0; j < count; j++) {
                // Write instruction (address, mnemonic, and operand to string
                std::string s =
                    fmt::sprintf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
                // Log each instruction to the disassembly window string vector
                addInstruction(s);
            }
            // Call free to clean up memory allocated by capstone
            cs_free(insn, count);
            // to show the end of the disassembly for the disassembled buffer
            addInstruction("----End of disassembly----\n");
            // If disassembly failed, log the error and close out disassembler
        } else {
            cs_close(&handle);
            m_tryDisassembly = false;
            return PCSX::Widgets::Disassembly::disassemblerResult::CS_DIS_FAIL;
        }
        // Sucessful disassembly, clean up disassembler instance and return successful result
        cs_close(&handle);
        m_tryDisassembly = false;
        return PCSX::Widgets::Disassembly::disassemblerResult::SUCCESS;
    }
}