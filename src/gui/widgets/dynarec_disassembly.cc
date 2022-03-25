/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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
#ifdef _WIN32
#include <capstone/capstone.h>
#else
#include <capstone.h>
#endif

#include <cinttypes>
#include <fstream>

#include "gui/gui.h"
#include "imgui.h"

void PCSX::Widgets::Disassembly::writeFile() {
    std::ofstream file;
    // Open file - default location in resources directory
    file.open("DynarecDisassembly.txt", std::ios::app);
    // If file exists, write to it, otherwise return
    if (file) {
        for (auto i = 0; i < m_items.size(); ++i) {
            file << m_items[i];
        }
    } else {
        PCSX::g_system->printf("Disassembler Error: failed to open output file for disassembly.\n");
        m_showError = true;
        return;
    }
    // Close out file
    file.close();
    // If bad bit is set, there was an error, return -1
    if (file.fail()) {
        PCSX::g_system->printf("Disassembler Error: failed to write disassembly to output file.\n");
        m_showError = true;
    }
}

void PCSX::Widgets::Disassembly::draw(GUI* gui, const char* title) {
    ImGui::SetNextWindowSize(ImVec2(520, 600), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }
    // Disassemble button
    if (ImGui::Button("Disassemble Buffer")) {
        m_codeSize = disassembleBuffer();
    }
    ImGui::SameLine();
    // Save to File button
    if (ImGui::Button("Save to File")) {
        writeFile();
    }
    // Error popup
    if (m_showError) {
        ImGui::OpenPopup("Disassembler Error");
        if (ImGui::BeginPopupModal("Disassembler Error", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::Text("Disassembly Failed.\nCheck Logs");
            if (ImGui::Button("Close")) {
                ImGui::CloseCurrentPopup();
                m_showError = false;
            }
        }
        ImGui::EndPopup();
    }
    // Close error popup
    if (ImGui::BeginPopupContextItem()) {
        if (ImGui::MenuItem("Close Disassembler")) {
            m_show = false;
        }
        ImGui::EndPopup();
    }

    ImGui::Separator();
    // Clear items button
    if (ImGui::SmallButton("Clear")) {
        m_items.clear();
        m_codeSize = 0;
    }
    ImGui::SameLine();
    bool copy_to_clipboard = ImGui::SmallButton("Copy");

    // Options menu
    if (ImGui::BeginPopup("Options")) {
        ImGui::Checkbox("Auto-scroll", &m_autoScroll);
        ImGui::Checkbox("Mono", &m_mono);
        ImGui::EndPopup();
    }

    ImGui::SameLine();
    // Options, Filter
    if (ImGui::SmallButton("Options")) {
        ImGui::OpenPopup("Options");
    }

    ImGui::SameLine();
    // Show buffer size returned from disassembly function
    ImGui::Text("Code size: %.2fMB", (double)m_codeSize / (1024 * 1024));
    ImGui::Separator();

    if (m_mono) {
        gui->useMonoFont();
    }
    // Scrolling child window containing diassembly output
    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -4), false, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 1));  // Tighten spacing

    if (copy_to_clipboard) {
        ImGui::LogToClipboard();
    }
    // Loop through vec and display each string item in scrolling region
    for (auto& item : m_items) {
        ImGui::TextUnformatted(item.c_str());
    }

    if (copy_to_clipboard) {
        ImGui::LogFinish();
    }

    if (m_scrollToBottom || (m_autoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())) {
        ImGui::SetScrollHereY(1.0f);
    }
    m_scrollToBottom = false;

    ImGui::PopStyleVar();
    ImGui::EndChild();

    if (m_mono) {
        ImGui::PopFont();
    }

    ImGui::Separator();

    // Auto-focus on window apparition
    ImGui::SetItemDefaultFocus();

    ImGui::End();
}

size_t PCSX::Widgets::Disassembly::disassembleBuffer() {
    csh handle;
    cs_insn* insn;
    size_t count;

    // Get pointer to code buffer along with size of buffer
    const uint8_t* buffer = PCSX::g_emulator->m_psxCpu->getBufferPtr();
    const size_t bufferSize = PCSX::g_emulator->m_psxCpu->getBufferSize();
    // Check to ensure code buffer pointer is not null and size is not 0
    if (buffer == nullptr) {
        PCSX::g_system->printf("Disassembler Error: nullpointer to code buffer.\n");
        m_showError = true;
        return 0;
    } else if (bufferSize <= 0) {
        PCSX::g_system->printf("Disassembler Error: Invalid code buffer size.\n");
        m_showError = true;
        return 0;
    }
    // Attempt to initialize Capstone disassembler, if error log it and return
    if (cs_open(CS_ARCH, CS_MODE, &handle) != CS_ERR_OK) {
        PCSX::g_system->printf("Disassembler Error: Failed to initialize Capstone.\n");
        m_showError = true;
        return 0;
    }
    // Set SKIPDATA option as to not break disassembler
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    // Walk code buffer and try to disassemble
    count = cs_disasm(handle, buffer, bufferSize, 0x0, 0, &insn);
    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            // Write instruction (address, mnemonic, and operand to string
            std::string s =
                fmt::sprintf("%#010" PRIx64 ":\t\t%-12s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
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
        PCSX::g_system->printf("Disassembler Error: Failed to disassemble buffer.\n");
        m_showError = true;
        return 0;
    }
    // Successful disassembly, clean up disassembler instance and return successful result
    cs_close(&handle);
    return bufferSize;
}
