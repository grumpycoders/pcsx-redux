//
// Created by Caleb Yates on 12/16/21.
//

#include "gui/widgets/dynarec_disassembly.h"

#include "gui/gui.h"
#include "imgui.h"
#include "imgui_stdlib.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <inttypes.h>

void PCSX::Widgets::Disassembly::draw(GUI* gui, const char* title) {
    ImGui::SetNextWindowSize(ImVec2(520, 600), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }
//    PCSX::g_system->message("DOING THAT");
    if (ImGui::Button("Dump Buffer")) {
         m_tryDisassembly = true;
    }
    ImGui::Checkbox("Output File", &m_outputFile);

    if (m_tryDisassembly)
        m_result = disassembleBuffer();

    if (m_showError) {
        ImGui::OpenPopup("Disassembler Error");
        if (ImGui::BeginPopupModal("Disassembler Error", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
            switch(m_result) {
                case disassemblerResult::INVALID_BFR:
                    ImGui::Text("CodeBuffer pointer is invalid");
                    break;
                case disassemblerResult::INVALID_BFR_SIZE:
                    ImGui::Text("Bad Buffer Size");
                    break;
                case disassemblerResult::CS_INIT_FAIL:
                    ImGui::Text("Failed to initialize Capstone Disassembler\n Check Logs");
                    break;
                case disassemblerResult::CS_DIS_FAIL:
                    ImGui::Text("Failed to disassembler buffer\n Check Logs");
                    break;
                default: {
                    ImGui::Text("Unknown Disassembler Error");
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
        if (ImGui::MenuItem("Close Disassembly")) m_show = false;
        ImGui::EndPopup();
    }

    ImGui::SameLine();
    if (ImGui::SmallButton("Clear")) m_items.clear();
    ImGui::SameLine();
    bool copy_to_clipboard = ImGui::SmallButton("Copy");

    ImGui::Separator();

//    // Options menu
    if (ImGui::BeginPopup("Options")) {
        ImGui::Checkbox("Auto-scroll", &m_autoScroll);
        ImGui::Checkbox("Mono", &m_mono);
        ImGui::EndPopup();
    }

    // Options, Filter
    if (ImGui::Button("Options")) ImGui::OpenPopup("Options");
    ImGui::Separator();
//
//    // Reserve enough left-over height for 1 separator + 1 input text
    if (m_mono) gui->useMonoFont();
    const float footer_height_to_reserve = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();
    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footer_height_to_reserve), false,
                      ImGuiWindowFlags_HorizontalScrollbar);
//
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 1));  // Tighten spacing
    if (copy_to_clipboard) ImGui::LogToClipboard();
    for (auto& item : m_items) {
//        ImVec4 color;
//        bool has_color = false;
//        switch (item.first) {
//            case LineType::ERRORMSG:
//                color = ImVec4(1.0f, 0.4f, 0.4f, 1.0f);
//                has_color = true;
//                break;
//            case LineType::COMMAND:
//                color = ImVec4(1.0f, 0.8f, 0.6f, 1.0f);
//                has_color = true;
//                break;
//        }
//        if (has_color) ImGui::PushStyleColor(ImGuiCol_Text, color);
        ImGui::TextUnformatted(item.c_str());
//        if (has_color) ImGui::PopStyleColor();
    }
    if (copy_to_clipboard) ImGui::LogFinish();
//
    if (m_scrollToBottom || (m_autoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())) {
        ImGui::SetScrollHereY(1.0f);
    }
    m_scrollToBottom = false;
//
    ImGui::PopStyleVar();
    ImGui::EndChild();
    if (m_mono) ImGui::PopFont();
    ImGui::Separator();
//
//    // Command-line
//    bool reclaim_focus = false;
//    ImGuiInputTextFlags input_text_flags = ImGuiInputTextFlags_EnterReturnsTrue |
//                                           ImGuiInputTextFlags_CallbackCompletion | ImGuiInputTextFlags_CallbackHistory;
//    if (ImGui::InputText("Input", &InputBuf, input_text_flags, &TextEditCallbackStub, (void*)this)) {
//        m_items.push_back(std::make_pair(LineType::COMMAND, "# " + InputBuf));
//
//        m_historyPos = -1;
//        m_history.push_back(InputBuf);
//
//        // Process command
//        m_cmdExec(InputBuf);
//
//        // On command input, we scroll to bottom even if AutoScroll==false
//        m_scrollToBottom = true;
//        InputBuf = "";
//        reclaim_focus = true;
//    }

    // Auto-focus on window apparition
    ImGui::SetItemDefaultFocus();
//    if (reclaim_focus) ImGui::SetKeyboardFocusHere(-1);  // Auto focus previous widget

    ImGui::End();
}

PCSX::Widgets::Disassembly::disassemblerResult PCSX::Widgets::Disassembly::disassembleBuffer() {
    csh handle;
    cs_insn *insn;
    size_t count;
    FILE *disassembly;
    const uint8_t* buffer = PCSX::g_emulator->m_psxCpu->getBufferPtr();
    const size_t bufferSize = PCSX::g_emulator->m_psxCpu->getBufferSize();
    if (buffer == nullptr) {
        m_showError = true;
        m_tryDisassembly = false;
        return PCSX::Widgets::Disassembly::disassemblerResult::INVALID_BFR;
    } else if (bufferSize <= 0) {
        m_showError = true;
        m_tryDisassembly = false;
        return PCSX::Widgets::Disassembly::disassemblerResult::INVALID_BFR_SIZE;
    }

    if (m_tryDisassembly) {

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            PCSX::g_system->message("ERROR: Failed to initialize capstone disassembler!\n");
            m_tryDisassembly = false;
            return PCSX::Widgets::Disassembly::disassemblerResult::CS_INIT_FAIL;
        }
        cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
        count = cs_disasm(handle, buffer, bufferSize, 0x0, 0, &insn);
        if (m_outputFile)
            disassembly = fopen("DynarecDisassembly.txt", "a");
        if (count > 0) {
            size_t j;
            for (j = 0; j < count; j++) {
                std::string s = fmt::sprintf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                                             insn[j].op_str);

                if (m_outputFile) {
                    if (!disassembly)
                        PCSX::g_system->printf("Failed to open output file for disassembly");
                    fprintf(disassembly, s.c_str());
                }
                addLog(s);
            }

            cs_free(insn, count);
            addLog("----End of disassembly----\n");
            if (m_outputFile) {
                fprintf(disassembly, "---END OF DUMP---\n");
                fclose(disassembly);
            }
        } else {
            cs_close(&handle);
            m_tryDisassembly = false;
            return PCSX::Widgets::Disassembly::disassemblerResult::CS_DIS_FAIL;
        }
        cs_close(&handle);
        m_tryDisassembly = false;
        return PCSX::Widgets::Disassembly::disassemblerResult::SUCCESS;
    }
}