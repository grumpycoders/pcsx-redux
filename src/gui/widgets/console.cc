/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

#include "gui/widgets/console.h"

#include "imgui.h"
#include "imgui_stdlib.h"

void PCSX::Widgets::Console::draw(const char* title) {
    ImGui::SetNextWindowSize(ImVec2(520, 600), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    if (ImGui::BeginPopupContextItem()) {
        if (ImGui::MenuItem("Close Console")) m_show = false;
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
        ImGui::EndPopup();
    }

    // Options, Filter
    if (ImGui::Button("Options")) ImGui::OpenPopup("Options");
    ImGui::Separator();

    // Reserve enough left-over height for 1 separator + 1 input text
    const float footer_height_to_reserve = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();
    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footer_height_to_reserve), false,
                      ImGuiWindowFlags_HorizontalScrollbar);

    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 1));  // Tighten spacing
    if (copy_to_clipboard) ImGui::LogToClipboard();
    for (auto& item : m_items) {
        ImVec4 color;
        bool has_color = false;
        switch (item.first) {
            case LineType::ERRORMSG:
                color = ImVec4(1.0f, 0.4f, 0.4f, 1.0f);
                has_color = true;
                break;
            case LineType::COMMAND:
                color = ImVec4(1.0f, 0.8f, 0.6f, 1.0f);
                has_color = true;
                break;
        }
        if (has_color) ImGui::PushStyleColor(ImGuiCol_Text, color);
        ImGui::TextUnformatted(item.second.c_str());
        if (has_color) ImGui::PopStyleColor();
    }
    if (copy_to_clipboard) ImGui::LogFinish();

    if (m_scrollToBottom || (m_autoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()))
        ImGui::SetScrollHereY(1.0f);
    m_scrollToBottom = false;

    ImGui::PopStyleVar();
    ImGui::EndChild();
    ImGui::Separator();

    // Command-line
    bool reclaim_focus = false;
    ImGuiInputTextFlags input_text_flags = ImGuiInputTextFlags_EnterReturnsTrue |
                                           ImGuiInputTextFlags_CallbackCompletion | ImGuiInputTextFlags_CallbackHistory;
    if (ImGui::InputText("Input", &InputBuf, input_text_flags, &TextEditCallbackStub, (void*)this)) {
        m_items.push_back(std::make_pair(LineType::COMMAND, "# " + InputBuf));

        m_historyPos = -1;
        m_history.push_back(InputBuf);

        // Process command
        m_cmdExec(InputBuf);

        // On command input, we scroll to bottom even if AutoScroll==false
        m_scrollToBottom = true;
        InputBuf = "";
        reclaim_focus = true;
    }

    // Auto-focus on window apparition
    ImGui::SetItemDefaultFocus();
    if (reclaim_focus) ImGui::SetKeyboardFocusHere(-1);  // Auto focus previous widget

    ImGui::End();
}

int PCSX::Widgets::Console::TextEditCallback(ImGuiInputTextCallbackData* data) {
    switch (data->EventFlag) {
        case ImGuiInputTextFlags_CallbackHistory: {
            const int prev_history_pos = m_historyPos;
            if (data->EventKey == ImGuiKey_UpArrow) {
                if (m_historyPos == -1)
                    m_historyPos = m_history.size() - 1;
                else if (m_historyPos > 0)
                    m_historyPos--;
            } else if (data->EventKey == ImGuiKey_DownArrow) {
                if (m_historyPos != -1)
                    if (++m_historyPos >= m_history.size()) m_historyPos = -1;
            }

            if (prev_history_pos != m_historyPos) {
                const char* history_str = (m_historyPos >= 0) ? m_history[m_historyPos].c_str() : "";
                data->DeleteChars(0, data->BufTextLen);
                data->InsertChars(0, history_str);
            }
        }
    }
    return 0;
}
