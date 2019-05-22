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

#include "core/system.h"
#include "gui/widgets/log.h"

void PCSX::Widgets::Log::clear() {
    m_buffer.clear();
    m_lineOffsets.clear();
}

void PCSX::Widgets::Log::addLog(const char* fmt, va_list args) {
    int old_size = m_buffer.size();
    m_buffer.appendfv(fmt, args);
    for (int new_size = m_buffer.size(); old_size < new_size; old_size++)
        if (m_buffer[old_size] == '\n') m_lineOffsets.push_back(old_size);
    m_scrollToBottom = m_follow;
}

void PCSX::Widgets::Log::draw(const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }
    ImGui::Checkbox(_("Follow"), &m_follow);
    ImGui::SameLine();
    if (ImGui::Button(_("Clear"))) clear();
    ImGui::SameLine();
    bool copy = ImGui::Button(_("Copy"));
    ImGui::SameLine();
    m_filter.Draw(_("Filter"), -100.0f);
    ImGui::Separator();
    ImGui::BeginChild("scrolling", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
    if (copy) ImGui::LogToClipboard();

    if (m_filter.IsActive()) {
        const char* buf_begin = m_buffer.begin();
        const char* line = buf_begin;
        for (int line_no = 0; line != nullptr; line_no++) {
            const char* line_end = (line_no < m_lineOffsets.Size) ? buf_begin + m_lineOffsets[line_no] : NULL;
            if (m_filter.PassFilter(line, line_end)) ImGui::TextUnformatted(line, line_end);
            line = line_end && line_end[1] ? line_end + 1 : nullptr;
        }
    } else {
        ImGui::TextUnformatted(m_buffer.begin());
    }

    if (m_scrollToBottom) ImGui::SetScrollHereY(1.0f);
    m_scrollToBottom = false;
    ImGui::EndChild();
    ImGui::End();
}
