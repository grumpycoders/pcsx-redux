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

#include "gui/widgets/log.h"

#include "core/logger.h"
#include "core/system.h"
#include "gui/gui.h"
#include "imgui.h"
#include "imgui_internal.h"
#include "magic_enum/include/magic_enum.hpp"

PCSX::Widgets::Log::Log(bool& show) : m_show(show) {
    for (auto logClass : magic_enum::enum_values<LogClass>()) {
        addClass(magic_enum::enum_integer(logClass), std::string{magic_enum::enum_name(logClass)});
    }
}

void PCSX::Widgets::Log::draw(GUI* gui, const char* title) {
    if (!ImGui::Begin(title, &m_show, ImGuiWindowFlags_MenuBar)) {
        ImGui::End();
        return;
    }
    if (ImGui::BeginMenuBar()) {
        bool changed = false;
        if (ImGui::BeginMenu(_("Enabled"))) {
            ImGui::PushItemFlag(ImGuiItemFlags_SelectableDontClosePopup, true);
            for (auto logClass : magic_enum::enum_values<LogClass>()) {
                auto c = m_classes.find(magic_enum::enum_integer(logClass));
                std::string name = std::string{magic_enum::enum_name(logClass)};
                changed |= ImGui::MenuItem(name.c_str(), nullptr, &c->enabled);
            }
            ImGui::PopItemFlag();
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu(_("Displayed"))) {
            ImGui::PushItemFlag(ImGuiItemFlags_SelectableDontClosePopup, true);
            for (auto logClass : magic_enum::enum_values<LogClass>()) {
                auto c = m_classes.find(magic_enum::enum_integer(logClass));
                std::string name = std::string{magic_enum::enum_name(logClass)};
                changed |= ImGui::MenuItem(name.c_str(), nullptr, &c->displayed);
            }
            ImGui::PopItemFlag();
            ImGui::EndMenu();
        }
        if (changed) rebuildActive();
        ImGui::EndMenuBar();
    }

    ImGui::Checkbox(_("Follow"), &m_follow);
    ImGui::SameLine();
    ImGui::Checkbox(_("Mono"), &m_mono);
    ImGui::SameLine();
    if (ImGui::Button(_("Clear"))) clear();
    ImGui::SameLine();
    bool copy = ImGui::Button(_("Copy"));
    ImGui::Separator();
    if (m_mono) gui->useMonoFont();
    ImGui::BeginChild("scrolling", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
    if (copy) ImGui::LogToClipboard();

    ImGuiListClipper clipper;
    clipper.Begin(m_activeLogs.size());

    while (clipper.Step()) {
        for (auto i = m_activeLogs.find(clipper.DisplayStart);
             i != m_activeLogs.end() && i->getLow() < clipper.DisplayEnd; i++) {
            auto& s = i->entry;
            ImGui::TextUnformatted(s.c_str(), s.c_str() + s.length());
        }
    }

    if (m_scrollToBottom) ImGui::SetScrollHereY(1.0f);
    m_scrollToBottom = m_follow;
    ImGui::EndChild();
    if (m_mono) ImGui::PopFont();
    ImGui::End();
}

void PCSX::Widgets::Log::rebuildActive() {
    m_activeLogs.clear();

    for (auto& e : m_allLogs) {
        ClassElement* c = nullptr;
        for (auto& cl : m_classes) {
            if (cl.list.contains(&e)) {
                c = &cl;
                break;
            }
        }
        if (c && c->enabled && c->displayed) m_activeLogs.insert(m_activeLogs.size(), &e);
    }
}
