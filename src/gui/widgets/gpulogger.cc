/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include "gui/widgets/gpulogger.h"

#include "core/gpulogger.h"
#include "core/psxemulator.h"
#include "fmt/format.h"

void PCSX::Widgets::GPULogger::draw(PCSX::GPULogger* logger, const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    if (ImGui::Checkbox(_("GPU logging"), &logger->m_enabled)) {
        if (logger->m_enabled) {
            logger->m_clearScheduled = true;
        }
    }
    ImGui::Checkbox(_("Breakpoint on vsync"), &logger->m_breakOnVSync);
    ImGui::Checkbox(_("Replay frame"), &m_replay);
    bool collapseAll = false;
    bool expandAll = false;
    bool disableFromHere = false;
    if (ImGui::Button(_("Collapse all nodes"))) {
        collapseAll = true;
    }
    ImGui::SameLine();
    if (ImGui::Button(_("Expand all nodes"))) {
        expandAll = true;
    }

    int n = 0;
    ImGui::BeginChild("DrawCalls");

    std::string label;
    for (auto& logged : logger->m_list) {
        if (disableFromHere) logged.enabled = false;
        label = fmt::format("##highlight{}", n);
        ImGui::Checkbox(label.c_str(), &logged.highlight);
        ImGui::SameLine();
        label = fmt::format("##enable{}", n);
        ImGui::Checkbox(label.c_str(), &logged.enabled);
        ImGui::SameLine();
        label = fmt::format(" ##upto{}", n);
        if (ImGui::Button(label.c_str())) {
            for (auto& before : logger->m_list) {
                before.enabled = true;
                if (&before == &logged) break;
            }
            disableFromHere = true;
        }
        ImGui::SameLine();
        if (collapseAll) ImGui::SetNextItemOpen(false);
        if (expandAll) ImGui::SetNextItemOpen(true);
        label = fmt::format("{}##node{}", logged.getName(), n);
        if (ImGui::TreeNode(label.c_str())) {
            ImGui::TreePop();
        }
        n++;
    }

    ImGui::EndChild();
    ImGui::End();

    if (m_replay && !g_system->running()) {
        logger->replay(g_emulator->m_gpu.get());
    }
}
