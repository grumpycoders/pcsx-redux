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
#include "core/system.h"
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
    ImGui::SameLine();
    if (ImGui::Button(_("Resume"))) {
        g_system->resume();
    }
    ImGui::Checkbox(_("Replay frame"), &m_replay);
    ImGui::Checkbox(_("Show origins"), &m_showOrigins);
    bool collapseAll = false;
    bool expandAll = false;
    bool disableFromHere = false;
    bool removeHighlight = false;
    if (ImGui::Button(_("Collapse all nodes"))) {
        collapseAll = true;
    }
    ImGui::SameLine();
    ImGui::Checkbox(_("Keep collapsed"), &m_collapseAll);
    if (ImGui::Button(_("Expand all nodes"))) {
        expandAll = true;
    }
    ImGui::SameLine();
    ImGui::Checkbox(_("Keep expanded"), &m_expandAll);
    if (ImGui::Button(_("Remove all highlights"))) {
        removeHighlight = true;
    }

    ImGui::Separator();
    ImGui::BeginChild("DrawCalls");

    GPU::Logged::Origin origin = GPU::Logged::Origin::REPLAY;
    uint32_t value = 0;
    uint32_t length = 0;
    int n = 0;

    std::string label;
    for (auto& logged : logger->m_list) {
        if (m_showOrigins) {
            if ((logged.origin != GPU::Logged::Origin::REPLAY) &&
                ((origin != logged.origin) || (value != logged.value) || (length != logged.length))) {
                ImGui::Separator();
                std::string label;
                origin = logged.origin;
                value = logged.value;
                length = logged.length;
                switch (origin) {
                    case GPU::Logged::Origin::DATAWRITE:
                        ImGui::Text(_("Data port write: %08x"), value);
                        break;
                    case GPU::Logged::Origin::CTRLWRITE:
                        ImGui::Text(_("Control port write: %08x"), value);
                        break;
                    case GPU::Logged::Origin::DIRECT_DMA:
                        ImGui::TextUnformatted(_("Direct DMA from"));
                        ImGui::SameLine();
                        label = fmt::format("{:08x}", value | 0x80000000);
                        if (ImGui::Button(label.c_str())) {
                            g_system->m_eventBus->signal(Events::GUI::JumpToMemory{value | 0x80000000, length * 4});
                        }
                        break;
                    case GPU::Logged::Origin::CHAIN_DMA:
                        ImGui::TextUnformatted(_("Chain DMA from"));
                        ImGui::SameLine();
                        label = fmt::format("{:08x}", value | 0x80000000);
                        if (ImGui::Button(label.c_str())) {
                            g_system->m_eventBus->signal(Events::GUI::JumpToMemory{value | 0x80000000, length * 4 + 4});
                        }
                        break;
                }
                ImGui::SameLine();
                ImGui::TextUnformatted(_("from"));
                ImGui::SameLine();
                label = fmt::format("{:08x}", logged.pc);
                if (ImGui::Button(label.c_str())) {
                    g_system->m_eventBus->signal(Events::GUI::JumpToPC{logged.pc});
                }
            }
        }
        if (disableFromHere) logged.enabled = false;
        if (removeHighlight) logged.highlight = false;
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
        if (collapseAll || m_collapseAll) ImGui::SetNextItemOpen(false);
        if (expandAll || m_expandAll) ImGui::SetNextItemOpen(true);
        label = fmt::format("{}##node{}", logged.getName(), n);
        if (ImGui::TreeNode(label.c_str())) {
            logged.drawLogNode();
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
