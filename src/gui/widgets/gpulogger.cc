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
#include "support/imgui-helpers.h"

PCSX::Widgets::GPULogger::GPULogger(bool& show) : m_show(show), m_listener(g_system->m_eventBus) {
    m_listener.listen<Events::GUI::VRAMHover>([this](auto event) {
        if (!m_filterProbing) return;
        m_filter.x = event.x;
        m_filter.y = event.y;
    });
    m_listener.listen<Events::GUI::VRAMClick>([this](auto event) {
        if (!m_filterProbing) return;
        m_filter.x = event.x;
        m_filter.y = event.y;
        m_filterProbing = false;
    });
}

void PCSX::Widgets::GPULogger::draw(PCSX::GPULogger* logger, const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    if (ImGui::Checkbox(_("GPU logging"), &logger->m_enabled)) {
        if (logger->m_enabled) {
            logger->enable();
        } else {
            logger->disable();
        }
    }
    ImGuiHelpers::ShowHelpMarker(
        _("Logs each frame's draw calls. When enabled, all the commands sent to the GPU will be logged and displayed "
          "here. This will contain only a single frame worth of commands. The feature can be pretty demanding in CPU "
          "and memory."));
    ImGui::Checkbox(_("Breakpoint on vsync"), &logger->m_breakOnVSync);
    ImGui::SameLine();
    if (ImGui::Button(_("Resume"))) {
        g_system->resume();
    }
    ImGui::Checkbox(_("Replay frame"), &m_replay);
    ImGuiHelpers::ShowHelpMarker(
        _("When enabled, the framebuffer will be constantly redrawned using the selected commands, allowing to see the "
          "resulting output immediately. This doesn't make sense to have this enabled when: (1) the CPU is running and "
          "(2) the GPU logging isn't enabled. Selection of which commands to replay is done using the first checkbox "
          "in the logger display below. The [T] button will select all commands for replay from the top and until this "
          "command."));
    ImGui::Checkbox(_("Show origins"), &m_showOrigins);
    ImGuiHelpers::ShowHelpMarker(
        _("When enabled, the logger display will also show where did the command come from, which can be useful to "
          "debug or reverse engineer, but will also clutter the logger view."));
    bool collapseAll = false;
    bool expandAll = false;
    bool disableFromHere = false;
    bool removeHighlight = false;
    bool setHighlightRange = m_setHighlightRange;
    GPU::Logged* tempHighlight = nullptr;
    bool hasHighlight = false;
    m_setHighlightRange = false;
    if (ImGui::BeginTable("Buttons", 2, ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        if (ImGui::Button(_("Collapse all nodes"))) {
            collapseAll = true;
        }
        ImGui::TableSetColumnIndex(1);
        ImGui::Checkbox(_("Keep collapsed"), &m_collapseAll);
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        if (ImGui::Button(_("Expand all nodes"))) {
            expandAll = true;
        }
        ImGui::TableSetColumnIndex(1);
        ImGui::Checkbox(_("Keep expanded"), &m_expandAll);
        ImGui::EndTable();
    }
    ImGui::Separator();
    if (ImGui::Button(_("Remove all highlight selections"))) {
        removeHighlight = true;
    }
    ImGui::Checkbox(_("Highlight on hover"), &m_hoverHighlight);
    ImGuiHelpers::ShowHelpMarker(
        _("When enabled, hovering a command in the logger view will highlight it in the vram display. Individual "
          "commands can be selected for highlight by using the second checkbox in the logger view. The [B] and [E] "
          "buttons can be used to specify the beginning and the end of a span of commands to highlight."));
    ImGui::Checkbox(_("Filter by pixel"), &m_filterEnabled);
    ImGuiHelpers::ShowHelpMarker(_(
        "When enabled, only the commands that are related to the specified pixel will be shown. The pixel location is "
        "specified in the next input fields. The [Probe VRAM] button can be used to set the pixel location by hovering "
        "and clicking inside the VRAM viewer."));
    ImGui::InputInt2(_("Pixel location"), m_filter.raw);
    if (ImGui::Button(_("Probe VRAM"))) {
        m_filterProbing = true;
    }
    ImGuiHelpers::ShowHelpMarker(_(
        "When enabled, hovering then clicking inside the VRAM viewer will set the pixel location for the filtering."));

    std::string label;

    ImGui::Separator();
    label = fmt::format(f_("Frame {}###FrameCounterNode"), logger->m_frameCounter - m_frameCounterOrigin);
    if (ImGui::TreeNode(label.c_str())) {
        if (ImGui::Button(_("Reset frame counter"))) {
            m_frameCounterOrigin = logger->m_frameCounter;
        }
        ImGui::Text(_("%i primitives"), logger->m_list.size());
        GPU::GPUStats stats;
        for (auto& logged : logger->m_list) {
            logged.cumulateStats(&stats);
        }
        ImGui::Text(_("%i triangles"), stats.triangles);
        ImGui::Text(_("%i textured triangles"), stats.texturedTriangles);
        ImGui::Text(_("%i rectangles"), stats.rectangles);
        ImGui::Text(_("%i sprites"), stats.sprites);
        ImGui::Text(_("%i pixel writes"), stats.pixelWrites);
        ImGui::Text(_("%i pixel reads"), stats.pixelReads);
        ImGui::Text(_("%i texel reads"), stats.texelReads);

        ImGui::TreePop();
    }
    ImGui::Separator();
    ImGui::BeginChild("DrawCalls");

    GPU::Logged::Origin origin = GPU::Logged::Origin::REPLAY;
    uint32_t value = 0;
    uint32_t length = 0;
    int n = 0;

    for (auto& logged : logger->m_list) {
        if (m_filterEnabled && !logged.isInside(m_filter.x, m_filter.y)) {
            continue;
        }
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
                ImGui::TextUnformatted(_("at PC = "));
                ImGui::SameLine();
                label = fmt::format("{:08x}", logged.pc);
                if (ImGui::Button(label.c_str())) {
                    g_system->m_eventBus->signal(Events::GUI::JumpToPC{logged.pc});
                }
            }
        }
        if (disableFromHere) logged.enabled = false;
        if (removeHighlight) logged.highlight = false;
        ImGui::BeginGroup();
        label = fmt::format("##enable{}", n);
        if (!m_replay) ImGui::BeginDisabled();
        ImGui::Checkbox(label.c_str(), &logged.enabled);
        ImGui::SameLine();
        label = fmt::format("T##upto{}", n);
        if (ImGui::Button(label.c_str())) {
            for (auto& before : logger->m_list) {
                before.enabled = true;
                if (&before == &logged) break;
            }
            disableFromHere = true;
        }
        if (!m_replay) ImGui::EndDisabled();
        ImGui::SameLine();
        label = fmt::format("##highlight{}", n);
        ImGui::Checkbox(label.c_str(), &logged.highlight);
        ImGui::SameLine();
        label = fmt::format("B##upto{}", n);
        if (ImGui::Button(label.c_str())) {
            m_setHighlightRange = true;
            m_beginHighlight = n;
        }
        ImGui::SameLine();
        label = fmt::format("E##upto{}", n);
        if (ImGui::Button(label.c_str())) {
            m_setHighlightRange = true;
            m_endHighlight = n;
        }
        ImGui::SameLine();
        if (collapseAll || m_collapseAll) ImGui::SetNextItemOpen(false);
        if (expandAll || m_expandAll) ImGui::SetNextItemOpen(true);
        label = fmt::format("{}##node{}", logged.getName(), n);
        if (ImGui::TreeNode(label.c_str())) {
            logged.drawLogNode(n);
            ImGui::TreePop();
        }
        ImGui::EndGroup();
        if (m_hoverHighlight && ImGui::IsItemHovered()) {
            tempHighlight = &logged;
        }
        if (setHighlightRange) {
            logged.highlight = (m_beginHighlight <= n) && (n <= m_endHighlight);
        }
        if (logged.highlight) {
            hasHighlight = true;
        }
        n++;
    }

    ImGui::EndChild();
    ImGui::End();

    if (m_replay && !g_system->running()) {
        logger->replay(g_emulator->m_gpu.get());
    }

    logger->highlight(tempHighlight, tempHighlight && ImGui::GetIO().KeyCtrl);
}
