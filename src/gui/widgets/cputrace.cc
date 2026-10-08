/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include "gui/widgets/cputrace.h"

#include <stdlib.h>

#include "core/cputrace.h"
#include "core/disr3000a.h"
#include "core/psxemulator.h"
#include "core/r3000a.h"
#include "core/system.h"
#include "fmt/format.h"
#include "gui/gui.h"
#include "imgui.h"

void PCSX::Widgets::CpuTrace::draw(GUI* gui, const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    auto& debugSettings = g_emulator->settings.get<Emulator::SettingDebugSettings>();
    auto& trace = *g_emulator->m_cpuTrace;

    // Capture controls. The Trace debug setting is the single enable - the
    // interpreter only writes records while it is on. SkipISR keeps the existing
    // semantics: instructions executed inside an interrupt service routine are
    // not captured.
    ImGui::Checkbox(_("Capture"), &debugSettings.get<Emulator::DebugSettings::Trace>().value);
    ImGui::SameLine();
    ImGui::Checkbox(_("Skip ISR"), &debugSettings.get<Emulator::DebugSettings::SkipISR>().value);
    ImGui::SameLine();
    ImGui::Checkbox(_("Follow"), &m_followTail);
    ImGui::SameLine();
    if (ImGui::Button(_("Clear"))) {
        trace.clear();
        m_followTail = false;
    }

    const size_t count = trace.size();
    const double bytes = static_cast<double>(count) * sizeof(TraceEntry);
    ImGui::TextUnformatted(
        fmt::format(f_("{} instructions captured ({:.2f} MiB)"), count, bytes / (1024.0 * 1024.0)).c_str());

    // Jump-to-index box.
    ImGui::SetNextItemWidth(120.0f);
    if (ImGui::InputText(_("Go to #"), m_jumpString, sizeof(m_jumpString),
                         ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsDecimal)) {
        char* end = nullptr;
        long idx = strtol(m_jumpString, &end, 10);
        if (end != m_jumpString && idx >= 0 && static_cast<size_t>(idx) < count) {
            m_scrollTo = idx;
            m_followTail = false;
        }
    }

    ImGui::Separator();

    gui->useMonoFont();
    ImGui::BeginChild("##traceScroll", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);

    if (count == 0) {
        ImGui::TextUnformatted(_("No trace captured. Enable Capture and run."));
    } else {
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(count));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++) {
                const TraceEntry& e = trace[static_cast<size_t>(row)];
                PlaybackValueSource source(e);
                std::string line = Disasm::asString(e.code, 0, e.pc, nullptr, true, &source);
                ImGui::TextUnformatted(fmt::format("{:8}: {}", row, line).c_str());
            }
        }

        // Deferred scroll target (jump box). Map the row to a pixel offset.
        if (m_scrollTo >= 0) {
            ImGui::SetScrollY(static_cast<float>(m_scrollTo) * ImGui::GetTextLineHeightWithSpacing());
            m_scrollTo = -1;
        } else if (m_followTail) {
            ImGui::SetScrollY(ImGui::GetScrollMaxY());
        }
    }

    ImGui::EndChild();
    ImGui::End();
}
