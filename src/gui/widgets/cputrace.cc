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

#include <filesystem>

#include "core/cputrace.h"
#include "core/disr3000a.h"
#include "core/psxemulator.h"
#include "core/r3000a.h"
#include "core/system.h"
#include "fmt/format.h"
#include "gui/gui.h"
#include "imgui.h"

PCSX::Widgets::CpuTrace::CpuTrace(bool& show, std::vector<std::string>& favorites)
    : m_show(show),
      m_exportTextDialog(l_("Export CPU trace as text"), favorites),
      m_saveDialog(l_("Save CPU trace"), favorites),
      m_loadDialog(l_("Load CPU trace"), favorites) {}

void PCSX::Widgets::CpuTrace::draw(GUI* gui, const char* title) {
    if (ImGui::Begin(title, &m_show)) {
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
        if (ImGui::Button(_("Clear"))) {
            trace.clear();
            m_live.followTail = false;
        }
        ImGui::SameLine();
        if (ImGui::Button(_("Export text..."))) m_exportTextDialog.openDialog();
        ImGui::SameLine();
        if (ImGui::Button(_("Save..."))) m_saveDialog.openDialog();
        ImGui::SameLine();
        if (ImGui::Button(_("Load..."))) m_loadDialog.openDialog();

        int limitMiB = static_cast<int>(trace.limit() * sizeof(TraceEntry) / (1024 * 1024));
        ImGui::SetNextItemWidth(120.0f);
        if (ImGui::InputInt(_("Limit (MiB, 0 = none)"), &limitMiB, 0)) {
            if (limitMiB < 0) limitMiB = 0;
            trace.setLimit(static_cast<size_t>(limitMiB) * 1024 * 1024 / sizeof(TraceEntry));
        }
        if (trace.full()) {
            ImGui::SameLine();
            ImGui::TextUnformatted(_("Limit reached, capture stopped."));
        }
        if (!m_error.empty()) ImGui::TextUnformatted(m_error.c_str());

        drawView(gui, trace, m_live, true);
    }
    ImGui::End();

    if (m_exportTextDialog.draw()) {
        auto& selected = m_exportTextDialog.selected();
        if (!selected.empty()) {
            IO<File> file = new PosixFile(selected[0], FileOps::TRUNCATE);
            if (file->failed()) {
                m_error = _("Unable to open the file for writing.");
            } else {
                g_emulator->m_cpuTrace->exportText(file);
                m_error.clear();
            }
        }
    }
    if (m_saveDialog.draw()) {
        auto& selected = m_saveDialog.selected();
        if (!selected.empty()) {
            IO<File> file = new PosixFile(selected[0], FileOps::TRUNCATE);
            if (file->failed()) {
                m_error = _("Unable to open the file for writing.");
            } else {
                g_emulator->m_cpuTrace->save(file);
                m_error.clear();
            }
        }
    }
    if (m_loadDialog.draw()) {
        auto& selected = m_loadDialog.selected();
        if (!selected.empty()) {
            IO<File> file = new PosixFile(selected[0]);
            auto& loaded = m_loaded.emplace_back();
            if (file->failed() || !loaded.trace.load(file)) {
                m_loaded.pop_back();
                m_error = _("Not a CPU trace file.");
            } else {
                loaded.name = std::filesystem::path(selected[0]).filename().string();
                m_error.clear();
            }
        }
    }

    for (auto it = m_loaded.begin(); it != m_loaded.end();) {
        auto& loaded = *it;
        std::string windowTitle = fmt::format("{}: {}###cputrace{}", title, loaded.name, static_cast<void*>(&loaded));
        if (ImGui::Begin(windowTitle.c_str(), &loaded.show)) {
            drawView(gui, loaded.trace, loaded.view, false);
        }
        ImGui::End();
        if (!loaded.show) {
            it = m_loaded.erase(it);
        } else {
            ++it;
        }
    }
}

void PCSX::Widgets::CpuTrace::drawView(GUI* gui, const PCSX::CpuTrace& trace, View& view, bool live) {
    const size_t count = trace.size();
    const double bytes = static_cast<double>(count) * sizeof(TraceEntry);
    ImGui::TextUnformatted(fmt::format(f_("{} instructions ({:.2f} MiB)"), count, bytes / (1024.0 * 1024.0)).c_str());

    if (live) {
        ImGui::Checkbox(_("Follow"), &view.followTail);
        ImGui::SameLine();
    }
    ImGui::Checkbox(_("Sync"), &view.sync);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.0f);
    if (ImGui::InputText(_("Go to #"), view.jumpString, sizeof(view.jumpString),
                         ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsDecimal)) {
        char* end = nullptr;
        long long idx = strtoll(view.jumpString, &end, 10);
        if (end != view.jumpString && idx >= 0 && static_cast<size_t>(idx) < count) {
            view.scrollTo = idx;
            view.followTail = false;
        }
    }

    ImGui::Separator();

    gui->useMonoFont();
    ImGui::BeginChild("##traceScroll", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);

    if (count == 0) {
        ImGui::TextUnformatted(live ? _("No trace captured. Enable Capture and run.") : _("Empty trace."));
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

        const float lineHeight = ImGui::GetTextLineHeightWithSpacing();
        if (view.scrollTo >= 0) {
            ImGui::SetScrollY(static_cast<float>(view.scrollTo) * lineHeight);
            if (view.sync) m_syncRow = view.scrollTo;
            view.lastTop = view.scrollTo;
            view.scrollTo = -1;
        } else if (view.followTail) {
            ImGui::SetScrollY(ImGui::GetScrollMaxY());
        } else if (view.sync) {
            // A synced view that moved since last frame leads; the others follow it.
            int64_t top = static_cast<int64_t>(ImGui::GetScrollY() / lineHeight);
            if (top != view.lastTop) {
                m_syncRow = top;
            } else if (m_syncRow >= 0 && m_syncRow != top) {
                ImGui::SetScrollY(static_cast<float>(m_syncRow) * lineHeight);
                top = m_syncRow;
            }
            view.lastTop = top;
        }
    }

    ImGui::EndChild();
}
