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

#include "gui/widgets/source.h"

#include <filesystem>
#include <fstream>
#include <list>
#include <string>
#include <vector>

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "fmt/format.h"

void PCSX::Widgets::Source::draw(const char* title, uint32_t pc) {
    auto switchSource = [this](std::filesystem::path path, int line) mutable -> bool {
        if (!std::filesystem::exists(path)) {
            if (path.is_absolute()) path = path.relative_path();
            while (!std::filesystem::exists(path)) {
                std::list<PCSX::u8string> elements;
                for (auto& p : path) elements.emplace_back(p.filename().u8string());
                if (elements.size() <= 1) break;
                elements.pop_front();
                path = elements.front();
                elements.pop_front();
                for (auto& p : elements) path /= p;
            }
        }

        if (m_oldPath != path) {
            m_oldPath = path;
            if (!std::filesystem::exists(path)) return false;
            std::ifstream src(path.c_str());
            if (!src.is_open()) return false;

            std::string str((std::istreambuf_iterator<char>(src)), std::istreambuf_iterator<char>());
            m_text.SetText(str);
        }
        TextEditor::Coordinates c;
        c.mLine = line - 1;
        c.mColumn = 1;
        if (c.mLine < 0) c.mLine = 0;
        m_text.SetCursorPosition(c);
        return true;
    };

    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    if (pc != m_oldPC) {
        m_currentStacktrace = Stacktrace::computeStacktrace(g_emulator->m_psxMem.get(), &g_emulator->m_psxCpu->m_psxRegs);
        bool found = false;
        m_oldPC = pc;
        for (auto& e : g_emulator->m_psxMem->getElves()) {
            auto [entry, stack] = e.findByAddress(pc);
            if (!entry.valid()) continue;
            if (switchSource(entry.file->path, entry.line)) {
                found = true;
                break;
            }
        }

        if (!found) m_text.SetText("No source found for address");
    }

    m_text.Render(_("Source"));

    ImGui::End();

    if (ImGui::Begin(_("Callstack"))) {
        int l = 0;
        for (auto& e : m_currentStacktrace) {
            std::string label;
            label = fmt::format("{:2}: @{:08x}/{:08x} {}:{}", l++, e.pc, e.sp, e.path.string(), e.line);
            if (ImGui::Button(label.c_str()) && !switchSource(e.path, e.line)) {
                m_text.SetText("Source not found");
            }
        }
    }
    ImGui::End();
}
