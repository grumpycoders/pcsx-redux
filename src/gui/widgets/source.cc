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

#include "core/psxmem.h"

void PCSX::Widgets::Source::draw(const char* title, uint32_t pc) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    if (pc != m_oldPC) {
        bool found = false;
        m_oldPC = pc;
        for (auto& e : g_emulator.m_psxMem->getElves()) {
            auto [entry, stack] = e.findByAddress(pc);
            if (!entry.valid()) continue;
            std::filesystem::path path = entry.file->path;
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
                if (!std::filesystem::exists(path)) continue;
                std::ifstream src(path.u8string());
                if (!src.is_open()) continue;

                std::string str((std::istreambuf_iterator<char>(src)), std::istreambuf_iterator<char>());
                m_text.SetText(str);
            }
            found = true;
            TextEditor::Coordinates c;
            c.mLine = entry.line - 1; 
            c.mColumn = entry.column;
            m_text.SetCursorPosition(c);
            break;
        }

        if (!found) {
            m_text.SetText("No source found for address");
        }
    }

    m_text.Render(_("Source"));

    ImGui::End();
}
