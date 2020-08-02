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

#include "gui/widgets/luaeditor.h"

#include <filesystem>
#include <fstream>
#include <list>
#include <string>
#include <vector>

#include "core/psxemulator.h"
#include "fmt/format.h"
#include "lua/luawrapper.h"

void PCSX::Widgets::LuaEditor::draw(const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    auto& L = g_emulator->m_lua;

    m_text.Render(_("Lua Source"), ImVec2(0, -ImGui::GetTextLineHeightWithSpacing() * 5));
    if (m_text.IsTextChanged()) {
        m_lastErrors.clear();
        auto oldNormalPrinter = L->normalPrinter;
        auto oldErrorPrinter = L->errorPrinter;
        L->normalPrinter = [](const std::string&) {};
        L->errorPrinter = [this](const std::string& msg) { m_lastErrors.push_back(msg); };
        try {
            L->load(m_text.GetText(), "pcsx.lua", false);
            L->pcall();
            m_displayError = false;
        } catch (...) {
            m_displayError = true;
        }
        L->normalPrinter = oldNormalPrinter;
        L->errorPrinter = oldErrorPrinter;
    }

    if (m_displayError) {
        for (auto& msg : m_lastErrors) {
            ImGui::TextUnformatted(msg.c_str());
        }
    }

    ImGui::End();
}
