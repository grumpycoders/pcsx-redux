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

#include <GL/gl3w.h>

#include <filesystem>
#include <fstream>
#include <istream>
#include <list>
#include <ostream>
#include <sstream>
#include <streambuf>
#include <string>
#include <vector>

#include "core/psxemulator.h"
#include "fmt/format.h"
#include "gui/gui.h"
#include "lua/luawrapper.h"
#include "support/file.h"

PCSX::Widgets::LuaEditor::LuaEditor(bool& show) : m_show(show) {
    std::ifstream in("pcsx.lua", std::ifstream::in);
    if (in) {
        std::ostringstream code;
        code << in.rdbuf();
        in.close();
        m_text.setText(code.str());
    }
}

void PCSX::Widgets::LuaEditor::draw(const char* title, PCSX::GUI* gui) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    auto& L = g_emulator->m_lua;

    ImGui::Checkbox(_("Auto reload"), &m_autoreload);
    ImGui::SameLine();
    ImGui::Checkbox(_("Auto save"), &m_autosave);
    ImVec2 size(0, -ImGui::GetTextLineHeightWithSpacing() * 5);
    ImGui::BeginChild("LuaSource", size);
    m_text.draw(gui);
    ImGui::EndChild();
    if (m_text.hasTextChanged()) {
        if (m_autoreload) {
            m_lastErrors.clear();
            auto oldNormalPrinter = L->normalPrinter;
            auto oldErrorPrinter = L->errorPrinter;
            L->normalPrinter = [](const std::string&) {};
            L->errorPrinter = [this](const std::string& msg) { m_lastErrors.push_back(msg); };
            GUI::ScopedOnlyLog scopedOnlyLog(gui);
            gui->useImguiLuaUserErrorHandler();
            try {
                L->load(m_text.getText(), "pcsx.lua", false);
                L->pcall();
                auto errors = gui->getGLerrors();
                if (errors.empty()) {
                    m_displayError = false;
                } else {
                    for (const auto& error : errors) {
                        m_lastErrors.push_back(error);
                    }
                }
            } catch (...) {
                m_displayError = true;
            }
            gui->noImguiUserErrorHandler();
            L->normalPrinter = oldNormalPrinter;
            L->errorPrinter = oldErrorPrinter;
        }

        if (m_autosave) {
            std::ofstream out("pcsx.lua", std::ofstream::out);
            out << m_text.getText();
        }
    }

    if (m_displayError) {
        for (auto& msg : m_lastErrors) {
            ImGui::TextUnformatted(msg.c_str());
        }
    }

    ImGui::End();
}
