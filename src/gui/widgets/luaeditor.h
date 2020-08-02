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

#pragma once

#include <stdint.h>

#include <filesystem>

#include "ImGuiColorTextEdit/TextEditor.h"
#include "core/stacktrace.h"

namespace PCSX {

namespace Widgets {

class LuaEditor {
  public:
    LuaEditor(bool& show) : m_show(show) { m_text.SetLanguageDefinition(TextEditor::LanguageDefinition::Lua()); }
    bool& m_show;

    void draw(const char* title);

  private:
    TextEditor m_text;
    std::vector<std::string> m_lastErrors;
    bool m_displayError = false;
};

}  // namespace Widgets

}  // namespace PCSX
