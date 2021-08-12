/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "GL/gl3w.h"
#include "ImGuiColorTextEdit/TextEditor.h"
#include "lua/luawrapper.h"

namespace PCSX {

class GUI;

namespace Widgets {

class ShaderEditor {
  public:
    ShaderEditor(const std::string& base) : m_baseFilename(base), m_index(++s_index) {}
    [[nodiscard]] std::optional<GLuint> compile(const std::vector<std::string_view>& mandatoryAttributes = {});

    bool m_show = false;

    void setText(std::string_view VS, std::string_view PS, std::string_view L) {
        m_vertexShaderEditor.SetText(VS.data());
        m_pixelShaderEditor.SetText(PS.data());
        m_luaEditor.SetText(L.data());
    }

    bool draw(std::string_view title, GUI* gui);

  private:
    std::string getVertexText() { return m_vertexShaderEditor.GetText(); }
    std::string getPixelText() { return m_pixelShaderEditor.GetText(); }
    std::string getLuaText() { return m_luaEditor.GetText(); }

    const std::string m_baseFilename;

    TextEditor m_vertexShaderEditor;
    TextEditor m_pixelShaderEditor;
    TextEditor m_luaEditor;
    std::string m_errorMessage;
    std::vector<std::string> m_lastLuaErrors;
    bool m_displayError = false;
    bool m_autoreload = true;
    bool m_autosave = true;

    static lua_Number s_index;
    const lua_Number m_index;
};

}  // namespace Widgets
}  // namespace PCSX
