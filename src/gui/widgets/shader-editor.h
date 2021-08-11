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

namespace PCSX {

class GUI;

namespace Widgets {

class ShaderEditor {
  public:
    std::optional<GLuint> [[nodiscard]] compile(std::string_view VS, std::string_view PS,
                                                const std::vector<std::string_view>& mandatoryAttributes = {});

    bool m_show = false;

    void setText(std::string_view VS, std::string_view PS) {
        m_vertexShaderEditor.SetText(VS.data());
        m_pixelShaderEditor.SetText(PS.data());
    }

    bool draw(std::string_view title, GUI* gui);

    std::string getVertexText() { return m_vertexShaderEditor.GetText(); }
    std::string getPixelText() { return m_pixelShaderEditor.GetText(); }

  private:
    TextEditor m_vertexShaderEditor;
    TextEditor m_pixelShaderEditor;
    std::string m_errorMessage;
};

}  // namespace Widgets
}  // namespace PCSX
