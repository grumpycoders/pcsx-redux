/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include "imgui.h"
#include "ImGuiColorTextEdit/TextEditor.h"

namespace PCSX {
namespace Widgets {

class VRAMViewer {
  public:
    void init();
    void drawVRAM(unsigned int textureID, ImVec2 dimensions);
    void drawEditor();
    void destroy();

  private:
    void compileShader(const char *VS, const char *PS);
    static void imguiCBtrampoline(const ImDrawList *parentList, const ImDrawCmd *cmd) {
        VRAMViewer *that = reinterpret_cast<VRAMViewer *>(cmd->UserCallbackData);
        that->imguiCB(parentList, cmd);
    }
    void imguiCB(const ImDrawList *parentList, const ImDrawCmd *cmd);

    unsigned int m_vertexShader = 0;
    unsigned int m_pixelShader = 0;
    unsigned int m_shaderProgram = 0;
    int m_attribLocationTex;
    int m_attribLocationProjMtx;
    int m_attribLocationVtxPos;
    int m_attribLocationVtxUV;
    int m_attribLocationHovered;

    bool m_hovered = false;
    TextEditor m_vertexShaderEditor;
    TextEditor m_pixelShaderEditor;

    std::string m_errorMessage;
};

}
}
