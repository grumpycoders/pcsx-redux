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

#include <functional>
#include <string>

#include "GL/gl3w.h"
#include "gui/widgets/shader-editor.h"
#include "imgui.h"

namespace PCSX {

class GUI;

namespace Widgets {

class VRAMViewer {
  public:
    void init(bool isMain = false);
    void setTitle(std::function<std::string()> title) { m_title = title; }
    void setClutDestination(VRAMViewer *destination) {
        m_clutDestination = destination;
        destination->m_hasClut = true;
    }
    void resetView();
    void destroy();

    void render(GLuint VRAMTexture, GUI *gui);

  private:
    void drawEditor(GUI *gui);
    static inline const float RATIOS[] = {0.75f, 0.5f, 0.25f, 0.125f, 0.0625f, 0.03125f};
    void drawVRAM(GLuint textureID);
    void compileShader();
    void modeChanged();
    static void imguiCBtrampoline(const ImDrawList *parentList, const ImDrawCmd *cmd) {
        VRAMViewer *that = reinterpret_cast<VRAMViewer *>(cmd->UserCallbackData);
        that->imguiCB(parentList, cmd);
    }
    void imguiCB(const ImDrawList *parentList, const ImDrawCmd *cmd);

    bool m_isMain = false;

    GLuint m_shaderProgram = 0;
    int m_attribLocationTex;
    int m_attribLocationProjMtx;
    int m_attribLocationVtxPos;
    int m_attribLocationVtxUV;
    int m_attribLocationHovered;
    int m_attribLocationMousePos;
    int m_attribLocationMouseUV;
    int m_attribLocationResolution;
    int m_attribLocationOrigin;
    int m_attribLocationMagnify;
    int m_attribLocationMagnifyRadius;
    int m_attribLocationMagnifyAmount;
    int m_attribLocationCornerTL;
    int m_attribLocationCornerBR;
    int m_attribLocationAlpha;
    int m_attribLocationGreyscale;
    int m_attribLocationMode;
    int m_attribLocationClut;
    int m_attribLocation24shift;

    bool m_hovered = false;
    bool m_magnify = false;
    float m_magnifyAmount = 5.0f;
    float m_magnifyRadius = 150.0f;
    ImVec2 m_mousePos;
    ImVec2 m_mouseUV;
    ImVec2 m_resolution;
    ImVec2 m_origin;
    ImVec2 m_cornerTL = {0.0f, 0.0f};
    ImVec2 m_cornerBR = {1024.0f, 512.0f};
    GLuint m_textureID;

    enum : int {
        VRAM_24BITS,
        VRAM_16BITS,
        VRAM_8BITS,
        VRAM_4BITS,
    } m_vramMode = VRAM_16BITS;
    bool m_alpha = false;
    bool m_greyscale = false;
    bool m_selectingClut = false;
    int m_24shift = 0;

  public:
    bool m_show = false;

  private:
    std::function<std::string()> m_title;

    bool m_hasClut = false;
    ImVec2 m_clut;
    VRAMViewer *m_clutDestination = nullptr;

    bool m_firstShown = false;

    ShaderEditor m_editor = {"vram-viewer"};
};

}  // namespace Widgets
}  // namespace PCSX
