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
#include "support/eventbus.h"

namespace PCSX {

class GUI;

namespace Widgets {

class VRAMViewer {
  public:
    VRAMViewer(bool &show);
    void setMain() { m_isMain = true; }
    void setTitle(std::function<std::string()> title) { m_title = title; }
    void setClutDestination(VRAMViewer *destination) {
        m_clutDestination = destination;
        destination->m_hasClut = true;
    }
    void resetView();
    void moveTo(ImVec2 pos);
    void focusOn(ImVec2 topLeft, ImVec2 bottomRight);
    void zoom(float factor, ImVec2 centerUV);

    void draw(GUI *gui, GLuint VRAMTexture);

  private:
    void drawEditor(GUI *gui);
    static inline const float RATIOS[] = {0.125f, 0.25f, 0.5f, 0.75f};
    void drawVRAM(GUI *gui, GLuint textureID);
    void compileShader(GUI *gui);
    void modeChanged();
    void imguiCB(const ImDrawList *parentList, const ImDrawCmd *cmd);

    bool m_isMain = false;

    GLuint m_shaderProgram = 0;

    int m_attribLocation24shift;
    int m_attribLocationAlpha;
    int m_attribLocationClut;
    int m_attribLocationCornerBR;
    int m_attribLocationCornerTL;
    int m_attribLocationPixelScale;
    int m_attribLocationGreyscale;
    int m_attribLocationHovered;
    int m_attribLocationMagnify;
    int m_attribLocationMagnifyAmount;
    int m_attribLocationMagnifyRadius;
    int m_attribLocationDrawGrid;
    int m_attribLocationPixelGridColor;
    int m_attribLocationTPageGridColor;
    int m_attribLocationMode;
    int m_attribLocationMonitorDPI;
    int m_attribLocationMonitorPosition;
    int m_attribLocationMonitorResolution;
    int m_attribLocationMousePos;
    int m_attribLocationMouseUV;
    int m_attribLocationOrigin;
    int m_attribLocationProjMtx;
    int m_attribLocationReadColor;
    int m_attribLocationReadHeatmap;
    int m_attribLocationReadHighlight;
    int m_attribLocationResolution;
    int m_attribLocationTex;
    int m_attribLocationVtxPos;
    int m_attribLocationVtxUV;
    int m_attribLocationWrittenColor;
    int m_attribLocationWrittenHeatmap;
    int m_attribLocationWrittenHighlight;

    float m_DPI = 1.0f;
    GLuint m_textureID;

    bool m_selectingClut = false;

    int m_24shift = 0;
    bool m_alpha = false;
    ImVec2 m_clut;
    ImVec2 m_cornerBR = {1024.0f, 512.0f};
    ImVec2 m_cornerTL = {0.0f, 0.0f};
    bool m_drawGrid = true;
    ImVec4 m_pixelGridColor = ImVec4{0.5f, 0.5f, 0.5f, 0.8f};
    ImVec4 m_tpageGridColor = ImVec4{0.9f, 0.9f, 0.9f, 0.8f};
    bool m_greyscale = false;
    bool m_hovered = false;
    bool m_magnify = false;
    float m_magnifyAmount = 5.0f;
    float m_magnifyRadius = 150.0f;
    enum : int {
        VRAM_4BITS,
        VRAM_8BITS,
        VRAM_16BITS,
        VRAM_24BITS,
    } m_vramMode = VRAM_16BITS;
    float m_monitorDPI;
    ImVec2 m_monitorPosition;
    ImVec2 m_monitorResolution;
    ImVec2 m_mousePos;
    ImVec2 m_mouseUV;
    ImVec2 m_origin;
    ImVec4 m_readColor = ImVec4{0.0f, 1.0f, 0.0f, 0.375f};
    ImVec2 m_resolution;
    ImVec4 m_writtenColor = ImVec4{1.0f, 0.0f, 0.0f, 0.375f};

  public:
    bool &m_show;

  private:
    std::function<std::string()> m_title;

    bool m_hasClut = false;
    VRAMViewer *m_clutDestination = nullptr;

    bool m_firstShown = false;

    ShaderEditor m_editor = {"vram-viewer"};

    EventBus::Listener m_listener;
};

}  // namespace Widgets
}  // namespace PCSX
