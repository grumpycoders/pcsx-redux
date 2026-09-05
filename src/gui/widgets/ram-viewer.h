/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include <string>

#include "GL/gl3w.h"
#include "gui/widgets/shader-editor.h"
#include "gui/widgets/zoomable-image.h"
#include "imgui.h"
#include "support/eventbus.h"

namespace PCSX {

class GUI;

namespace Widgets {

class RAMViewer : public ZoomableImage {
  public:
    RAMViewer(bool &show);
    void draw(GUI *gui);
    void focusOn(uint32_t address, uint32_t size);

    ImVec2 defaultViewSize() const override;

  private:
    void drawRAM(GUI *gui);
    void compileShader(GUI *gui);
    void imguiCB(const ImDrawList *parentList, const ImDrawCmd *cmd);

    GLuint m_shaderProgram = 0;

    // Uniform locations
    int m_locProjMtx;
    int m_locVtxPos;
    int m_locVtxUV;
    int m_locRAMTexture;
    int m_locReadHeatmap;
    int m_locWriteHeatmap;
    int m_locExecHeatmap;
    int m_locReadColor;
    int m_locWriteColor;
    int m_locExecColor;
    int m_locCornerTL;
    int m_locCornerBR;
    int m_locResolution;
    int m_locOrigin;
    int m_locMousePos;
    int m_locMouseUV;
    int m_locHovered;
    int m_locRAMHeight;
    int m_locCurrentCycle;
    int m_locDecayHalfLife;
    int m_locShowRead;
    int m_locShowWrite;
    int m_locShowExec;
    int m_locPixelScale;
    int m_locDrawGrid;
    int m_locGridColor;
    int m_locFontAtlas;
    int m_locGlyphUVs;
    int m_locGlyphAspect;

    // Cached hex-glyph atlas state, populated during drawRAM() (which runs
    // before the ImGui render pass), then consumed inside imguiCB() during
    // the actual draw. Pulling glyphs out of ImFontBaked from inside the
    // render callback could grow the atlas after the backend has already
    // staged its texture upload for the frame, leaving us sampling with
    // stale UVs; pre-fetching avoids that race.
    float m_glyphUVs[16 * 4] = {0};
    float m_glyphAspect = 0.5f;
    GLuint m_fontTexID = 0;
    int m_locShowHex;
    int m_locShowGreyscale;

    // Hex display
    bool m_showHex = true;

    // Greyscale base
    bool m_showGreyscale = true;

    // Channel colors
    ImVec4 m_readColor = ImVec4{0.0f, 1.0f, 0.0f, 0.75f};
    ImVec4 m_writeColor = ImVec4{1.0f, 0.0f, 0.0f, 0.75f};
    ImVec4 m_execColor = ImVec4{0.3f, 0.5f, 1.0f, 0.75f};

    // Channel visibility
    bool m_showRead = true;
    bool m_showWrite = true;
    bool m_showExec = true;

    // Grid
    bool m_drawGrid = true;
    ImVec4 m_gridColor = ImVec4{0.5f, 0.5f, 0.5f, 0.8f};

    ShaderEditor m_editor = {"ram-viewer"};

    EventBus::Listener m_listener;
};

}  // namespace Widgets
}  // namespace PCSX
