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

namespace PCSX {

class GUI;

namespace Widgets {

class CDRomViewer : public ZoomableImage {
  public:
    CDRomViewer(bool &show);
    void draw(GUI *gui);

    ImVec2 defaultViewSize() const override;

  private:
    void drawDisc(GUI *gui);
    void compileShader(GUI *gui);
    void imguiCB(const ImDrawList *parentList, const ImDrawCmd *cmd);

    // Convert a UV inside the image into a sector LBA, honoring the current
    // mapping mode. Returns false if the UV falls outside the disc (the inner
    // hole or past the rim in polar mode). Shared by hover readout and shader
    // logic (kept in sync with the GLSL).
    bool uvToLBA(ImVec2 uv, uint32_t &lba) const;

    GLuint m_shaderProgram = 0;

    // Uniform / attribute locations
    int m_locProjMtx;
    int m_locVtxPos;
    int m_locVtxUV;
    int m_locDataHeatmap;
    int m_locAudioHeatmap;
    int m_locSeekHeatmap;
    int m_locDataColor;
    int m_locAudioColor;
    int m_locSeekColor;
    int m_locShowData;
    int m_locShowAudio;
    int m_locShowSeek;
    int m_locCurrentCycle;
    int m_locDecayHalfLife;
    int m_locPolarMode;
    int m_locInnerHole;
    int m_locDiscSectors;
    int m_locSide;

    // Channel colors: data=green, audio=amber, seek=blue
    ImVec4 m_dataColor = ImVec4{0.0f, 1.0f, 0.3f, 0.85f};
    ImVec4 m_audioColor = ImVec4{1.0f, 0.7f, 0.0f, 0.85f};
    ImVec4 m_seekColor = ImVec4{0.3f, 0.5f, 1.0f, 0.85f};

    // Channel visibility
    bool m_showData = true;
    bool m_showAudio = true;
    bool m_showSeek = true;

    // false = square raster (LBA row-major), true = polar disc (area-law radius)
    bool m_polarMode = false;

    ShaderEditor m_editor = {"cdrom-viewer"};
};

}  // namespace Widgets
}  // namespace PCSX
