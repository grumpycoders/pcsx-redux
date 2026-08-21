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

#include <stdint.h>
#include <string.h>

#include "support/opengl.h"

namespace PCSX {

namespace Widgets {
class RAMViewer;
}

class RAMLogger {
  public:
    enum class AccessType { Read, Write, Execute };

    static constexpr int c_width = 2048;
    static constexpr int c_maxHeight = 4096;                     // 8MB / 2048
    static constexpr size_t c_maxBytes = c_width * c_maxHeight;  // 8MB

    void recordAccess(uint32_t physAddr, unsigned width, AccessType type, uint32_t cycle);

    void enable();
    void disable();
    bool isEnabled() const { return m_enabled; }

    void uploadRAM();
    void uploadHeatmaps();

    void bindReadHeatmap() { m_readHeatmapTex.bind(); }
    void bindWriteHeatmap() { m_writeHeatmapTex.bind(); }
    void bindExecHeatmap() { m_execHeatmapTex.bind(); }
    void bindRAMTexture() { m_ramTexture.bind(); }
    GLuint getRAMTextureID() { return m_ramTexture.handle(); }

    // Configurable decay half-life in cycles (how many cycles until intensity halves)
    float m_decayHalfLife = 33868800.0f;  // ~1 second at 33.8MHz

  private:
    bool m_enabled = false;
    bool m_hasResources = false;

    // Per-byte cycle timestamp arrays (low 32 bits of cycle counter)
    uint32_t m_readTimestamps[c_maxBytes] = {};
    uint32_t m_writeTimestamps[c_maxBytes] = {};
    uint32_t m_execTimestamps[c_maxBytes] = {};

    // Heatmap textures (GL_R32UI, 2048 x maxHeight)
    OpenGL::Texture m_readHeatmapTex, m_writeHeatmapTex, m_execHeatmapTex;

    // Raw RAM texture (GL_R8, 2048 x maxHeight)
    OpenGL::Texture m_ramTexture;

    friend class Widgets::RAMViewer;
};

}  // namespace PCSX
