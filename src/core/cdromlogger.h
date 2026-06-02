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
class CDRomViewer;
}

// Per-sector access logger for the CD-ROM, mirroring RAMLogger's cycle-timestamp
// design. One pixel per sector, laid out row-major into a 640x640 grid.
//
// 640x640 = 409600 sectors = 91 minutes of audio. The theoretical MSF maximum
// (99:57:74 = 449849 sectors) does not fit, but that disc cannot physically
// exist: Red Book caps at 74 minutes, 80-minute discs are common, and even
// aggressive 90-minute overburn (405000 sectors) lands under the 91-minute
// ceiling. So the grid covers every physically real disc without wasting a
// texture on the impossible tail. Anything past c_maxSectors is dropped.
class CDRomLogger {
  public:
    enum class AccessType { Data, Audio, Seek };

    static constexpr int c_side = 640;
    static constexpr size_t c_maxSectors = static_cast<size_t>(c_side) * c_side;  // 409600

    // Record one sector access. lba is the raw MSF->LBA (0-based at 00:00:00).
    void recordAccess(uint32_t lba, AccessType type, uint32_t cycle);

    void enable();
    void disable();
    bool isEnabled() const { return m_enabled; }

    void uploadHeatmaps();

    // Total sector count of the mounted disc (lead-out LBA), for the backdrop
    // that shades the valid disc extent. 0 = unknown / no disc.
    void setDiscSectors(uint32_t n) { m_discSectors = n; }
    uint32_t getDiscSectors() const { return m_discSectors; }

    void bindDataHeatmap() { m_dataHeatmapTex.bind(); }
    void bindAudioHeatmap() { m_audioHeatmapTex.bind(); }
    void bindSeekHeatmap() { m_seekHeatmapTex.bind(); }
    GLuint getDataHeatmapID() { return m_dataHeatmapTex.handle(); }

    // Configurable decay half-life in cycles (how many cycles until intensity halves).
    // CD activity is sparse (75 sectors/s max), so the default memory is long.
    float m_decayHalfLife = 169344000.0f;  // ~5 seconds at 33.8688 MHz

  private:
    bool m_enabled = false;
    bool m_hasResources = false;
    uint32_t m_discSectors = 0;

    // Per-sector cycle timestamp arrays (low 32 bits of the CPU cycle counter).
    uint32_t m_dataTimestamps[c_maxSectors] = {};
    uint32_t m_audioTimestamps[c_maxSectors] = {};
    uint32_t m_seekTimestamps[c_maxSectors] = {};

    // Heatmap textures (GL_R32UI, 640 x 640).
    OpenGL::Texture m_dataHeatmapTex, m_audioHeatmapTex, m_seekHeatmapTex;

    friend class Widgets::CDRomViewer;
};

}  // namespace PCSX
