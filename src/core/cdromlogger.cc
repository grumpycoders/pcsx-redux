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

#include "core/cdromlogger.h"

void PCSX::CDRomLogger::recordAccess(uint32_t lba, AccessType type, uint32_t cycle) {
    if (!m_enabled) return;
    if (lba >= c_maxSectors) return;

    uint32_t* timestamps = (type == AccessType::Data)    ? m_dataTimestamps
                           : (type == AccessType::Audio) ? m_audioTimestamps
                                                         : m_seekTimestamps;
    timestamps[lba] = cycle;
}

void PCSX::CDRomLogger::enable() {
    if (m_hasResources) {
        m_enabled = true;
        return;
    }

    auto setupTex = [](OpenGL::Texture& tex) {
        tex.bind();
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    };

    // Create heatmap textures (GL_R32UI - unsigned integer)
    m_dataHeatmapTex.create(c_side, c_side, GL_R32UI);
    m_audioHeatmapTex.create(c_side, c_side, GL_R32UI);
    m_seekHeatmapTex.create(c_side, c_side, GL_R32UI);
    if (!m_dataHeatmapTex.exists() || !m_audioHeatmapTex.exists() || !m_seekHeatmapTex.exists()) return;
    setupTex(m_dataHeatmapTex);
    setupTex(m_audioHeatmapTex);
    setupTex(m_seekHeatmapTex);

    // Clear timestamp arrays
    memset(m_dataTimestamps, 0, sizeof(m_dataTimestamps));
    memset(m_audioTimestamps, 0, sizeof(m_audioTimestamps));
    memset(m_seekTimestamps, 0, sizeof(m_seekTimestamps));

    m_hasResources = true;
    m_enabled = true;
}

void PCSX::CDRomLogger::disable() { m_enabled = false; }

void PCSX::CDRomLogger::uploadHeatmaps() {
    if (!m_hasResources) return;

    glPixelStorei(GL_UNPACK_ALIGNMENT, 4);

    m_dataHeatmapTex.bind();
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, c_side, c_side, GL_RED_INTEGER, GL_UNSIGNED_INT, m_dataTimestamps);

    m_audioHeatmapTex.bind();
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, c_side, c_side, GL_RED_INTEGER, GL_UNSIGNED_INT, m_audioTimestamps);

    m_seekHeatmapTex.bind();
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, c_side, c_side, GL_RED_INTEGER, GL_UNSIGNED_INT, m_seekTimestamps);
}
