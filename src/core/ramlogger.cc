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

#include "core/ramlogger.h"

#include "core/psxemulator.h"
#include "core/psxmem.h"

void PCSX::RAMLogger::recordAccess(uint32_t physAddr, unsigned width, AccessType type, uint32_t cycle) {
    if (!m_enabled) return;

    uint32_t* timestamps = (type == AccessType::Read)    ? m_readTimestamps
                           : (type == AccessType::Write) ? m_writeTimestamps
                                                         : m_execTimestamps;

    for (unsigned i = 0; i < width; i++) {
        uint32_t addr = physAddr + i;
        if (addr < c_maxBytes) {
            timestamps[addr] = cycle;
        }
    }
}

void PCSX::RAMLogger::enable() {
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
    m_readHeatmapTex.create(c_width, c_maxHeight, GL_R32UI);
    m_writeHeatmapTex.create(c_width, c_maxHeight, GL_R32UI);
    m_execHeatmapTex.create(c_width, c_maxHeight, GL_R32UI);
    if (!m_readHeatmapTex.exists() || !m_writeHeatmapTex.exists() || !m_execHeatmapTex.exists()) return;
    setupTex(m_readHeatmapTex);
    setupTex(m_writeHeatmapTex);
    setupTex(m_execHeatmapTex);

    // Create RAM data texture (GL_R8)
    m_ramTexture.create(c_width, c_maxHeight, GL_R8);
    if (!m_ramTexture.exists()) return;
    setupTex(m_ramTexture);

    // Clear timestamp arrays
    memset(m_readTimestamps, 0, sizeof(m_readTimestamps));
    memset(m_writeTimestamps, 0, sizeof(m_writeTimestamps));
    memset(m_execTimestamps, 0, sizeof(m_execTimestamps));

    m_hasResources = true;
    m_enabled = true;
}

void PCSX::RAMLogger::disable() { m_enabled = false; }

void PCSX::RAMLogger::uploadRAM() {
    if (!m_hasResources) return;
    bool is8MB = g_emulator->settings.get<Emulator::Setting8MB>();
    int height = is8MB ? c_maxHeight : (c_maxHeight / 4);

    m_ramTexture.bind();
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, c_width, height, GL_RED, GL_UNSIGNED_BYTE, g_emulator->m_mem->m_wram);
}

void PCSX::RAMLogger::uploadHeatmaps() {
    if (!m_hasResources) return;
    bool is8MB = g_emulator->settings.get<Emulator::Setting8MB>();
    int height = is8MB ? c_maxHeight : (c_maxHeight / 4);

    glPixelStorei(GL_UNPACK_ALIGNMENT, 4);

    m_readHeatmapTex.bind();
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, c_width, height, GL_RED_INTEGER, GL_UNSIGNED_INT, m_readTimestamps);

    m_writeHeatmapTex.bind();
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, c_width, height, GL_RED_INTEGER, GL_UNSIGNED_INT, m_writeTimestamps);

    m_execHeatmapTex.bind();
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, c_width, height, GL_RED_INTEGER, GL_UNSIGNED_INT, m_execTimestamps);
}
