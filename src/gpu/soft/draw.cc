/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include <cstdint>

#include "GL/gl3w.h"
#include "gpu/soft/externals.h"
#include "gpu/soft/gpu.h"
#include "gpu/soft/interface.h"
#include "gpu/soft/soft.h"
#include "gui/gui.h"

static const unsigned int pitch = 4096;

void PCSX::SoftGPU::impl::doBufferSwap() {
    m_gui->setViewport();
    GLuint textureID;

    if (PSXDisplay.RGB24) {
        textureID = m_vramTexture24;
        glBindTexture(GL_TEXTURE_2D, textureID);
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 682, 512, GL_RGB, GL_UNSIGNED_BYTE, psxVuw);
    } else {
        textureID = m_vramTexture16;
        glBindTexture(GL_TEXTURE_2D, textureID);
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 1024, 512, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, psxVuw);
    }

    float xRatio = PSXDisplay.RGB24 ? ((1.0f / 1.5f) * (1.0f / 1024.0f)) : (1.0f / 1024.0f);

    float startX = PSXDisplay.DisplayPosition.x * xRatio;
    float startY = PSXDisplay.DisplayPosition.y / 512.0f;
    float width = (PSXDisplay.DisplayEnd.x - PSXDisplay.DisplayPosition.x) / 1024.0f;
    float height = (PSXDisplay.DisplayEnd.y - PSXDisplay.DisplayPosition.y) / 512.0f;

    // Temporary workaround until we make our Display struct work with the sw backend
    // Trim 1 pixel from the height and width when linear filtering is on to avoid artifacts due to wrong sampling
    if (g_emulator->settings.get<Emulator::SettingLinearFiltering>()) {
        width -= 1.f / 1024.f;
        height -= 1.f / 512.f;
    }

    m_gui->m_offscreenShaderEditor.render(m_gui, textureID, {startX, startY}, {width, height}, m_gui->getRenderSize());
    m_gui->flip();
}

void PCSX::SoftGPU::impl::clearVRAM() {
    const auto oldTex = OpenGL::getTex2D();
    std::memset(psxVSecure, 0x00, (iGPUHeight * 2) * 1024 + (1024 * 1024));

    glBindTexture(GL_TEXTURE_2D, m_vramTexture16);
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 1024, 512, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, psxVSecure);
    glBindTexture(GL_TEXTURE_2D, oldTex);
}

void PCSX::SoftGPU::impl::setLinearFiltering() {
    const auto filter = g_emulator->settings.get<Emulator::SettingLinearFiltering>().value ? GL_LINEAR : GL_NEAREST;
    glBindTexture(GL_TEXTURE_2D, m_vramTexture24);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, filter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, filter);

    glBindTexture(GL_TEXTURE_2D, m_vramTexture16);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, filter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, filter);
}

void PCSX::SoftGPU::impl::initDisplay() {
    glGenTextures(1, &m_vramTexture24);
    glBindTexture(GL_TEXTURE_2D, m_vramTexture24);
    glTexStorage2D(GL_TEXTURE_2D, 1, GL_RGB8, 1024, 512);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

    glGenTextures(1, &m_vramTexture16);
    glBindTexture(GL_TEXTURE_2D, m_vramTexture16);
    glTexStorage2D(GL_TEXTURE_2D, 1, GL_RGB5_A1, 1024, 512);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
}
