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
#include "gpu/soft/interface.h"
#include "gpu/soft/soft.h"
#include "gui/gui.h"

void PCSX::SoftGPU::impl::doBufferSwap(bool fromGui) {
    GUI *gui = dynamic_cast<GUI *>(m_ui);
    if (!gui) {
        return;
    }
    gui->setViewport();
    GLuint textureID;

    if (m_softDisplay.RGB24) {
        auto offset = (m_softDisplay.DisplayPosition.x * 2) % 3;
        textureID = m_vramTexture24;
        glBindTexture(GL_TEXTURE_2D, textureID);
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 682, 512, GL_RGB, GL_UNSIGNED_BYTE, m_vram + offset);
    } else {
        textureID = m_vramTexture16;
        glBindTexture(GL_TEXTURE_2D, textureID);
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 1024, 512, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, m_vram16);
    }

    float xRatio = m_softDisplay.RGB24 ? ((1.0f / 1.5f) * (1.0f / 1024.0f)) : (1.0f / 1024.0f);

    float startX = m_softDisplay.DisplayPosition.x * xRatio;
    float startY = m_softDisplay.DisplayPosition.y / 512.0f;
    float width = (m_softDisplay.DisplayEnd.x - m_softDisplay.DisplayPosition.x) / 1024.0f;
    float height = (m_softDisplay.DisplayEnd.y - m_softDisplay.DisplayPosition.y) / 512.0f;

    // Temporary workaround until we make our Display struct work with the sw backend
    // Trim 1 pixel from the height and width when linear filtering is on to avoid artifacts due to wrong sampling
    if (g_emulator->settings.get<Emulator::SettingLinearFiltering>()) {
        width -= 1.f / 1024.f;
        height -= 1.f / 512.f;
    }

    gui->m_offscreenShaderEditor.render(gui, textureID, {startX, startY}, {width, height}, gui->getRenderSize());
    if (!fromGui) gui->flip();
}

void PCSX::SoftGPU::impl::clearVRAM() {
    GUI *gui = dynamic_cast<GUI *>(m_ui);
    if (!gui) return;
    const auto oldTex = OpenGL::getTex2D();
    std::memset(m_allocatedVRAM, 0x00, (GPU_HEIGHT * 2) * 1024 + (1024 * 1024));

    glBindTexture(GL_TEXTURE_2D, m_vramTexture16);
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 1024, 512, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, m_allocatedVRAM);
    glBindTexture(GL_TEXTURE_2D, oldTex);
}

void PCSX::SoftGPU::impl::setLinearFiltering() {
    GUI *gui = dynamic_cast<GUI *>(m_ui);
    if (!gui) return;
    const auto filter = g_emulator->settings.get<Emulator::SettingLinearFiltering>().value ? GL_LINEAR : GL_NEAREST;
    glBindTexture(GL_TEXTURE_2D, m_vramTexture24);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, filter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, filter);

    glBindTexture(GL_TEXTURE_2D, m_vramTexture16);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, filter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, filter);
}

void PCSX::SoftGPU::impl::initDisplay() {
    GUI *gui = dynamic_cast<GUI *>(m_ui);
    if (!gui) return;
    glGenTextures(1, &m_vramTexture24);
    glBindTexture(GL_TEXTURE_2D, m_vramTexture24);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, 1024, 512, 0, GL_RGB, GL_UNSIGNED_BYTE, nullptr);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

    glGenTextures(1, &m_vramTexture16);
    glBindTexture(GL_TEXTURE_2D, m_vramTexture16);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 1024, 512, 0, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, nullptr);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
}
