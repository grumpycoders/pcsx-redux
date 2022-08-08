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
#include "gpu/soft/prim.h"
#include "gui/gui.h"

int iFastFwd = 0;
PSXPoint_t ptCursorPoint[8];
uint16_t usCursorActive = 0;

PCSX::GUI *m_gui;
bool bVsync_Key = false;

static const unsigned int pitch = 4096;

void ShowGunCursor(unsigned char *surf) {
    uint16_t dx = (uint16_t)PreviousPSXDisplay.Range.x1;
    uint16_t dy = (uint16_t)PreviousPSXDisplay.DisplayMode.y;
    int x, y, iPlayer, sx, ex, sy, ey;

    if (PreviousPSXDisplay.Range.y0)  // centering needed?
    {
        surf += PreviousPSXDisplay.Range.y0 * pitch;
        dy -= PreviousPSXDisplay.Range.y0;
    }

    const uint32_t crCursorColor32[8] = {0xffff0000, 0xff00ff00, 0xff0000ff, 0xffff00ff,
                                         0xffffff00, 0xff00ffff, 0xffffffff, 0xff7f7f7f};

    surf += PreviousPSXDisplay.Range.x0 << 2;  // -> add x left border

    for (iPlayer = 0; iPlayer < 8; iPlayer++)  // -> loop all possible players
    {
        if (usCursorActive & (1 << iPlayer))  // -> player active?
        {
            const int ty = (ptCursorPoint[iPlayer].y * dy) / 256;  // -> calculate the cursor pos in the current display
            const int tx = (ptCursorPoint[iPlayer].x * dx) / 512;
            sx = tx - 5;
            if (sx < 0) {
                if (sx & 1)
                    sx = 1;
                else
                    sx = 0;
            }
            sy = ty - 5;
            if (sy < 0) {
                if (sy & 1)
                    sy = 1;
                else
                    sy = 0;
            }
            ex = tx + 6;
            if (ex > dx) ex = dx;
            ey = ty + 6;
            if (ey > dy) ey = dy;

            for (x = tx, y = sy; y < ey; y += 2)  // -> do dotted y line
                *((uint32_t *)((surf) + (y * pitch) + x * 4)) = crCursorColor32[iPlayer];
            for (y = ty, x = sx; x < ex; x += 2)  // -> do dotted x line
                *((uint32_t *)((surf) + (y * pitch) + x * 4)) = crCursorColor32[iPlayer];
        }
    }
}

static GLuint vramTexture = 0;

void PCSX::SoftGPU::impl::doBufferSwap() {
    GLuint textureID = m_vramTexture16;
    m_gui->setViewport();
    glBindTexture(GL_TEXTURE_2D, textureID);
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 1024, 512, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, psxVuw);

    if (PSXDisplay.RGB24) {
        textureID = vramTexture;
        glBindTexture(GL_TEXTURE_2D, vramTexture);
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 682, 512, GL_RGB, GL_UNSIGNED_BYTE, psxVuw);
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
    glBindTexture(GL_TEXTURE_2D, vramTexture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, filter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, filter);

    glBindTexture(GL_TEXTURE_2D, m_vramTexture16);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, filter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, filter);
}

void PCSX::SoftGPU::impl::initDisplay() {
    glGenTextures(1, &vramTexture);
    glBindTexture(GL_TEXTURE_2D, vramTexture);
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
