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

#include "gpu/soft/soft.h"

#include <algorithm>

#include "gpu/soft/pixel-writer.h"
#include "gpu/soft/raster-state.h"

static constexpr int CHKMAX_X = 1024;
static constexpr int CHKMAX_Y = 512;

// Hardware silently drops any polygon or line that has an edge longer than
// 1023 pixels horizontally or 511 pixels vertically (verified on SCPH-5501
// via gpu-raster-phase14). The drop is unconditional - it does NOT depend on
// any vertex being off-screen. For quads, hardware applies the rule to the
// original 4-vertex perimeter, not to the decomposed-triangle edges, so the
// 4-vert check stays at this level rather than firing inside drawPolyXXX4.
static inline bool edgeOverLimit(int x0, int y0, int x1, int y1) {
    int dx = x1 - x0;
    int dy = y1 - y0;
    if (dx < 0) dx = -dx;
    if (dy < 0) dy = -dy;
    return dx >= CHKMAX_X || dy >= CHKMAX_Y;
}

bool PCSX::SoftGPU::SoftRenderer::checkCoord4(int16_t &x0, int16_t &y0, int16_t &x1, int16_t &y1, int16_t &x2,
                                              int16_t &y2, int16_t &x3, int16_t &y3) {
    // Per-perimeter-edge over-limit cull. Quad perimeter (PSX vertex order)
    // is v0->v1, v1->v3, v3->v2, v2->v0.
    if (edgeOverLimit(x0, y0, x1, y1)) return true;
    if (edgeOverLimit(x1, y1, x3, y3)) return true;
    if (edgeOverLimit(x3, y3, x2, y2)) return true;
    if (edgeOverLimit(x2, y2, x0, y0)) return true;

    return false;
}

bool PCSX::SoftGPU::SoftRenderer::checkCoord3(int16_t &x0, int16_t &y0, int16_t &x1, int16_t &y1, int16_t &x2,
                                              int16_t &y2) {
    // Per-edge over-limit cull.
    if (edgeOverLimit(x0, y0, x1, y1)) return true;
    if (edgeOverLimit(x1, y1, x2, y2)) return true;
    if (edgeOverLimit(x2, y2, x0, y0)) return true;

    return false;
}

void PCSX::SoftGPU::SoftRenderer::texturePage(GPU::TPage *prim) {
    m_globalTextAddrX = prim->tx << 6;
    m_globalTextAddrY = prim->ty << 8;

    if (m_useDither == 2) {
        m_ditherMode = true;
    } else {
        if (prim->dither) {
            m_ditherMode = m_useDither != 0;
        } else {
            m_ditherMode = false;
        }
    }

    m_globalTextTP = prim->texDepth;

    m_globalTextABR = prim->blendFunction;

    m_statusRet &= ~0x07ff;               // Clear the necessary bits
    m_statusRet |= (prim->raw & 0x07ff);  // set the necessary bits
}

void PCSX::SoftGPU::SoftRenderer::twindow(GPU::TWindow *prim) {
    uint32_t YAlign, XAlign;

    // Texture window size is determined by the least bit set of the relevant 5 bits
    if (prim->y & 0x01) {
        m_textureWindow.y1 = 8;  // xxxx1
    } else if (prim->y & 0x02) {
        m_textureWindow.y1 = 16;  // xxx10
    } else if (prim->y & 0x04) {
        m_textureWindow.y1 = 32;  // xx100
    } else if (prim->y & 0x08) {
        m_textureWindow.y1 = 64;  // x1000
    } else if (prim->y & 0x10) {
        m_textureWindow.y1 = 128;  // 10000
    } else {
        m_textureWindow.y1 = 256;  // 00000
    }

    if (prim->x & 0x01) {
        m_textureWindow.x1 = 8;  // xxxx1
    } else if (prim->x & 0x02) {
        m_textureWindow.x1 = 16;  // xxx10
    } else if (prim->x & 0x04) {
        m_textureWindow.x1 = 32;  // xx100
    } else if (prim->x & 0x08) {
        m_textureWindow.x1 = 64;  // x1000
    } else if (prim->x & 0x10) {
        m_textureWindow.x1 = 128;  // 10000
    } else {
        m_textureWindow.x1 = 256;  // 00000
    }

    // Re-calculate the bit field, because we can't trust what is passed in the data
    YAlign = (uint32_t)(32 - (m_textureWindow.y1 >> 3));
    XAlign = (uint32_t)(32 - (m_textureWindow.x1 >> 3));

    // Absolute position of the start of the texture window
    m_textureWindow.y0 = (int16_t)((prim->h & YAlign) << 3);
    m_textureWindow.x0 = (int16_t)((prim->w & XAlign) << 3);

    // Bit-substitution form consumed by the templated Sampler<TexMode>
    // paths. Hardware applies the window as
    //   filtered = (raw & ~(mask * 8)) | ((offset * 8) & (mask * 8))
    // not as "wrap raw within a power-of-2 region", so the mask field's
    // full 5-bit value participates and offset bits outside the mask
    // region are discarded. Verified on SCPH-5501 via gpu-raster-phase15
    // wt_mask01_off07_x0 / wt_mask03_off1f_x0.
    m_textureWindowMaskU = (uint8_t)((prim->x & 0x1f) << 3);
    m_textureWindowMaskV = (uint8_t)((prim->y & 0x1f) << 3);
    m_textureWindowOffU = (uint8_t)(((prim->w & 0x1f) << 3) & m_textureWindowMaskU);
    m_textureWindowOffV = (uint8_t)(((prim->h & 0x1f) << 3) & m_textureWindowMaskV);
}

void PCSX::SoftGPU::SoftRenderer::drawingAreaStart(GPU::DrawingAreaStart *prim) {
    m_drawX = prim->x;
    m_drawY = prim->y;
}

void PCSX::SoftGPU::SoftRenderer::drawingAreaEnd(GPU::DrawingAreaEnd *prim) {
    m_drawW = prim->x;
    m_drawH = prim->y;
}

void PCSX::SoftGPU::SoftRenderer::drawingOffset(GPU::DrawingOffset *prim) {
    m_softDisplay.DrawOffset.x = prim->x;
    m_softDisplay.DrawOffset.y = prim->y;
}

void PCSX::SoftGPU::SoftRenderer::maskBit(GPU::MaskBit *prim) {
    m_statusRet &= ~0x1800;

    if (prim->set) {
        m_setMask16 = 0x8000;
        m_setMask32 = 0x80008000;
        m_statusRet |= 0x0800;
    } else {
        m_setMask16 = 0;
        m_setMask32 = 0;
    }

    if (prim->check) {
        m_statusRet |= 0x1000;
    }
    m_checkMask = prim->check;
}

void PCSX::SoftGPU::SoftRenderer::drawRect(int16_t x0, int16_t y0, int16_t x1, int16_t y1, uint16_t col) {
    int16_t j, i, dx, dy;

    if (y0 > y1) return;
    if (x0 > x1) return;

    if (x1 < m_drawX) return;
    if (y1 < m_drawY) return;
    if (x0 > m_drawW) return;
    if (y0 > m_drawH) return;

    x1 = std::min(x1, static_cast<int16_t>(m_drawW + 1));
    y1 = std::min(y1, static_cast<int16_t>(m_drawH + 1));
    x0 = std::max(x0, static_cast<int16_t>(m_drawX));
    y0 = std::max(y0, static_cast<int16_t>(m_drawY));

    if (y0 >= VRAM_HEIGHT) return;
    if (x0 >= VRAM_WIDTH) return;

    if (y1 > VRAM_HEIGHT) y1 = VRAM_HEIGHT;
    if (x1 > VRAM_WIDTH) x1 = VRAM_WIDTH;

    dx = x1 - x0;
    dy = y1 - y0;

    if (dx == 1 && dy == 1 && x0 == 1020 && y0 == 511) {
        // interlace hack - fix me
        static int iCheat = 0;
        col += iCheat;
        iCheat ^= 1;
    }

    RasterState rs = makeBaseRasterState();

    using Writer = PixelWriter<false, GPU::Shading::Flat, WriteMode::Default>;

    if (dx & 1) {
        // slow fill
        for (i = 0; i < dy; i++) {
            for (j = 0; j < dx; j++) Writer::scalar(rs, x0 + j, y0 + i, col);
        }
    } else {
        // fast fill
        uint32_t *DSTPtr;
        uint16_t LineOffset;
        uint32_t lcol = m_setMask32 | (((uint32_t)(col)) << 16) | col;
        dx >>= 1;
        DSTPtr = (uint32_t *)(m_vram16 + (VRAM_WIDTH * y0) + x0);
        LineOffset = 512 - dx;

        if (!m_checkMask && !m_drawSemiTrans) {
            for (i = 0; i < dy; i++) {
                for (j = 0; j < dx; j++) *DSTPtr++ = lcol;
                DSTPtr += LineOffset;
            }
        } else {
            for (i = 0; i < dy; i++) {
                for (j = 0; j < dx; j++) Writer::packed(rs, x0 + (j << 1), y0 + i, lcol);
            }
        }
    }
}

void PCSX::SoftGPU::SoftRenderer::fillArea(int16_t x0, int16_t y0, int16_t x1, int16_t y1, uint16_t col) {
    int16_t j, i, dx, dy;

    if (y0 > y1) return;
    if (x0 > x1) return;

    if (y0 >= VRAM_HEIGHT) return;
    if (x0 >= VRAM_WIDTH) return;

    if (y1 > VRAM_HEIGHT) y1 = VRAM_HEIGHT;
    if (x1 > VRAM_WIDTH) x1 = VRAM_WIDTH;

    dx = x1 - x0;
    dy = y1 - y0;
    if (dx & 1) {
        uint16_t *DSTPtr;
        uint16_t LineOffset;

        DSTPtr = m_vram16 + (VRAM_WIDTH * y0) + x0;
        LineOffset = VRAM_WIDTH - dx;

        for (i = 0; i < dy; i++) {
            for (j = 0; j < dx; j++) *DSTPtr++ = col;
            DSTPtr += LineOffset;
        }
    } else {
        uint32_t *DSTPtr;
        uint16_t LineOffset;
        uint32_t lcol = (((int32_t)col) << 16) | col;

        dx >>= 1;
        DSTPtr = (uint32_t *)(m_vram16 + (VRAM_WIDTH * y0) + x0);
        LineOffset = 512 - dx;

        for (i = 0; i < dy; i++) {
            for (j = 0; j < dx; j++) *DSTPtr++ = lcol;
            DSTPtr += LineOffset;
        }
    }
}

template <PCSX::SoftGPU::TexMode Tex>
void PCSX::SoftGPU::SoftRenderer::drawSprite(int16_t x, int16_t y, int16_t w, int16_t h, int16_t u, int16_t v,
                                             int16_t clX, int16_t clY) {
    if (w <= 0 || h <= 0) return;

    int32_t x0 = x;
    int32_t y0 = y;
    int32_t x1 = x + w;
    int32_t y1 = y + h;

    // Clip to draw area (m_drawW / m_drawH are inclusive bottom-right).
    int32_t uStart = u;
    int32_t vStart = v;
    if (x0 < m_drawX) {
        uStart += m_drawX - x0;
        x0 = m_drawX;
    }
    if (y0 < m_drawY) {
        vStart += m_drawY - y0;
        y0 = m_drawY;
    }
    if (x1 > m_drawW + 1) x1 = m_drawW + 1;
    if (y1 > m_drawH + 1) y1 = m_drawH + 1;
    if (x0 >= x1 || y0 >= y1) return;

    RasterState rs = makeTexturedRasterState<Tex>(m_drawX, m_drawY, m_drawW, m_drawH, clX, clY);
    const int32_t yAdj = Sampler<Tex>::yAdjust(rs);
    if (!m_checkMask && !m_drawSemiTrans) {
        // Solid fast path: direct VRAM write, packed pairs where the row
        // length permits. This is shared by non-blended rectangles regardless
        // of whether the GP0 command was a semi-transparent variant.
        for (int32_t row = y0; row < y1; row++) {
            int32_t posX = (uStart) << 16;
            const int32_t posY = (vStart + (row - y0)) << 16;
            int32_t col = x0;
            // Packed pairs of texels while at least two columns remain.
            for (; col + 1 < x1; col += 2) {
                const uint32_t color = Sampler<Tex>::packed(rs, yAdj, posX, posY, 0x10000, 0);
                PixelWriter<true, GPU::Shading::Flat, WriteMode::Solid>::packed(rs, col, row, color);
                posX += 0x20000;
            }
            if (col < x1) {
                PixelWriter<true, GPU::Shading::Flat, WriteMode::Solid>::scalar(
                    rs, col, row, Sampler<Tex>::scalar(rs, yAdj, posX, posY));
            }
        }
        return;
    }

    // Blended or mask-checked path. Route the write through PixelWriter so
    // texture sampling stays separate from the VRAM geometry.
    for (int32_t row = y0; row < y1; row++) {
        int32_t posX = (uStart) << 16;
        const int32_t posY = (vStart + (row - y0)) << 16;
        int32_t col = x0;
        for (; col + 1 < x1; col += 2) {
            const uint32_t color = Sampler<Tex>::packed(rs, yAdj, posX, posY, 0x10000, 0);
            PixelWriter<true, GPU::Shading::Flat, WriteMode::Default>::packed(rs, col, row, color);
            posX += 0x20000;
        }
        if (col < x1) {
            const uint16_t color = Sampler<Tex>::scalar(rs, yAdj, posX, posY);
            PixelWriter<true, GPU::Shading::Flat, WriteMode::Default>::scalar(rs, col, row, color);
        }
    }
}

// Explicit instantiations: one rectangle blitter per texture mode.
template void PCSX::SoftGPU::SoftRenderer::drawSprite<PCSX::SoftGPU::TexMode::Clut4>(int16_t, int16_t, int16_t, int16_t,
                                                                                     int16_t, int16_t, int16_t,
                                                                                     int16_t);
template void PCSX::SoftGPU::SoftRenderer::drawSprite<PCSX::SoftGPU::TexMode::Clut8>(int16_t, int16_t, int16_t, int16_t,
                                                                                     int16_t, int16_t, int16_t,
                                                                                     int16_t);
template void PCSX::SoftGPU::SoftRenderer::drawSprite<PCSX::SoftGPU::TexMode::Direct15>(int16_t, int16_t, int16_t,
                                                                                        int16_t, int16_t, int16_t,
                                                                                        int16_t, int16_t);
