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
#include "gpu/soft/soft.h"

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

// Signed 4x4 Bayer dither offsets, applied in 8-bit space before the
// 5-bit truncation. Indexed by (sy & 3) * 4 + (sx & 3). Values match
// the hardware-verified table reproduced in psx-spx.
// clang-format off
static constexpr int8_t s_dithertable[16] = {
    -4,  0, -3,  1,
     2, -2,  3, -1,
    -3,  1, -4,  0,
     3, -1,  2, -2,
};
// clang-format on

static uint16_t *s_ditherLUT = nullptr;

static void prepareDitherLut() {
    uint32_t r, g, b, s;
    assert(s_ditherLUT == nullptr);
    s_ditherLUT = new uint16_t[256 * 256 * 256 * 16];
    uint16_t *ditherLUT = s_ditherLUT;
    for (r = 0; r < 256; r++) {
        for (g = 0; g < 256; g++) {
            for (b = 0; b < 256; b++) {
                for (s = 0; s < 16; s++) {
                    int32_t offset = s_dithertable[s];
                    int32_t ra = (int32_t)r + offset;
                    int32_t ga = (int32_t)g + offset;
                    int32_t ba = (int32_t)b + offset;
                    if (ra < 0) {
                        ra = 0;
                    } else if (ra > 0xff) {
                        ra = 0xff;
                    }
                    if (ga < 0) {
                        ga = 0;
                    } else if (ga > 0xff) {
                        ga = 0xff;
                    }
                    if (ba < 0) {
                        ba = 0;
                    } else if (ba > 0xff) {
                        ba = 0xff;
                    }

                    uint32_t rc = (uint32_t)ra >> 3;
                    uint32_t gc = (uint32_t)ga >> 3;
                    uint32_t bc = (uint32_t)ba >> 3;

                    *ditherLUT++ = ((uint16_t)bc << 10) | ((uint16_t)gc << 5) | (uint16_t)rc;
                }
            }
        }
    }
}

void PCSX::SoftGPU::SoftRenderer::enableCachedDithering() {
    if (!s_ditherLUT) prepareDitherLut();
}

void PCSX::SoftGPU::SoftRenderer::disableCachedDithering() {
    if (s_ditherLUT) delete[] s_ditherLUT;
    s_ditherLUT = nullptr;
}

PCSX::SoftGPU::SoftRenderer::~SoftRenderer() {
    if (s_ditherLUT) delete[] s_ditherLUT;
    s_ditherLUT = nullptr;
}

static void applyDitherCached(uint16_t *pdest, uint16_t *base, uint32_t r, uint32_t g, uint32_t b, uint16_t sM) {
    int x, y;

    x = pdest - base;
    y = x >> 10;
    x -= (y << 10);

    uint32_t index = r;
    index <<= 8;
    index |= g;
    index <<= 8;
    index |= b;
    index <<= 4;
    index |= (y & 3) * 4 + (x & 3);

    *pdest = s_ditherLUT[index] | sM;
}

static void applyDither(uint16_t *pdest, uint16_t *base, uint32_t r, uint32_t g, uint32_t b, uint16_t sM) {
    int x, y;

    x = pdest - base;
    y = x >> 10;
    x -= (y << 10);

    int32_t offset = s_dithertable[(y & 3) * 4 + (x & 3)];

    int32_t ra = std::clamp((int32_t)r + offset, 0, 0xff);
    int32_t ga = std::clamp((int32_t)g + offset, 0, 0xff);
    int32_t ba = std::clamp((int32_t)b + offset, 0, 0xff);

    uint32_t r5 = (uint32_t)ra >> 3;
    uint32_t g5 = (uint32_t)ga >> 3;
    uint32_t b5 = (uint32_t)ba >> 3;

    *pdest = ((uint16_t)b5 << 10) | ((uint16_t)g5 << 5) | (uint16_t)r5 | sM;
}

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////

template <bool useCachedDither>
void PCSX::SoftGPU::SoftRenderer::getShadeTransColDither(uint16_t *pdest, int32_t m1, int32_t m2, int32_t m3) {
    int32_t r, g, b;

    if (m_checkMask && *pdest & 0x8000) return;

    if (m_drawSemiTrans) {
        r = ((Channel555::R::extractRightAligned(*pdest)) << 3);
        b = ((Channel555::B::extractRightAligned(*pdest)) << 3);
        g = ((Channel555::G::extractRightAligned(*pdest)) << 3);

        if (m_globalTextABR == GPU::BlendFunction::HalfBackAndHalfFront) {
            // (B + F) / 2 preserving each channel's bit-0 carry
            // (phase-12 abr0_tri_b31_f31). 8-bit per channel here.
            r = (r + m1) >> 1;
            b = (b + m2) >> 1;
            g = (g + m3) >> 1;
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackAndFullFront) {
            r += m1;
            b += m2;
            g += m3;
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackSubFullFront) {
            r -= m1;
            b -= m2;
            g -= m3;
            if (r & 0x80000000) r = 0;
            if (b & 0x80000000) b = 0;
            if (g & 0x80000000) g = 0;
        } else {
            r += (m1 >> 2);
            b += (m2 >> 2);
            g += (m3 >> 2);
        }
    } else {
        r = m1;
        b = m2;
        g = m3;
    }

    if (r & 0x7fffff00) r = 0xff;
    if (b & 0x7fffff00) b = 0xff;
    if (g & 0x7fffff00) g = 0xff;

    if constexpr (useCachedDither) {
        applyDitherCached(pdest, m_vram16, r, b, g, m_setMask16);
    } else {
        applyDither(pdest, m_vram16, r, b, g, m_setMask16);
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::getTextureTransColShadeSemi(uint16_t *pdest, uint16_t color) {
    int32_t r, g, b;
    uint16_t l;

    if (color == 0) return;

    if (m_checkMask && *pdest & 0x8000) return;

    l = m_setMask16 | (color & 0x8000);

    if (m_drawSemiTrans && (color & 0x8000)) {
        if (m_globalTextABR == GPU::BlendFunction::HalfBackAndHalfFront) {
            // Carry-preserving (B + F_modulated) / 2 per channel
            // (phase-12 abr0_tri_b31_f31).
            const int32_t Br = *pdest & 0x1f;
            const int32_t Bb = (*pdest >> 5) & 0x1f;
            const int32_t Bg = (*pdest >> 10) & 0x1f;
            const int32_t Fr = ((color & 0x1f) * m_m1) >> 7;
            const int32_t Fb = (((color >> 5) & 0x1f) * m_m2) >> 7;
            const int32_t Fg = (((color >> 10) & 0x1f) * m_m3) >> 7;
            r = (Br + Fr) >> 1;
            b = ((Bb + Fb) >> 1) << 5;
            g = ((Bg + Fg) >> 1) << 10;
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackAndFullFront) {
            r = (Channel555::R::extractNative(*pdest)) + ((((Channel555::R::extractNative(color))) * m_m1) >> 7);
            b = (Channel555::B::extractNative(*pdest)) + ((((Channel555::B::extractNative(color))) * m_m2) >> 7);
            g = (Channel555::G::extractNative(*pdest)) + ((((Channel555::G::extractNative(color))) * m_m3) >> 7);
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackSubFullFront) {
            r = (Channel555::R::extractNative(*pdest)) - ((((Channel555::R::extractNative(color))) * m_m1) >> 7);
            b = (Channel555::B::extractNative(*pdest)) - ((((Channel555::B::extractNative(color))) * m_m2) >> 7);
            g = (Channel555::G::extractNative(*pdest)) - ((((Channel555::G::extractNative(color))) * m_m3) >> 7);
            if (r & 0x80000000) r = 0;
            if (b & 0x80000000) b = 0;
            if (g & 0x80000000) g = 0;
        } else {
            r = (Channel555::R::extractNative(*pdest)) + ((((Channel555::R::extractNative(color)) >> 2) * m_m1) >> 7);
            b = (Channel555::B::extractNative(*pdest)) + ((((Channel555::B::extractNative(color)) >> 2) * m_m2) >> 7);
            g = (Channel555::G::extractNative(*pdest)) + ((((Channel555::G::extractNative(color)) >> 2) * m_m3) >> 7);
        }
    } else {
        r = ((Channel555::R::extractNative(color)) * m_m1) >> 7;
        b = ((Channel555::B::extractNative(color)) * m_m2) >> 7;
        g = ((Channel555::G::extractNative(color)) * m_m3) >> 7;
    }

    if (r & 0x7fffffe0) r = 0x1f;
    if (b & 0x7ffffc00) b = 0x3e0;
    if (g & 0x7fff8000) g = 0x7c00;

    *pdest = (Channel555::packBGRMasked(r, b, g)) | l;
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::getTextureTransColShadeSemi32(uint32_t *pdest, uint32_t color) {
    int32_t r, g, b;

    if (color == 0) return;

    if (m_drawSemiTrans && (color & 0x80008000)) {
        if (m_globalTextABR == GPU::BlendFunction::HalfBackAndHalfFront) {
            r = ((((PackedPair555::alignRForHalfBlend(*pdest)) + ((PackedPair555::extractR(color)) * m_m1)) &
                  0xff00ff00) >>
                 8);
            b = ((((PackedPair555::alignBForHalfBlend(*pdest)) + ((PackedPair555::extractB(color)) * m_m2)) &
                  0xff00ff00) >>
                 8);
            g = ((((PackedPair555::alignGForHalfBlend(*pdest)) + ((PackedPair555::extractG(color)) * m_m3)) &
                  0xff00ff00) >>
                 8);
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackAndFullFront) {
            r = (PackedPair555::extractR(*pdest)) + (((((PackedPair555::extractR(color))) * m_m1) & 0xff80ff80) >> 7);
            b = (PackedPair555::extractB(*pdest)) + (((((PackedPair555::extractB(color))) * m_m2) & 0xff80ff80) >> 7);
            g = (PackedPair555::extractG(*pdest)) + (((((PackedPair555::extractG(color))) * m_m3) & 0xff80ff80) >> 7);
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackSubFullFront) {
            int32_t t;
            r = (((((PackedPair555::extractR(color))) * m_m1) & 0xff80ff80) >> 7);
            t = (*pdest & 0x001f0000) - (r & 0x003f0000);
            if (t & 0x80000000) t = 0;
            r = (*pdest & 0x0000001f) - (r & 0x0000003f);
            if (r & 0x80000000) r = 0;
            r |= t;

            b = (((((PackedPair555::extractB(color))) * m_m2) & 0xff80ff80) >> 7);
            t = ((*pdest >> 5) & 0x001f0000) - (b & 0x003f0000);
            if (t & 0x80000000) t = 0;
            b = ((*pdest >> 5) & 0x0000001f) - (b & 0x0000003f);
            if (b & 0x80000000) b = 0;
            b |= t;

            g = (((((PackedPair555::extractG(color))) * m_m3) & 0xff80ff80) >> 7);
            t = ((*pdest >> 10) & 0x001f0000) - (g & 0x003f0000);
            if (t & 0x80000000) t = 0;
            g = ((*pdest >> 10) & 0x0000001f) - (g & 0x0000003f);
            if (g & 0x80000000) g = 0;
            g |= t;
        } else {
            r = (PackedPair555::extractR(*pdest)) +
                (((((PackedPair555::extractRForQuarter(color)) >> 2) * m_m1) & 0xff80ff80) >> 7);
            b = (PackedPair555::extractB(*pdest)) +
                (((((PackedPair555::extractBForQuarter(color)) >> 2) * m_m2) & 0xff80ff80) >> 7);
            g = (PackedPair555::extractG(*pdest)) +
                (((((PackedPair555::extractGForQuarter(color)) >> 2) * m_m3) & 0xff80ff80) >> 7);
        }

        if (!(color & 0x8000)) {
            r = (r & 0xffff0000) | ((((PackedPair555::extractR(color)) * m_m1) & 0x0000ff80) >> 7);
            b = (b & 0xffff0000) | ((((PackedPair555::extractB(color)) * m_m2) & 0x0000ff80) >> 7);
            g = (g & 0xffff0000) | ((((PackedPair555::extractG(color)) * m_m3) & 0x0000ff80) >> 7);
        }
        if (!(color & 0x80000000)) {
            r = (r & 0xffff) | ((((PackedPair555::extractR(color)) * m_m1) & 0xFF800000) >> 7);
            b = (b & 0xffff) | ((((PackedPair555::extractB(color)) * m_m2) & 0xFF800000) >> 7);
            g = (g & 0xffff) | ((((PackedPair555::extractG(color)) * m_m3) & 0xFF800000) >> 7);
        }

    } else {
        r = (((PackedPair555::extractR(color)) * m_m1) & 0xff80ff80) >> 7;
        b = (((PackedPair555::extractB(color)) * m_m2) & 0xff80ff80) >> 7;
        g = (((PackedPair555::extractG(color)) * m_m3) & 0xff80ff80) >> 7;
    }

    if (r & 0x7fe00000) r = 0x1f0000 | (r & 0xffff);
    if (r & 0x7fe0) r = 0x1f | (r & 0xffff0000);
    if (b & 0x7fe00000) b = 0x1f0000 | (b & 0xffff);
    if (b & 0x7fe0) b = 0x1f | (b & 0xffff0000);
    if (g & 0x7fe00000) g = 0x1f0000 | (g & 0xffff);
    if (g & 0x7fe0) g = 0x1f | (g & 0xffff0000);

    if (m_checkMask) {
        uint32_t ma = *pdest;

        *pdest = (PackedPair555::packBGR(r, b, g)) | m_setMask32 | (color & 0x80008000);

        if ((color & 0xffff) == 0) *pdest = (ma & 0xffff) | (*pdest & 0xffff0000);
        if ((color & 0xffff0000) == 0) *pdest = (ma & 0xffff0000) | (*pdest & 0xffff);
        if (ma & 0x80000000) *pdest = (ma & 0xffff0000) | (*pdest & 0xffff);
        if (ma & 0x00008000) *pdest = (ma & 0xffff) | (*pdest & 0xffff0000);

        return;
    }
    if ((color & 0xffff) == 0) {
        *pdest =
            (*pdest & 0xffff) | (((PackedPair555::packBGR(r, b, g)) | m_setMask32 | (color & 0x80008000)) & 0xffff0000);
        return;
    }
    if ((color & 0xffff0000) == 0) {
        *pdest =
            (*pdest & 0xffff0000) | (((PackedPair555::packBGR(r, b, g)) | m_setMask32 | (color & 0x80008000)) & 0xffff);
        return;
    }

    *pdest = (PackedPair555::packBGR(r, b, g)) | m_setMask32 | (color & 0x80008000);
}

////////////////////////////////////////////////////////////////////////

template <bool useCachedDither>
void PCSX::SoftGPU::SoftRenderer::getTextureTransColShadeDither(uint16_t *pdest, uint16_t color, int32_t m1, int32_t m2,
                                                                int32_t m3) {
    int32_t r, g, b;

    if (color == 0) return;

    if (m_checkMask && *pdest & 0x8000) return;

    m1 = (((Channel555::R::extractRightAligned(color))) * m1) >> 4;
    m2 = (((Channel555::B::extractRightAligned(color))) * m2) >> 4;
    m3 = (((Channel555::G::extractRightAligned(color))) * m3) >> 4;

    if (m_drawSemiTrans && (color & 0x8000)) {
        r = ((Channel555::R::extractRightAligned(*pdest)) << 3);
        b = ((Channel555::B::extractRightAligned(*pdest)) << 3);
        g = ((Channel555::G::extractRightAligned(*pdest)) << 3);

        if (m_globalTextABR == GPU::BlendFunction::HalfBackAndHalfFront) {
            // (B + F) / 2 preserving each channel's bit-0 carry
            // (phase-12 abr0_tri_b31_f31). 8-bit per channel here.
            r = (r + m1) >> 1;
            b = (b + m2) >> 1;
            g = (g + m3) >> 1;
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackAndFullFront) {
            r += m1;
            b += m2;
            g += m3;
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackSubFullFront) {
            r -= m1;
            b -= m2;
            g -= m3;
            if (r & 0x80000000) r = 0;
            if (b & 0x80000000) b = 0;
            if (g & 0x80000000) g = 0;
        } else {
            r += (m1 >> 2);
            b += (m2 >> 2);
            g += (m3 >> 2);
        }
    } else {
        r = m1;
        b = m2;
        g = m3;
    }

    if (r & 0x7fffff00) r = 0xff;
    if (b & 0x7fffff00) b = 0xff;
    if (g & 0x7fffff00) g = 0xff;

    if constexpr (useCachedDither) {
        applyDitherCached(pdest, m_vram16, r, b, g, m_setMask16 | (color & 0x8000));
    } else {
        applyDither(pdest, m_vram16, r, b, g, m_setMask16 | (color & 0x8000));
    }
}

////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// FILL FUNCS
////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::fillSoftwareAreaTrans(int16_t x0, int16_t y0, int16_t x1, int16_t y1, uint16_t col) {
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

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::fillSoftwareArea(int16_t x0, int16_t y0, int16_t x1, int16_t y1, uint16_t col) {
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

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
// EDGE INTERPOLATION
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

// Unified 3-vertex edge walkers.
//
// One body per role, four (HasUV, HasRGB) template instantiations replace
// the legacy Flat3 / Shade3 / FlatTextured3 / ShadeTextured3 family:
//
//   <false, false> : drawPolyFlat3              (flat untextured triangle)
//   <false, true>  : drawPoly3G             (gouraud untextured triangle)
//   <true,  false> : drawPoly3T<TexMode>        (flat textured triangle)
//   <true,  true>  : drawPoly3TGi<TexMode, Dith> (gouraud textured triangle)
//
// 3-vert convention worth knowing before reading the body: the
// m_deltaRight{U,V,R,G,B} members are the *X-direction span gradients*
// computed once via shl10idiv against the longest edge. Per-row Y advance
// on the right edge only carries the m_rightStartX/m_rightDiffX recompute
// pair. The left edge tracks full X+U+V+R+G+B per-row via m_leftStart{X,
// U,V,R,G,B}/m_leftDiff{X,U,V,R,G,B}.
//
// Per-row recompute. Each row computes its edge-state value from scratch
// as start + (int64_t)diff * row / fullHeight, where row is the
// section-relative row index derived from the down-counter. This is
// bit-exact against hardware: hardware itself walks edges with full
// precision, and the recompute formula reproduces that behaviour with one
// truncation per row instead of accumulating an integer-divided quotient
// that drifts after multiple rows.
//
// Bodies live in this TU only; all instantiations happen here, so no
// explicit instantiation declarations are needed.

template <bool HasUV, bool HasRGB>
int PCSX::SoftGPU::SoftRenderer::rightSection3() {
    SoftVertex *v1 = m_rightArray[m_rightSection];
    SoftVertex *v2 = m_rightArray[m_rightSection - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    m_rightStartX = v1->x;
    m_rightDiffX = v2->x - v1->x;
    m_rightX = v1->x;

    m_rightSectionFullHeight = height;
    m_rightSectionHeight = height;
    return height;
}

template <bool HasUV, bool HasRGB>
int PCSX::SoftGPU::SoftRenderer::leftSection3() {
    SoftVertex *v1 = m_leftArray[m_leftSection];
    SoftVertex *v2 = m_leftArray[m_leftSection - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    m_leftStartX = v1->x;
    m_leftDiffX = v2->x - v1->x;
    m_leftX = v1->x;

    if constexpr (HasUV) {
        m_leftStartU = v1->u;
        m_leftDiffU = v2->u - v1->u;
        m_leftU = v1->u;
        m_leftStartV = v1->v;
        m_leftDiffV = v2->v - v1->v;
        m_leftV = v1->v;
    }

    if constexpr (HasRGB) {
        m_leftStartR = v1->R;
        m_leftDiffR = v2->R - v1->R;
        m_leftR = v1->R;
        m_leftStartG = v1->G;
        m_leftDiffG = v2->G - v1->G;
        m_leftG = v1->G;
        m_leftStartB = v1->B;
        m_leftDiffB = v2->B - v1->B;
        m_leftB = v1->B;
    }

    m_leftSectionFullHeight = height;
    m_leftSectionHeight = height;
    return height;
}

template <bool HasUV, bool HasRGB>
bool PCSX::SoftGPU::SoftRenderer::nextRow3() {
    if (--m_leftSectionHeight <= 0) {
        if (--m_leftSection <= 0) return true;
        if (leftSection3<HasUV, HasRGB>() <= 0) return true;
    } else {
        const int row = m_leftSectionFullHeight - m_leftSectionHeight;
        const int height = m_leftSectionFullHeight;
        m_leftX = m_leftStartX + (int64_t)m_leftDiffX * row / height;
        if constexpr (HasUV) {
            m_leftU = m_leftStartU + (int64_t)m_leftDiffU * row / height;
            m_leftV = m_leftStartV + (int64_t)m_leftDiffV * row / height;
        }
        if constexpr (HasRGB) {
            m_leftR = m_leftStartR + (int64_t)m_leftDiffR * row / height;
            m_leftG = m_leftStartG + (int64_t)m_leftDiffG * row / height;
            m_leftB = m_leftStartB + (int64_t)m_leftDiffB * row / height;
        }
    }

    if (--m_rightSectionHeight <= 0) {
        if (--m_rightSection <= 0) return true;
        if (rightSection3<HasUV, HasRGB>() <= 0) return true;
    } else {
        const int row = m_rightSectionFullHeight - m_rightSectionHeight;
        m_rightX = m_rightStartX + (int64_t)m_rightDiffX * row / m_rightSectionFullHeight;
    }
    return false;
}

template <bool HasUV, bool HasRGB>
bool PCSX::SoftGPU::SoftRenderer::setupSections3(const TriInput &in) {
    SoftVertex *v1, *v2, *v3;

    v1 = m_vtx;
    v1->x = in.x[0] << 16;
    v1->y = in.y[0];
    if constexpr (HasUV) {
        v1->u = in.u[0] << 16;
        v1->v = in.v[0] << 16;
    }
    if constexpr (HasRGB) {
        v1->R = in.rgb[0] & 0x00ff0000;
        v1->G = (in.rgb[0] << 8) & 0x00ff0000;
        v1->B = (in.rgb[0] << 16) & 0x00ff0000;
    }

    v2 = m_vtx + 1;
    v2->x = in.x[1] << 16;
    v2->y = in.y[1];
    if constexpr (HasUV) {
        v2->u = in.u[1] << 16;
        v2->v = in.v[1] << 16;
    }
    if constexpr (HasRGB) {
        v2->R = in.rgb[1] & 0x00ff0000;
        v2->G = (in.rgb[1] << 8) & 0x00ff0000;
        v2->B = (in.rgb[1] << 16) & 0x00ff0000;
    }

    v3 = m_vtx + 2;
    v3->x = in.x[2] << 16;
    v3->y = in.y[2];
    if constexpr (HasUV) {
        v3->u = in.u[2] << 16;
        v3->v = in.v[2] << 16;
    }
    if constexpr (HasRGB) {
        v3->R = in.rgb[2] & 0x00ff0000;
        v3->G = (in.rgb[2] << 8) & 0x00ff0000;
        v3->B = (in.rgb[2] << 16) & 0x00ff0000;
    }

    if (v1->y > v2->y) {
        SoftVertex *v = v1;
        v1 = v2;
        v2 = v;
    }
    if (v1->y > v3->y) {
        SoftVertex *v = v1;
        v1 = v3;
        v3 = v;
    }
    if (v2->y > v3->y) {
        SoftVertex *v = v2;
        v2 = v3;
        v3 = v;
    }

    int height = v3->y - v1->y;
    if (height == 0) return false;

    int temp = (((v2->y - v1->y) << 16) / height);
    int longest = temp * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
    if (longest == 0) return false;

    if (longest < 0) {
        m_rightArray[0] = v3;
        m_rightArray[1] = v2;
        m_rightArray[2] = v1;
        m_rightSection = 2;
        m_leftArray[0] = v3;
        m_leftArray[1] = v1;
        m_leftSection = 1;

        if (leftSection3<HasUV, HasRGB>() <= 0) return false;
        if (rightSection3<HasUV, HasRGB>() <= 0) {
            m_rightSection--;
            if (rightSection3<HasUV, HasRGB>() <= 0) return false;
        }
        if constexpr (HasUV || HasRGB) {
            if (longest > -0x1000) longest = -0x1000;
        }
    } else {
        m_leftArray[0] = v3;
        m_leftArray[1] = v2;
        m_leftArray[2] = v1;
        m_leftSection = 2;
        m_rightArray[0] = v3;
        m_rightArray[1] = v1;
        m_rightSection = 1;

        if (rightSection3<HasUV, HasRGB>() <= 0) return false;
        if (leftSection3<HasUV, HasRGB>() <= 0) {
            m_leftSection--;
            if (leftSection3<HasUV, HasRGB>() <= 0) return false;
        }
        if constexpr (HasUV || HasRGB) {
            if (longest < 0x1000) longest = 0x1000;
        }
    }

    m_yMin = v1->y;
    m_yMax = std::min(v3->y - 1, m_drawH);

    if constexpr (HasRGB) {
        m_deltaRightR = shl10idiv(temp * ((v3->R - v1->R) >> 10) + ((v1->R - v2->R) << 6), longest);
        m_deltaRightG = shl10idiv(temp * ((v3->G - v1->G) >> 10) + ((v1->G - v2->G) << 6), longest);
        m_deltaRightB = shl10idiv(temp * ((v3->B - v1->B) >> 10) + ((v1->B - v2->B) << 6), longest);
    }

    if constexpr (HasUV) {
        m_deltaRightU = shl10idiv(temp * ((v3->u - v1->u) >> 10) + ((v1->u - v2->u) << 6), longest);
        m_deltaRightV = shl10idiv(temp * ((v3->v - v1->v) >> 10) + ((v1->v - v2->v) << 6), longest);
    }

    return true;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
// POLY FUNCS
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// POLY 3/4 FLAT SHADED
////////////////////////////////////////////////////////////////////////

template <PCSX::GPU::Shading Shading, bool useCachedDither>
void PCSX::SoftGPU::SoftRenderer::drawPoly3i(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                             int32_t rgb1, int32_t rgb2, int32_t rgb3) {
    int i, j, xmin, xmax, ymin, ymax;

    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;

    const int16_t rejXs[3] = {x1, x2, x3};
    const int16_t rejYs[3] = {y1, y2, y3};
    if (primitiveOutsideDrawArea(rejXs, rejYs)) return;

    if (!setupSections3<false, Shading == GPU::Shading::Gouraud>(
            TriInput{{x1, x2, x3}, {y1, y2, y3}, {}, {}, {rgb1, rgb2, rgb3}}))
        return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRow3<false, Shading == GPU::Shading::Gouraud>()) return;
    }

    const auto vram16 = m_vram16;
    uint16_t color;
    uint32_t lcolor;
    int32_t cR1 = 0, cG1 = 0, cB1 = 0;
    int32_t difR = 0, difG = 0, difB = 0, difR2 = 0, difG2 = 0, difB2 = 0;

    if constexpr (Shading == GPU::Shading::Flat) {
        color = PCSX::SoftGPU::Channel555::fromCommandColor(rgb1);
        lcolor = m_setMask32 | (((uint32_t)(color)) << 16) | color;
    } else {
        difR = m_deltaRightR;
        difG = m_deltaRightG;
        difB = m_deltaRightB;
        difR2 = difR << 1;
        difG2 = difG << 1;
        difB2 = difB << 1;
    }

    RasterState rs = makeBaseRasterState();

    if (!m_checkMask && !m_drawSemiTrans && (Shading == GPU::Shading::Flat || !m_ditherMode)) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX + 0xFFFF) >> 16;
            xmax = (m_rightX - 1) >> 16;
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                if constexpr (Shading == GPU::Shading::Gouraud) {
                    cR1 = m_leftR;
                    cG1 = m_leftG;
                    cB1 = m_leftB;
                }

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    if constexpr (Shading == GPU::Shading::Gouraud) {
                        cR1 += j * difR;
                        cG1 += j * difG;
                        cB1 += j * difB;
                    }
                }

                for (j = xmin; j < xmax; j += 2) {
                    if constexpr (Shading == GPU::Shading::Flat) {
                        PixelWriter<false, Shading, WriteMode::Solid>::packed(rs, j, i, lcolor);
                    } else {
                        const uint32_t packedColor =
                            PCSX::SoftGPU::Channel555::fromHighAlignedRGBPair(cR1, cG1, cB1, difR, difG, difB);
                        PixelWriter<false, Shading, WriteMode::Solid>::packed(rs, j, i, packedColor);
                        cR1 += difR2;
                        cG1 += difG2;
                        cB1 += difB2;
                    }
                }
                if (j == xmax) {
                    if constexpr (Shading == GPU::Shading::Flat) {
                        PixelWriter<false, Shading, WriteMode::Solid>::scalar(rs, j, i, color);
                    } else {
                        const uint16_t scalarColor = PCSX::SoftGPU::Channel555::fromHighAlignedRGB(cR1, cG1, cB1);
                        PixelWriter<false, Shading, WriteMode::Solid>::scalar(rs, j, i, scalarColor);
                    }
                }
            }
            if (nextRow3<false, Shading == GPU::Shading::Gouraud>()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX + 0xFFFF) >> 16;
        xmax = (m_rightX - 1) >> 16;
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            if constexpr (Shading == GPU::Shading::Gouraud) {
                cR1 = m_leftR;
                cG1 = m_leftG;
                cB1 = m_leftB;
            }

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                if constexpr (Shading == GPU::Shading::Gouraud) {
                    cR1 += j * difR;
                    cG1 += j * difG;
                    cB1 += j * difB;
                }
            }

            if constexpr (Shading == GPU::Shading::Flat) {
                for (j = xmin; j < xmax; j += 2) {
                    PixelWriter<false, GPU::Shading::Flat, WriteMode::Default>::packed(rs, j, i, lcolor);
                }
                if (j == xmax) {
                    PixelWriter<false, GPU::Shading::Flat, WriteMode::Default>::scalar(rs, j, i, color);
                }
            } else {
                for (j = xmin; j <= xmax; j++) {
                    if (m_ditherMode) {
                        getShadeTransColDither<useCachedDither>(&vram16[(i << 10) + j], (cB1 >> 16), (cG1 >> 16),
                                                                (cR1 >> 16));
                    } else {
                        PixelWriter<false, GPU::Shading::Flat, WriteMode::Default>::scalar(
                            rs, j, i, PCSX::SoftGPU::Channel555::fromHighAlignedRGB(cR1, cG1, cB1));
                    }
                    cR1 += difR;
                    cG1 += difG;
                    cB1 += difB;
                }
            }
        }
        if (nextRow3<false, Shading == GPU::Shading::Gouraud>()) return;
    }
}

// Unified 3-vertex flat-textured rasterizer. Compile-time dispatch on the
// texture sampling mode collapses what used to be three near-identical
// functions (drawPoly3TEx4, drawPoly3TEx8, drawPoly3TD) into one body.
//
// xmax handling uses the inclusive-left / exclusive-right span
// convention: xmax = (m_rightX - 1) >> 16. A column j is drawn when
// leftX <= j*65536 < rightX, so the last drawn column is the integer
// just less than rightX in real coordinates. See the body comment
// above the 3-vert edge walker templates for the full derivation and
// the HW_VERIFIED test citations.
template <PCSX::SoftGPU::TexMode Tex>
void PCSX::SoftGPU::SoftRenderer::drawPoly3T(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                             int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                             int16_t ty3, int16_t clX, int16_t clY) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY;

    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawW = m_drawW;
    const auto drawH = m_drawH;

    const int16_t rejXs[3] = {x1, x2, x3};
    const int16_t rejYs[3] = {y1, y2, y3};
    if (primitiveOutsideDrawArea(rejXs, rejYs)) return;

    if (!setupSections3<true, false>(TriInput{{x1, x2, x3}, {y1, y2, y3}, {tx1, tx2, tx3}, {ty1, ty2, ty3}})) return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRow3<true, false>()) return;
    }

    RasterState rs = makeTexturedRasterState<Tex>(drawX, drawY, drawW, drawH, clX, clY);
    const int32_t yAdj = Sampler<Tex>::yAdjust(rs);
    difX = m_deltaRightU;
    difX2 = difX << 1;
    difY = m_deltaRightV;
    difY2 = difY << 1;

    if (!m_checkMask && !m_drawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX + 0xFFFF) >> 16;
            xmax = (m_rightX - 1) >> 16;
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = m_leftU + (int32_t)(((int64_t)(((int32_t)xmin << 16) + 0x8000 - m_leftX) * difX) >> 16);
                posY = m_leftV + (int32_t)(((int64_t)(((int32_t)xmin << 16) + 0x8000 - m_leftX) * difY) >> 16);

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }

                for (j = xmin; j < xmax; j += 2) {
                    const uint32_t color = Sampler<Tex>::packed(rs, yAdj, posX, posY, difX, difY);
                    PixelWriter<true, GPU::Shading::Flat, WriteMode::Solid>::packed(rs, j, i, color);

                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    PixelWriter<true, GPU::Shading::Flat, WriteMode::Solid>::scalar(
                        rs, j, i, Sampler<Tex>::scalar(rs, yAdj, posX, posY));
                }
            }
            if (nextRow3<true, false>()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX + 0xFFFF) >> 16;
        xmax = (m_rightX - 1) >> 16;
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = m_leftU + (int32_t)(((int64_t)(((int32_t)xmin << 16) + 0x8000 - m_leftX) * difX) >> 16);
            posY = m_leftV + (int32_t)(((int64_t)(((int32_t)xmin << 16) + 0x8000 - m_leftX) * difY) >> 16);

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }

            for (j = xmin; j < xmax; j += 2) {
                const uint32_t color = Sampler<Tex>::packed(rs, yAdj, posX, posY, difX, difY);
                PixelWriter<true, GPU::Shading::Flat, WriteMode::Default>::packed(rs, j, i, color);

                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                PixelWriter<true, GPU::Shading::Flat, WriteMode::Default>::scalar(
                    rs, j, i, Sampler<Tex>::scalar(rs, yAdj, posX, posY));
            }
        }
        if (nextRow3<true, false>()) return;
    }
}

// Explicit instantiations of drawPoly3T<TexMode> so polyExec in soft/gpu.cc
// can link against the three TexMode forms without the template body
// having to be visible in that translation unit.
template void PCSX::SoftGPU::SoftRenderer::drawPoly3T<PCSX::SoftGPU::TexMode::Clut4>(int16_t, int16_t, int16_t, int16_t,
                                                                                     int16_t, int16_t, int16_t, int16_t,
                                                                                     int16_t, int16_t, int16_t, int16_t,
                                                                                     int16_t, int16_t);
template void PCSX::SoftGPU::SoftRenderer::drawPoly3T<PCSX::SoftGPU::TexMode::Clut8>(int16_t, int16_t, int16_t, int16_t,
                                                                                     int16_t, int16_t, int16_t, int16_t,
                                                                                     int16_t, int16_t, int16_t, int16_t,
                                                                                     int16_t, int16_t);
template void PCSX::SoftGPU::SoftRenderer::drawPoly3T<PCSX::SoftGPU::TexMode::Direct15>(int16_t, int16_t, int16_t,
                                                                                        int16_t, int16_t, int16_t,
                                                                                        int16_t, int16_t, int16_t,
                                                                                        int16_t, int16_t, int16_t,
                                                                                        int16_t, int16_t);

////////////////////////////////////////////////////////////////////////
// SPRITE / TEXTURED RECTANGLE
////////////////////////////////////////////////////////////////////////

// Dedicated sprite/textured-rect rasterizer. The GP0 0x64-0x67 and
// 0x74-0x77 families always emit axis-aligned rectangles with 1:1 UV
// stepping, so there is no fractional edge or interpolation to track -
// the entire edge-walker family that drawPoly4T<Semi> previously called
// into (setupSectionsFlatTextured4 et al.) is overkill for this
// workload. Walk a clipped integer rectangle, sample the texture per
// scanline at integer (u, v), write through the texture-mode-specific
// path.
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

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3F(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                             int32_t rgb) {
    drawPoly3i<GPU::Shading::Flat, false>(x1, y1, x2, y2, x3, y3, rgb, rgb, rgb);
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3G(int16_t x0, int16_t y0, int16_t x1, int16_t y1, int16_t x2, int16_t y2,
                                             int32_t rgb1, int32_t rgb2, int32_t rgb3) {
    if (s_ditherLUT) {
        drawPoly3i<GPU::Shading::Gouraud, true>(x0, y0, x1, y1, x2, y2, rgb1, rgb2, rgb3);
    } else {
        drawPoly3i<GPU::Shading::Gouraud, false>(x0, y0, x1, y1, x2, y2, rgb1, rgb2, rgb3);
    }
}

// draw two g-shaded tris for right psx shading emulation

void PCSX::SoftGPU::SoftRenderer::drawPoly4G(int16_t x0, int16_t y0, int16_t x1, int16_t y1, int16_t x2, int16_t y2,
                                             int16_t x3, int16_t y3, int32_t rgb1, int32_t rgb2, int32_t rgb3,
                                             int32_t rgb4) {
    if (s_ditherLUT) {
        drawPoly3i<GPU::Shading::Gouraud, true>(x1, y1, x3, y3, x2, y2, rgb2, rgb4, rgb3);
        drawPoly3i<GPU::Shading::Gouraud, true>(x0, y0, x1, y1, x2, y2, rgb1, rgb2, rgb3);
    } else {
        drawPoly3i<GPU::Shading::Gouraud, false>(x1, y1, x3, y3, x2, y2, rgb2, rgb4, rgb3);
        drawPoly3i<GPU::Shading::Gouraud, false>(x0, y0, x1, y1, x2, y2, rgb1, rgb2, rgb3);
    }
}

////////////////////////////////////////////////////////////////////////

// Unified 3-vertex gouraud-textured rasterizer. Compile-time dispatch on
// texture sampling mode + cached-dither template parameter collapses what
// used to be three separate <useCachedDither>-templated functions
// (drawPoly3TGEx4i, drawPoly3TGEx8i, drawPoly3TGDi) into one body.
//
// Same xmax / fast-path / slow-path structure as drawPoly3T<TexMode>:
//   - fast path (!checkMask && !drawSemiTrans && !ditherMode) does packed
//     pair writes through PixelWriter<true, Gouraud, Solid> with per-pixel
//     gouraud-interpolated modulation
//   - slow path iterates one pixel at a time (color changes per pixel,
//     packed pair unavailable); dither branch calls the legacy
//     getTextureTransColShadeDither<useCachedDither>, non-dither branch
//     calls PixelWriter<true, Gouraud, Default>
//
// xmax handling matches the rest of the 3-vert family: inclusive-left
// / exclusive-right via `(m_rightX - 1) >> 16`. See the body comment
// above the edge walker templates for the derivation. HW_VERIFIED via
// gpu-raster-phase3 SF2/LE/QS cases on SCPH-5501.
template <PCSX::SoftGPU::TexMode Tex, bool useCachedDither>
void PCSX::SoftGPU::SoftRenderer::drawPoly3TGi(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                               int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                               int16_t ty3, int16_t clX, int16_t clY, int32_t col1, int32_t col2,
                                               int32_t col3) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t cR1, cG1, cB1;
    int32_t difR, difB, difG, difR2, difB2, difG2;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY;

    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;

    const int16_t rejXs[3] = {x1, x2, x3};
    const int16_t rejYs[3] = {y1, y2, y3};
    if (primitiveOutsideDrawArea(rejXs, rejYs)) return;

    if (!setupSections3<true, true>(
            TriInput{{x1, x2, x3}, {y1, y2, y3}, {tx1, tx2, tx3}, {ty1, ty2, ty3}, {col1, col2, col3}}))
        return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRow3<true, true>()) return;
    }

    RasterState rs = makeTexturedRasterState<Tex>(drawX, drawY, drawW, drawH, clX, clY);
    const int32_t yAdj = Sampler<Tex>::yAdjust(rs);
    const auto vram16 = rs.vram16;

    difR = m_deltaRightR;
    difG = m_deltaRightG;
    difB = m_deltaRightB;
    difR2 = difR << 1;
    difG2 = difG << 1;
    difB2 = difB << 1;
    difX = m_deltaRightU;
    difX2 = difX << 1;
    difY = m_deltaRightV;
    difY2 = difY << 1;

    if (!m_checkMask && !m_drawSemiTrans && !m_ditherMode) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX + 0xFFFF) >> 16;
            xmax = (m_rightX - 1) >> 16;
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = m_leftU;
                posY = m_leftV;
                cR1 = m_leftR;
                cG1 = m_leftG;
                cB1 = m_leftB;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                    cR1 += j * difR;
                    cG1 += j * difG;
                    cB1 += j * difB;
                }

                for (j = xmin; j < xmax; j += 2) {
                    const uint32_t color = Sampler<Tex>::packed(rs, yAdj, posX, posY, difX, difY);
                    PixelWriter<true, GPU::Shading::Gouraud, WriteMode::Solid>::packed(
                        rs, j, i, color, (cB1 >> 16) | ((cB1 + difB) & 0xff0000),
                        (cG1 >> 16) | ((cG1 + difG) & 0xff0000), (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                    posX += difX2;
                    posY += difY2;
                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax) {
                    PixelWriter<true, GPU::Shading::Gouraud, WriteMode::Solid>::scalar(
                        rs, j, i, Sampler<Tex>::scalar(rs, yAdj, posX, posY), (cB1 >> 16), (cG1 >> 16), (cR1 >> 16));
                }
            }
            if (nextRow3<true, true>()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX + 0xFFFF) >> 16;
        xmax = (m_rightX - 1) >> 16;
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = m_leftU;
            posY = m_leftV;
            cR1 = m_leftR;
            cG1 = m_leftG;
            cB1 = m_leftB;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
                cR1 += j * difR;
                cG1 += j * difG;
                cB1 += j * difB;
            }

            for (j = xmin; j <= xmax; j++) {
                const uint16_t color = Sampler<Tex>::scalar(rs, yAdj, posX, posY);
                if (m_ditherMode) {
                    getTextureTransColShadeDither<useCachedDither>(&vram16[(i << 10) + j], color, (cB1 >> 16),
                                                                   (cG1 >> 16), (cR1 >> 16));
                } else {
                    PixelWriter<true, GPU::Shading::Gouraud, WriteMode::Default>::scalar(rs, j, i, color, (cB1 >> 16),
                                                                                         (cG1 >> 16), (cR1 >> 16));
                }
                posX += difX;
                posY += difY;
                cR1 += difR;
                cG1 += difG;
                cB1 += difB;
            }
        }
        if (nextRow3<true, true>()) return;
    }
}

////////////////////////////////////////////////////////////////////////

template <PCSX::SoftGPU::TexMode Tex>
void PCSX::SoftGPU::SoftRenderer::drawPoly3TG(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                              int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                              int16_t ty3, int16_t clX, int16_t clY, int32_t col1, int32_t col2,
                                              int32_t col3) {
    if (s_ditherLUT) {
        drawPoly3TGi<Tex, true>(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3, clX, clY, col1, col2, col3);
    } else {
        drawPoly3TGi<Tex, false>(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3, clX, clY, col1, col2, col3);
    }
}

template void PCSX::SoftGPU::SoftRenderer::drawPoly3TG<PCSX::SoftGPU::TexMode::Clut4>(
    int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t,
    int16_t, int32_t, int32_t, int32_t);
template void PCSX::SoftGPU::SoftRenderer::drawPoly3TG<PCSX::SoftGPU::TexMode::Clut8>(
    int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t,
    int16_t, int32_t, int32_t, int32_t);
template void PCSX::SoftGPU::SoftRenderer::drawPoly3TG<PCSX::SoftGPU::TexMode::Direct15>(
    int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t,
    int16_t, int32_t, int32_t, int32_t);

// Unified 4-vertex gouraud-textured wrapper. Picks the cached-dither
// template parameter once and emits the two PSX-ordered triangles
// (vertices 2-3-4, then 1-2-4). Replaces drawPoly4TGEx4, drawPoly4TGEx8
// and drawPoly4TGD, which were three near-identical bodies parameterised
// only by which TexMode they routed to via the legacy i-suffix
// intermediate (drawPoly3TGEx4i / drawPoly3TGEx8i / drawPoly3TGDi).
// The new template calls drawPoly3TGi<Tex, useCachedDither> directly;
// the i-suffix intermediates stay for the matching 3-vert wrappers.
template <PCSX::SoftGPU::TexMode Tex>
void PCSX::SoftGPU::SoftRenderer::drawPoly4TG(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                              int16_t x4, int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2,
                                              int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4,
                                              int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col3,
                                              int32_t col4) {
    if (s_ditherLUT) {
        drawPoly3TGi<Tex, true>(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4, clX, clY, col2, col4, col3);
        drawPoly3TGi<Tex, true>(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4, clX, clY, col1, col2, col3);
    } else {
        drawPoly3TGi<Tex, false>(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4, clX, clY, col2, col4, col3);
        drawPoly3TGi<Tex, false>(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4, clX, clY, col1, col2, col3);
    }
}

template void PCSX::SoftGPU::SoftRenderer::drawPoly4TG<PCSX::SoftGPU::TexMode::Clut4>(
    int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t,
    int16_t, int16_t, int16_t, int16_t, int16_t, int32_t, int32_t, int32_t, int32_t);
template void PCSX::SoftGPU::SoftRenderer::drawPoly4TG<PCSX::SoftGPU::TexMode::Clut8>(
    int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t,
    int16_t, int16_t, int16_t, int16_t, int16_t, int32_t, int32_t, int32_t, int32_t);
template void PCSX::SoftGPU::SoftRenderer::drawPoly4TG<PCSX::SoftGPU::TexMode::Direct15>(
    int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t, int16_t,
    int16_t, int16_t, int16_t, int16_t, int16_t, int32_t, int32_t, int32_t, int32_t);

////////////////////////////////////////////////////////////////////////

namespace {

// Bresenham octant stepper. One template covers all four canonical octants
// the dispatcher emits after the negative-dx swap. See soft.h for the
// per-parameter contract; the bias choice is hardware-load-bearing and
// MUST track MajorAxis: shallow / X-major uses the pixel-centre 3*dy - dx,
// steep / Y-major uses the standard 2*dx - dy.
using Axis = PCSX::SoftGPU::Line::Axis;
using MajorSign = PCSX::SoftGPU::Line::MajorSign;
using MinorSign = PCSX::SoftGPU::Line::MinorSign;
using Bias = PCSX::SoftGPU::Line::Bias;

template <Axis MajorAxis, MajorSign MaSign, MinorSign MiSign, Bias B>
class LineStepper {
  public:
    LineStepper(int x0, int y0, int x1, int y1) : m_x(x0), m_y(y0) {
        int dx = x1 - x0;
        int dy = y1 - y0;
        // Historically the N_NE (Y-major negative slope) and E_NE
        // (X-major negative slope) octants each pre-negated dy so the
        // Bresenham bias and increment formulas could pretend the slope
        // was positive. The stepper does the same trick internally so
        // its callers don't have to. Whenever the minor axis steps in
        // the negative direction (X-major MinorSign::Minus, or Y-major
        // MajorSign::Minus where the minor axis is X but the steep-form
        // sign discipline routes through MajorSign), normalize dy to a
        // positive distance.
        if constexpr (MajorAxis == Axis::X && MiSign == MinorSign::Minus) {
            dy = -dy;
        } else if constexpr (MajorAxis == Axis::Y && MaSign == MajorSign::Minus) {
            dy = -dy;
        }
        if constexpr (B == Bias::Shallow) {
            // Shallow / X-major: pixel-centre biased initial.
            // Hardware-verified by phase-2 / phase-10; do not soften.
            m_d = 3 * dy - dx;
            m_incrMajor = 2 * dy;
            m_incrDiag = 2 * (dy - dx);
        } else {
            // Steep / Y-major: standard midpoint initial; already matches
            // hardware as-is.
            m_d = 2 * dx - dy;
            m_incrMajor = 2 * dx;
            m_incrDiag = 2 * (dx - dy);
        }
        m_endMajor = (MajorAxis == Axis::X) ? x1 : y1;
    }

    int x() const { return m_x; }
    int y() const { return m_y; }

    bool more() const {
        if constexpr (MajorAxis == Axis::X) {
            return m_x < m_endMajor;
        } else if constexpr (MaSign == MajorSign::Plus) {
            return m_y < m_endMajor;
        } else {
            return m_y > m_endMajor;
        }
    }

    void advance() {
        if (m_d <= 0) {
            m_d += m_incrMajor;
        } else {
            m_d += m_incrDiag;
            if constexpr (MajorAxis == Axis::X) {
                if constexpr (MiSign == MinorSign::Plus) {
                    ++m_y;
                } else {
                    --m_y;
                }
            } else {
                if constexpr (MiSign == MinorSign::Plus) {
                    ++m_x;
                } else {
                    --m_x;
                }
            }
        }
        if constexpr (MajorAxis == Axis::X) {
            ++m_x;
        } else if constexpr (MaSign == MajorSign::Plus) {
            ++m_y;
        } else {
            --m_y;
        }
    }

  private:
    int m_x;
    int m_y;
    int m_d;
    int m_incrMajor;
    int m_incrDiag;
    int m_endMajor;
};

// Per-step gouraud colour walker for shaded line rasterizers. Captures
// the per-channel deltas at construction; advanceTo(stepIdx) snaps the
// internal R/G/B back to the line-anchored linear interpolation, and
// current555() packs them into BGR555. Channels are kept in the same
// high-aligned 8.16-style layout the original octant bodies used so
// the >> 9 / >> 14 / >> 19 pack stays identical at the bit level.
// The steps==0 guard is hoisted into advanceTo() once instead of being
// repeated at every plot site.
class GouraudWalker {
  public:
    GouraudWalker(uint32_t rgb0, uint32_t rgb1, int steps)
        : m_r((rgb0 & 0x00ff0000)),
          m_g((rgb0 & 0x0000ff00) << 8),
          m_b((rgb0 & 0x000000ff) << 16),
          m_rInit(m_r),
          m_gInit(m_g),
          m_bInit(m_b),
          m_drFull((int32_t)(rgb1 & 0x00ff0000) - (int32_t)m_r),
          m_dgFull((int32_t)((rgb1 & 0x0000ff00) << 8) - (int32_t)m_g),
          m_dbFull((int32_t)((rgb1 & 0x000000ff) << 16) - (int32_t)m_b),
          m_steps(steps) {}

    void advanceTo(int stepIdx) {
        if (m_steps != 0) {
            m_r = m_rInit + (int64_t)m_drFull * stepIdx / m_steps;
            m_g = m_gInit + (int64_t)m_dgFull * stepIdx / m_steps;
            m_b = m_bInit + (int64_t)m_dbFull * stepIdx / m_steps;
        }
    }

    uint16_t current555() const { return (uint16_t)(PCSX::SoftGPU::Channel555::fromHighAlignedRGB(m_r, m_g, m_b)); }

  private:
    uint32_t m_r;
    uint32_t m_g;
    uint32_t m_b;
    uint32_t m_rInit;
    uint32_t m_gInit;
    uint32_t m_bInit;
    int32_t m_drFull;
    int32_t m_dgFull;
    int32_t m_dbFull;
    int m_steps;
};

struct FlatColor {
    FlatColor(uint16_t color_, uint16_t dummy, int dummy2) : color(color_) {}
    uint16_t current555() { return color; }
    void advanceTo(int) {}
    uint16_t color;
};

template <PCSX::GPU::Shading Shading>
using LineColorWalker = std::conditional_t<Shading == PCSX::GPU::Shading::Gouraud, GouraudWalker, FlatColor>;

}  // namespace

template <PCSX::SoftGPU::Line::Axis MajorAxis, PCSX::SoftGPU::Line::MajorSign MaSign,
          PCSX::SoftGPU::Line::MinorSign MiSign, PCSX::SoftGPU::Line::Bias B, PCSX::GPU::Shading Shading>
void PCSX::SoftGPU::SoftRenderer::drawLineOctant(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1) {
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    // Major-axis distance for the gouraud interpolation denominator.
    int steps;
    if constexpr (MajorAxis == Line::Axis::X) {
        steps = x1 - x0;
    } else if constexpr (MaSign == Line::MajorSign::Plus) {
        steps = y1 - y0;
    } else {
        steps = y0 - y1;
    }

    LineStepper<MajorAxis, MaSign, MiSign, B> stepper(x0, y0, x1, y1);
    LineColorWalker<Shading> walker(rgb0, rgb1, steps);
    RasterState rs = makeBaseRasterState();

    auto plot = [&](int x, int y) {
        if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH)) {
            PixelWriter<false, GPU::Shading::Flat, WriteMode::Default>::scalar(rs, x, y, walker.current555());
        }
    };

    plot(stepper.x(), stepper.y());
    int stepIdx = 0;
    while (stepper.more()) {
        stepper.advance();
        ++stepIdx;
        walker.advanceTo(stepIdx);
        plot(stepper.x(), stepper.y());
    }
}

///////////////////////////////////////////////////////////////////////

template <PCSX::SoftGPU::Line::Axis Iter, PCSX::GPU::Shading Shading>
void PCSX::SoftGPU::SoftRenderer::drawAxisLine(int constCoord, int varStart, int varEnd, uint32_t rgb0, uint32_t rgb1) {
    const int steps = varEnd - varStart;
    const int varStartOrig = varStart;

    LineColorWalker<Shading> walker(rgb0, rgb1, steps);

    if constexpr (Iter == Line::Axis::X) {
        if (varStart < m_drawX) varStart = m_drawX;
        if (varEnd > m_drawW) varEnd = m_drawW;
    } else {
        if (varStart < m_drawY) varStart = m_drawY;
        if (varEnd > m_drawH) varEnd = m_drawH;
    }

    RasterState rs = makeBaseRasterState();

    for (int v = varStart; v <= varEnd; ++v) {
        walker.advanceTo(v - varStartOrig);
        if constexpr (Iter == Line::Axis::X) {
            PixelWriter<false, GPU::Shading::Flat, WriteMode::Default>::scalar(rs, v, constCoord, walker.current555());
        } else {
            PixelWriter<false, GPU::Shading::Flat, WriteMode::Default>::scalar(rs, constCoord, v, walker.current555());
        }
    }
}

///////////////////////////////////////////////////////////////////////

/* Bresenham Line drawing function */
/* Bresenham Line drawing function */
template <PCSX::GPU::Shading Shading>
void PCSX::SoftGPU::SoftRenderer::drawSoftwareLine(int16_t x0, int16_t y0, int16_t x1, int16_t y1, int32_t rgb0,
                                                   int32_t rgb1) {
    int16_t xt, yt;
    double m, dy, dx;
    uint16_t color = 0;

    if (x0 > m_drawW && x1 > m_drawW) return;
    if (y0 > m_drawH && y1 > m_drawH) return;
    if (x0 < m_drawX && x1 < m_drawX) return;
    if (y0 < m_drawY && y1 < m_drawY) return;
    if (m_drawY >= m_drawH) return;
    if (m_drawX >= m_drawW) return;

    dx = x1 - x0;
    dy = y1 - y0;

    if (dx == 0) {
        if (dy == 0) {
            // Zero-length line: hardware draws exactly one pixel at the vertex.
            if ((x0 >= m_drawX) && (x0 < m_drawW) && (y0 >= m_drawY) && (y0 < m_drawH)) {
                RasterState rs = makeBaseRasterState();
                PixelWriter<false, GPU::Shading::Flat, WriteMode::Default>::scalar(rs, x0, y0, rgb0);
            }
            return;
        } else if (dy > 0) {
            drawAxisLine<Line::Axis::Y, Shading>(x0, y0, y1, rgb0, rgb1);
        } else {
            drawAxisLine<Line::Axis::Y, Shading>(x0, y1, y0, rgb0, rgb1);
        }
    } else if (dy == 0) {
        if (dx > 0) {
            drawAxisLine<Line::Axis::X, Shading>(y0, x0, x1, rgb0, rgb1);
        } else {
            drawAxisLine<Line::Axis::X, Shading>(y0, x1, x0, rgb0, rgb1);
        }
    } else {
        if (dx < 0) {
            xt = x0;
            yt = y0;
            x0 = x1;
            y0 = y1;
            x1 = xt;
            y1 = yt;

            dx = x1 - x0;
            dy = y1 - y0;
        }

        m = dy / dx;

        if (m >= 0) {
            if (m > 1) {
                drawLineOctant<Line::Axis::Y, Line::MajorSign::Plus, Line::MinorSign::Plus, Line::Bias::Steep, Shading>(
                    x0, y0, x1, y1, rgb0, rgb1);
            } else {
                drawLineOctant<Line::Axis::X, Line::MajorSign::Plus, Line::MinorSign::Plus, Line::Bias::Shallow,
                               Shading>(x0, y0, x1, y1, rgb0, rgb1);
            }
        } else if (m < -1) {
            drawLineOctant<Line::Axis::Y, Line::MajorSign::Minus, Line::MinorSign::Plus, Line::Bias::Steep, Shading>(
                x0, y0, x1, y1, rgb0, rgb1);
        } else {
            drawLineOctant<Line::Axis::X, Line::MajorSign::Plus, Line::MinorSign::Minus, Line::Bias::Shallow, Shading>(
                x0, y0, x1, y1, rgb0, rgb1);
        }
    }
}

template void PCSX::SoftGPU::SoftRenderer::drawSoftwareLine<PCSX::GPU::Shading::Flat>(int16_t x0, int16_t y0,
                                                                                      int16_t x1, int16_t y1,
                                                                                      int32_t rgb0, int32_t rgb1);
template void PCSX::SoftGPU::SoftRenderer::drawSoftwareLine<PCSX::GPU::Shading::Gouraud>(int16_t x0, int16_t y0,
                                                                                         int16_t x1, int16_t y1,
                                                                                         int32_t rgb0, int32_t rgb1);

///////////////////////////////////////////////////////////////////////
