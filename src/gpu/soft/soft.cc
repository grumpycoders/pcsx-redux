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

#include "gpu/soft/soft.h"

#define XCOL1(x) (x & 0x1f)
#define XCOL2(x) (x & 0x3e0)
#define XCOL3(x) (x & 0x7c00)

#define XCOL1D(x) (x & 0x1f)
#define XCOL2D(x) ((x >> 5) & 0x1f)
#define XCOL3D(x) ((x >> 10) & 0x1f)

#define X32TCOL1(x) ((x & 0x001f001f) << 7)
#define X32TCOL2(x) ((x & 0x03e003e0) << 2)
#define X32TCOL3(x) ((x & 0x7c007c00) >> 3)

#define X32COL1(x) (x & 0x001f001f)
#define X32COL2(x) ((x >> 5) & 0x001f001f)
#define X32COL3(x) ((x >> 10) & 0x001f001f)

#define X32ACOL1(x) (x & 0x001e001e)
#define X32ACOL2(x) ((x >> 5) & 0x001e001e)
#define X32ACOL3(x) ((x >> 10) & 0x001e001e)

#define X32BCOL1(x) (x & 0x001c001c)
#define X32BCOL2(x) ((x >> 5) & 0x001c001c)
#define X32BCOL3(x) ((x >> 10) & 0x001c001c)

#define X32PSXCOL(r, g, b) ((g << 10) | (b << 5) | r)

#define XPSXCOL(r, g, b) ((g & 0x7c00) | (b & 0x3e0) | (r & 0x1f))

static constexpr int CHKMAX_X = 1024;
static constexpr int CHKMAX_Y = 512;

////////////////////////////////////////////////////////////////////////
// special checks... nascar, syphon filter 2, mgs
////////////////////////////////////////////////////////////////////////

// xenogears FT4: not removed correctly right now... the tri 0,1,2
// should get removed, the tri 1,2,3 should stay... pfff

// x -466 1023 180 1023
// y   20 -228 222 -100

// 0 __1
//  . . .
//   2___3

bool PCSX::SoftGPU::SoftRenderer::checkCoord4() {
    if (m_x0 < 0) {
        if (((m_x1 - m_x0) > CHKMAX_X) || ((m_x2 - m_x0) > CHKMAX_X)) {
            if (m_x3 < 0) {
                if ((m_x1 - m_x3) > CHKMAX_X) return true;
                if ((m_x2 - m_x3) > CHKMAX_X) return true;
            }
        }
    }
    if (m_x1 < 0) {
        if ((m_x0 - m_x1) > CHKMAX_X) return true;
        if ((m_x2 - m_x1) > CHKMAX_X) return true;
        if ((m_x3 - m_x1) > CHKMAX_X) return true;
    }
    if (m_x2 < 0) {
        if ((m_x0 - m_x2) > CHKMAX_X) return true;
        if ((m_x1 - m_x2) > CHKMAX_X) return true;
        if ((m_x3 - m_x2) > CHKMAX_X) return true;
    }
    if (m_x3 < 0) {
        if (((m_x1 - m_x3) > CHKMAX_X) || ((m_x2 - m_x3) > CHKMAX_X)) {
            if (m_x0 < 0) {
                if ((m_x1 - m_x0) > CHKMAX_X) return true;
                if ((m_x2 - m_x0) > CHKMAX_X) return true;
            }
        }
    }

    if (m_y0 < 0) {
        if ((m_y1 - m_y0) > CHKMAX_Y) return true;
        if ((m_y2 - m_y0) > CHKMAX_Y) return true;
    }
    if (m_y1 < 0) {
        if ((m_y0 - m_y1) > CHKMAX_Y) return true;
        if ((m_y2 - m_y1) > CHKMAX_Y) return true;
        if ((m_y3 - m_y1) > CHKMAX_Y) return true;
    }
    if (m_y2 < 0) {
        if ((m_y0 - m_y2) > CHKMAX_Y) return true;
        if ((m_y1 - m_y2) > CHKMAX_Y) return true;
        if ((m_y3 - m_y2) > CHKMAX_Y) return true;
    }
    if (m_y3 < 0) {
        if ((m_y1 - m_y3) > CHKMAX_Y) return true;
        if ((m_y2 - m_y3) > CHKMAX_Y) return true;
    }

    return false;
}

bool PCSX::SoftGPU::SoftRenderer::checkCoord3() {
    if (m_x0 < 0) {
        if ((m_x1 - m_x0) > CHKMAX_X) return true;
        if ((m_x2 - m_x0) > CHKMAX_X) return true;
    }
    if (m_x1 < 0) {
        if ((m_x0 - m_x1) > CHKMAX_X) return true;
        if ((m_x2 - m_x1) > CHKMAX_X) return true;
    }
    if (m_x2 < 0) {
        if ((m_x0 - m_x2) > CHKMAX_X) return true;
        if ((m_x1 - m_x2) > CHKMAX_X) return true;
    }
    if (m_y0 < 0) {
        if ((m_y1 - m_y0) > CHKMAX_Y) return true;
        if ((m_y2 - m_y0) > CHKMAX_Y) return true;
    }
    if (m_y1 < 0) {
        if ((m_y0 - m_y1) > CHKMAX_Y) return true;
        if ((m_y2 - m_y1) > CHKMAX_Y) return true;
    }
    if (m_y2 < 0) {
        if ((m_y0 - m_y2) > CHKMAX_Y) return true;
        if ((m_y1 - m_y2) > CHKMAX_Y) return true;
    }

    return false;
}

void PCSX::SoftGPU::SoftRenderer::texturePage(GPU::TPage *prim) {
    m_globalTextAddrX = prim->tx << 6;
    m_globalTextAddrY = prim->ty << 8;

    if (m_useDither == 2) {
        m_ditherMode = 2;
    } else {
        if (prim->dither) {
            m_ditherMode = m_useDither;
        } else {
            m_ditherMode = 0;
        }
    }

    m_globalTextTP = prim->texDepth;

    m_globalTextABR = prim->blendFunction;

    m_statusRet &= ~0x07ff;               // Clear the necessary bits
    m_statusRet |= (prim->raw & 0x07ff);  // set the necessary bits
}

void PCSX::SoftGPU::SoftRenderer::twindow(GPU::TWindow *prim) {
    uint32_t YAlign, XAlign;

    m_textureWindowRaw = prim->raw & 0xfffff;

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
}

void PCSX::SoftGPU::SoftRenderer::drawingAreaStart(GPU::DrawingAreaStart *prim) {
    m_drawX = prim->x;
    m_drawY = prim->y;

    m_drawingStartRaw = prim->raw & 0xfffff;
}

void PCSX::SoftGPU::SoftRenderer::drawingAreaEnd(GPU::DrawingAreaEnd *prim) {
    m_drawW = prim->x;
    m_drawH = prim->y;

    m_drawingEndRaw = prim->raw & 0xfffff;
}

void PCSX::SoftGPU::SoftRenderer::drawingOffset(GPU::DrawingOffset *prim) {
    m_softDisplay.DrawOffset.x = prim->x;
    m_softDisplay.DrawOffset.y = prim->y;

    m_drawingOffsetRaw = prim->raw & 0x3fffff;
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

void PCSX::SoftGPU::SoftRenderer::applyOffset2() {
    m_x0 += m_softDisplay.DrawOffset.x;
    m_y0 += m_softDisplay.DrawOffset.y;
    m_x1 += m_softDisplay.DrawOffset.x;
    m_y1 += m_softDisplay.DrawOffset.y;
}

void PCSX::SoftGPU::SoftRenderer::applyOffset3() {
    m_x0 += m_softDisplay.DrawOffset.x;
    m_y0 += m_softDisplay.DrawOffset.y;
    m_x1 += m_softDisplay.DrawOffset.x;
    m_y1 += m_softDisplay.DrawOffset.y;
    m_x2 += m_softDisplay.DrawOffset.x;
    m_y2 += m_softDisplay.DrawOffset.y;
}

void PCSX::SoftGPU::SoftRenderer::applyOffset4() {
    m_x0 += m_softDisplay.DrawOffset.x;
    m_y0 += m_softDisplay.DrawOffset.y;
    m_x1 += m_softDisplay.DrawOffset.x;
    m_y1 += m_softDisplay.DrawOffset.y;
    m_x2 += m_softDisplay.DrawOffset.x;
    m_y2 += m_softDisplay.DrawOffset.y;
    m_x3 += m_softDisplay.DrawOffset.x;
    m_y3 += m_softDisplay.DrawOffset.y;
}

static constexpr uint8_t s_dithertable[16] = {7, 0, 6, 1, 2, 5, 3, 4, 1, 6, 0, 7, 4, 3, 5, 2};

void PCSX::SoftGPU::SoftRenderer::applyDither(uint16_t *pdest, uint32_t r, uint32_t g, uint32_t b, uint16_t sM) {
    uint8_t coeff;
    uint8_t rlow, glow, blow;
    int x, y;

    x = pdest - m_vram16;
    y = x >> 10;
    x -= (y << 10);

    coeff = s_dithertable[(y & 3) * 4 + (x & 3)];

    rlow = r & 7;
    glow = g & 7;
    blow = b & 7;

    r >>= 3;
    g >>= 3;
    b >>= 3;

    if ((r < 0x1F) && rlow > coeff) r++;
    if ((g < 0x1F) && glow > coeff) g++;
    if ((b < 0x1F) && blow > coeff) b++;

    *pdest = ((uint16_t)b << 10) | ((uint16_t)g << 5) | (uint16_t)r | sM;
}

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::getShadeTransColDither(uint16_t *pdest, int32_t m1, int32_t m2, int32_t m3) {
    int32_t r, g, b;

    if (m_checkMask && *pdest & 0x8000) return;

    if (m_drawSemiTrans) {
        r = ((XCOL1D(*pdest)) << 3);
        b = ((XCOL2D(*pdest)) << 3);
        g = ((XCOL3D(*pdest)) << 3);

        if (m_globalTextABR == GPU::BlendFunction::HalfBackAndHalfFront) {
            r = (r >> 1) + (m1 >> 1);
            b = (b >> 1) + (m2 >> 1);
            g = (g >> 1) + (m3 >> 1);
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

    if (r & 0x7FFFFF00) r = 0xff;
    if (b & 0x7FFFFF00) b = 0xff;
    if (g & 0x7FFFFF00) g = 0xff;

    applyDither(pdest, r, b, g, m_setMask16);
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::getShadeTransCol(uint16_t *pdest, uint16_t color) {
    if (m_checkMask && *pdest & 0x8000) return;

    if (m_drawSemiTrans) {
        int32_t r, g, b;

        if (m_globalTextABR == GPU::BlendFunction::HalfBackAndHalfFront) {
            *pdest = ((((*pdest) & 0x7bde) >> 1) + (((color)&0x7bde) >> 1)) | m_setMask16;  // 0x8000;
            return;
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackAndFullFront) {
            r = (XCOL1(*pdest)) + ((XCOL1(color)));
            b = (XCOL2(*pdest)) + ((XCOL2(color)));
            g = (XCOL3(*pdest)) + ((XCOL3(color)));
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackSubFullFront) {
            r = (XCOL1(*pdest)) - ((XCOL1(color)));
            b = (XCOL2(*pdest)) - ((XCOL2(color)));
            g = (XCOL3(*pdest)) - ((XCOL3(color)));
            if (r & 0x80000000) r = 0;
            if (b & 0x80000000) b = 0;
            if (g & 0x80000000) g = 0;
        } else {
            r = (XCOL1(*pdest)) + ((XCOL1(color)) >> 2);
            b = (XCOL2(*pdest)) + ((XCOL2(color)) >> 2);
            g = (XCOL3(*pdest)) + ((XCOL3(color)) >> 2);
        }

        if (r & 0x7FFFFFE0) r = 0x1f;
        if (b & 0x7FFFFC00) b = 0x3e0;
        if (g & 0x7FFF8000) g = 0x7c00;

        *pdest = (XPSXCOL(r, g, b)) | m_setMask16;  // 0x8000;
    } else {
        *pdest = color | m_setMask16;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::getShadeTransCol32(uint32_t *pdest, uint32_t color) {
    if (m_drawSemiTrans) {
        int32_t r, g, b;

        if (m_globalTextABR == GPU::BlendFunction::HalfBackAndHalfFront) {
            if (!m_checkMask) {
                *pdest = ((((*pdest) & 0x7bde7bde) >> 1) + (((color)&0x7bde7bde) >> 1)) | m_setMask32;  // 0x80008000;
                return;
            }
            r = (X32ACOL1(*pdest) >> 1) + ((X32ACOL1(color)) >> 1);
            b = (X32ACOL2(*pdest) >> 1) + ((X32ACOL2(color)) >> 1);
            g = (X32ACOL3(*pdest) >> 1) + ((X32ACOL3(color)) >> 1);
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackAndFullFront) {
            r = (X32COL1(*pdest)) + ((X32COL1(color)));
            b = (X32COL2(*pdest)) + ((X32COL2(color)));
            g = (X32COL3(*pdest)) + ((X32COL3(color)));
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackSubFullFront) {
            int32_t sr, sb, sg, src, sbc, sgc, c;
            src = XCOL1(color);
            sbc = XCOL2(color);
            sgc = XCOL3(color);
            c = (*pdest) >> 16;
            sr = (XCOL1(c)) - src;
            if (sr & 0x8000) sr = 0;
            sb = (XCOL2(c)) - sbc;
            if (sb & 0x8000) sb = 0;
            sg = (XCOL3(c)) - sgc;
            if (sg & 0x8000) sg = 0;
            r = ((int32_t)sr) << 16;
            b = ((int32_t)sb) << 11;
            g = ((int32_t)sg) << 6;
            c = (*pdest) & 0xffff;
            sr = (XCOL1(c)) - src;
            if (sr & 0x8000) sr = 0;
            sb = (XCOL2(c)) - sbc;
            if (sb & 0x8000) sb = 0;
            sg = (XCOL3(c)) - sgc;
            if (sg & 0x8000) sg = 0;
            r |= sr;
            b |= sb >> 5;
            g |= sg >> 10;
        } else {
            r = (X32COL1(*pdest)) + ((X32BCOL1(color)) >> 2);
            b = (X32COL2(*pdest)) + ((X32BCOL2(color)) >> 2);
            g = (X32COL3(*pdest)) + ((X32BCOL3(color)) >> 2);
        }

        if (r & 0x7FE00000) r = 0x1f0000 | (r & 0xFFFF);
        if (r & 0x7FE0) r = 0x1f | (r & 0xFFFF0000);
        if (b & 0x7FE00000) b = 0x1f0000 | (b & 0xFFFF);
        if (b & 0x7FE0) b = 0x1f | (b & 0xFFFF0000);
        if (g & 0x7FE00000) g = 0x1f0000 | (g & 0xFFFF);
        if (g & 0x7FE0) g = 0x1f | (g & 0xFFFF0000);

        if (m_checkMask) {
            uint32_t ma = *pdest;
            *pdest = (X32PSXCOL(r, g, b)) | m_setMask32;  // 0x80008000;
            if (ma & 0x80000000) *pdest = (ma & 0xFFFF0000) | (*pdest & 0xFFFF);
            if (ma & 0x00008000) *pdest = (ma & 0xFFFF) | (*pdest & 0xFFFF0000);
            return;
        }
        *pdest = (X32PSXCOL(r, g, b)) | m_setMask32;  // 0x80008000;
    } else {
        if (m_checkMask) {
            uint32_t ma = *pdest;
            *pdest = color | m_setMask32;  // 0x80008000;
            if (ma & 0x80000000) *pdest = (ma & 0xFFFF0000) | (*pdest & 0xFFFF);
            if (ma & 0x00008000) *pdest = (ma & 0xFFFF) | (*pdest & 0xFFFF0000);
            return;
        }

        *pdest = color | m_setMask32;  // 0x80008000;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::getTextureTransColShade(uint16_t *pdest, uint16_t color) {
    int32_t r, g, b;
    uint16_t l;

    if (color == 0) return;

    if (m_checkMask && *pdest & 0x8000) return;

    l = m_setMask16 | (color & 0x8000);

    if (m_drawSemiTrans && (color & 0x8000)) {
        if (m_globalTextABR == GPU::BlendFunction::HalfBackAndHalfFront) {
            uint16_t d;
            d = ((*pdest) & 0x7bde) >> 1;
            color = ((color)&0x7bde) >> 1;
            r = (XCOL1(d)) + ((((XCOL1(color))) * m_m1) >> 7);
            b = (XCOL2(d)) + ((((XCOL2(color))) * m_m2) >> 7);
            g = (XCOL3(d)) + ((((XCOL3(color))) * m_m3) >> 7);
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackAndFullFront) {
            r = (XCOL1(*pdest)) + ((((XCOL1(color))) * m_m1) >> 7);
            b = (XCOL2(*pdest)) + ((((XCOL2(color))) * m_m2) >> 7);
            g = (XCOL3(*pdest)) + ((((XCOL3(color))) * m_m3) >> 7);
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackSubFullFront) {
            r = (XCOL1(*pdest)) - ((((XCOL1(color))) * m_m1) >> 7);
            b = (XCOL2(*pdest)) - ((((XCOL2(color))) * m_m2) >> 7);
            g = (XCOL3(*pdest)) - ((((XCOL3(color))) * m_m3) >> 7);
            if (r & 0x80000000) r = 0;
            if (b & 0x80000000) b = 0;
            if (g & 0x80000000) g = 0;
        } else {
            r = (XCOL1(*pdest)) + ((((XCOL1(color)) >> 2) * m_m1) >> 7);
            b = (XCOL2(*pdest)) + ((((XCOL2(color)) >> 2) * m_m2) >> 7);
            g = (XCOL3(*pdest)) + ((((XCOL3(color)) >> 2) * m_m3) >> 7);
        }
    } else {
        r = ((XCOL1(color)) * m_m1) >> 7;
        b = ((XCOL2(color)) * m_m2) >> 7;
        g = ((XCOL3(color)) * m_m3) >> 7;
    }

    if (r & 0x7FFFFFE0) r = 0x1f;
    if (b & 0x7FFFFC00) b = 0x3e0;
    if (g & 0x7FFF8000) g = 0x7c00;

    *pdest = (XPSXCOL(r, g, b)) | l;
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SoftGPU::SoftRenderer::getTextureTransColShadeSolid(uint16_t *pdest, uint16_t color) {
    int32_t r, g, b;
    uint16_t l;

    if (color == 0) return;

    l = m_setMask16 | (color & 0x8000);

    r = ((XCOL1(color)) * m_m1) >> 7;
    b = ((XCOL2(color)) * m_m2) >> 7;
    g = ((XCOL3(color)) * m_m3) >> 7;

    if (r & 0x7FFFFFE0) r = 0x1f;
    if (b & 0x7FFFFC00) b = 0x3e0;
    if (g & 0x7FFF8000) g = 0x7c00;

    *pdest = (XPSXCOL(r, g, b)) | l;
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
            uint16_t d;
            d = ((*pdest) & 0x7bde) >> 1;
            color = ((color)&0x7bde) >> 1;
            r = (XCOL1(d)) + ((((XCOL1(color))) * m_m1) >> 7);
            b = (XCOL2(d)) + ((((XCOL2(color))) * m_m2) >> 7);
            g = (XCOL3(d)) + ((((XCOL3(color))) * m_m3) >> 7);
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackAndFullFront) {
            r = (XCOL1(*pdest)) + ((((XCOL1(color))) * m_m1) >> 7);
            b = (XCOL2(*pdest)) + ((((XCOL2(color))) * m_m2) >> 7);
            g = (XCOL3(*pdest)) + ((((XCOL3(color))) * m_m3) >> 7);
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackSubFullFront) {
            r = (XCOL1(*pdest)) - ((((XCOL1(color))) * m_m1) >> 7);
            b = (XCOL2(*pdest)) - ((((XCOL2(color))) * m_m2) >> 7);
            g = (XCOL3(*pdest)) - ((((XCOL3(color))) * m_m3) >> 7);
            if (r & 0x80000000) r = 0;
            if (b & 0x80000000) b = 0;
            if (g & 0x80000000) g = 0;
        } else {
            r = (XCOL1(*pdest)) + ((((XCOL1(color)) >> 2) * m_m1) >> 7);
            b = (XCOL2(*pdest)) + ((((XCOL2(color)) >> 2) * m_m2) >> 7);
            g = (XCOL3(*pdest)) + ((((XCOL3(color)) >> 2) * m_m3) >> 7);
        }
    } else {
        r = ((XCOL1(color)) * m_m1) >> 7;
        b = ((XCOL2(color)) * m_m2) >> 7;
        g = ((XCOL3(color)) * m_m3) >> 7;
    }

    if (r & 0x7FFFFFE0) r = 0x1f;
    if (b & 0x7FFFFC00) b = 0x3e0;
    if (g & 0x7FFF8000) g = 0x7c00;

    *pdest = (XPSXCOL(r, g, b)) | l;
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::getTextureTransColShade32(uint32_t *pdest, uint32_t color) {
    int32_t r, g, b, l;

    if (color == 0) return;

    l = m_setMask32 | (color & 0x80008000);

    if (m_drawSemiTrans && (color & 0x80008000)) {
        if (m_globalTextABR == GPU::BlendFunction::HalfBackAndHalfFront) {
            r = ((((X32TCOL1(*pdest)) + ((X32COL1(color)) * m_m1)) & 0xFF00FF00) >> 8);
            b = ((((X32TCOL2(*pdest)) + ((X32COL2(color)) * m_m2)) & 0xFF00FF00) >> 8);
            g = ((((X32TCOL3(*pdest)) + ((X32COL3(color)) * m_m3)) & 0xFF00FF00) >> 8);
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackAndFullFront) {
            r = (X32COL1(*pdest)) + (((((X32COL1(color))) * m_m1) & 0xFF80FF80) >> 7);
            b = (X32COL2(*pdest)) + (((((X32COL2(color))) * m_m2) & 0xFF80FF80) >> 7);
            g = (X32COL3(*pdest)) + (((((X32COL3(color))) * m_m3) & 0xFF80FF80) >> 7);
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackSubFullFront) {
            int32_t t;
            r = (((((X32COL1(color))) * m_m1) & 0xFF80FF80) >> 7);
            t = (*pdest & 0x001f0000) - (r & 0x003f0000);
            if (t & 0x80000000) t = 0;
            r = (*pdest & 0x0000001f) - (r & 0x0000003f);
            if (r & 0x80000000) r = 0;
            r |= t;

            b = (((((X32COL2(color))) * m_m2) & 0xFF80FF80) >> 7);
            t = ((*pdest >> 5) & 0x001f0000) - (b & 0x003f0000);
            if (t & 0x80000000) t = 0;
            b = ((*pdest >> 5) & 0x0000001f) - (b & 0x0000003f);
            if (b & 0x80000000) b = 0;
            b |= t;

            g = (((((X32COL3(color))) * m_m3) & 0xFF80FF80) >> 7);
            t = ((*pdest >> 10) & 0x001f0000) - (g & 0x003f0000);
            if (t & 0x80000000) t = 0;
            g = ((*pdest >> 10) & 0x0000001f) - (g & 0x0000003f);
            if (g & 0x80000000) g = 0;
            g |= t;
        } else {
            r = (X32COL1(*pdest)) + (((((X32BCOL1(color)) >> 2) * m_m1) & 0xFF80FF80) >> 7);
            b = (X32COL2(*pdest)) + (((((X32BCOL2(color)) >> 2) * m_m2) & 0xFF80FF80) >> 7);
            g = (X32COL3(*pdest)) + (((((X32BCOL3(color)) >> 2) * m_m3) & 0xFF80FF80) >> 7);
        }

        if (!(color & 0x8000)) {
            r = (r & 0xffff0000) | ((((X32COL1(color)) * m_m1) & 0x0000FF80) >> 7);
            b = (b & 0xffff0000) | ((((X32COL2(color)) * m_m2) & 0x0000FF80) >> 7);
            g = (g & 0xffff0000) | ((((X32COL3(color)) * m_m3) & 0x0000FF80) >> 7);
        }
        if (!(color & 0x80000000)) {
            r = (r & 0xffff) | ((((X32COL1(color)) * m_m1) & 0xFF800000) >> 7);
            b = (b & 0xffff) | ((((X32COL2(color)) * m_m2) & 0xFF800000) >> 7);
            g = (g & 0xffff) | ((((X32COL3(color)) * m_m3) & 0xFF800000) >> 7);
        }

    } else {
        r = (((X32COL1(color)) * m_m1) & 0xFF80FF80) >> 7;
        b = (((X32COL2(color)) * m_m2) & 0xFF80FF80) >> 7;
        g = (((X32COL3(color)) * m_m3) & 0xFF80FF80) >> 7;
    }

    if (r & 0x7FE00000) r = 0x1f0000 | (r & 0xFFFF);
    if (r & 0x7FE0) r = 0x1f | (r & 0xFFFF0000);
    if (b & 0x7FE00000) b = 0x1f0000 | (b & 0xFFFF);
    if (b & 0x7FE0) b = 0x1f | (b & 0xFFFF0000);
    if (g & 0x7FE00000) g = 0x1f0000 | (g & 0xFFFF);
    if (g & 0x7FE0) g = 0x1f | (g & 0xFFFF0000);

    if (m_checkMask) {
        uint32_t ma = *pdest;

        *pdest = (X32PSXCOL(r, g, b)) | l;

        if ((color & 0xffff) == 0) *pdest = (ma & 0xffff) | (*pdest & 0xffff0000);
        if ((color & 0xffff0000) == 0) *pdest = (ma & 0xffff0000) | (*pdest & 0xffff);
        if (ma & 0x80000000) *pdest = (ma & 0xFFFF0000) | (*pdest & 0xFFFF);
        if (ma & 0x00008000) *pdest = (ma & 0xFFFF) | (*pdest & 0xFFFF0000);

        return;
    }
    if ((color & 0xffff) == 0) {
        *pdest = (*pdest & 0xffff) | (((X32PSXCOL(r, g, b)) | l) & 0xffff0000);
        return;
    }
    if ((color & 0xffff0000) == 0) {
        *pdest = (*pdest & 0xffff0000) | (((X32PSXCOL(r, g, b)) | l) & 0xffff);
        return;
    }

    *pdest = (X32PSXCOL(r, g, b)) | l;
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::getTextureTransColShade32Solid(uint32_t *pdest, uint32_t color) {
    int32_t r, g, b;

    if (color == 0) return;

    r = (((X32COL1(color)) * m_m1) & 0xFF80FF80) >> 7;
    b = (((X32COL2(color)) * m_m2) & 0xFF80FF80) >> 7;
    g = (((X32COL3(color)) * m_m3) & 0xFF80FF80) >> 7;

    if (r & 0x7FE00000) r = 0x1f0000 | (r & 0xFFFF);
    if (r & 0x7FE0) r = 0x1f | (r & 0xFFFF0000);
    if (b & 0x7FE00000) b = 0x1f0000 | (b & 0xFFFF);
    if (b & 0x7FE0) b = 0x1f | (b & 0xFFFF0000);
    if (g & 0x7FE00000) g = 0x1f0000 | (g & 0xFFFF);
    if (g & 0x7FE0) g = 0x1f | (g & 0xFFFF0000);

    if ((color & 0xffff) == 0) {
        *pdest = (*pdest & 0xffff) | (((X32PSXCOL(r, g, b)) | m_setMask32 | (color & 0x80008000)) & 0xffff0000);
        return;
    }
    if ((color & 0xffff0000) == 0) {
        *pdest = (*pdest & 0xffff0000) | (((X32PSXCOL(r, g, b)) | m_setMask32 | (color & 0x80008000)) & 0xffff);
        return;
    }

    *pdest = (X32PSXCOL(r, g, b)) | m_setMask32 | (color & 0x80008000);
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::getTextureTransColG32Semi(uint32_t *pdest, uint32_t color) {
    int32_t r, g, b;

    if (color == 0) return;

    if (m_drawSemiTrans && (color & 0x80008000)) {
        if (m_globalTextABR == GPU::BlendFunction::HalfBackAndHalfFront) {
            r = ((((X32TCOL1(*pdest)) + ((X32COL1(color)) * m_m1)) & 0xFF00FF00) >> 8);
            b = ((((X32TCOL2(*pdest)) + ((X32COL2(color)) * m_m2)) & 0xFF00FF00) >> 8);
            g = ((((X32TCOL3(*pdest)) + ((X32COL3(color)) * m_m3)) & 0xFF00FF00) >> 8);
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackAndFullFront) {
            r = (X32COL1(*pdest)) + (((((X32COL1(color))) * m_m1) & 0xFF80FF80) >> 7);
            b = (X32COL2(*pdest)) + (((((X32COL2(color))) * m_m2) & 0xFF80FF80) >> 7);
            g = (X32COL3(*pdest)) + (((((X32COL3(color))) * m_m3) & 0xFF80FF80) >> 7);
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackSubFullFront) {
            int32_t t;
            r = (((((X32COL1(color))) * m_m1) & 0xFF80FF80) >> 7);
            t = (*pdest & 0x001f0000) - (r & 0x003f0000);
            if (t & 0x80000000) t = 0;
            r = (*pdest & 0x0000001f) - (r & 0x0000003f);
            if (r & 0x80000000) r = 0;
            r |= t;

            b = (((((X32COL2(color))) * m_m2) & 0xFF80FF80) >> 7);
            t = ((*pdest >> 5) & 0x001f0000) - (b & 0x003f0000);
            if (t & 0x80000000) t = 0;
            b = ((*pdest >> 5) & 0x0000001f) - (b & 0x0000003f);
            if (b & 0x80000000) b = 0;
            b |= t;

            g = (((((X32COL3(color))) * m_m3) & 0xFF80FF80) >> 7);
            t = ((*pdest >> 10) & 0x001f0000) - (g & 0x003f0000);
            if (t & 0x80000000) t = 0;
            g = ((*pdest >> 10) & 0x0000001f) - (g & 0x0000003f);
            if (g & 0x80000000) g = 0;
            g |= t;
        } else {
            r = (X32COL1(*pdest)) + (((((X32BCOL1(color)) >> 2) * m_m1) & 0xFF80FF80) >> 7);
            b = (X32COL2(*pdest)) + (((((X32BCOL2(color)) >> 2) * m_m2) & 0xFF80FF80) >> 7);
            g = (X32COL3(*pdest)) + (((((X32BCOL3(color)) >> 2) * m_m3) & 0xFF80FF80) >> 7);
        }

        if (!(color & 0x8000)) {
            r = (r & 0xffff0000) | ((((X32COL1(color)) * m_m1) & 0x0000FF80) >> 7);
            b = (b & 0xffff0000) | ((((X32COL2(color)) * m_m2) & 0x0000FF80) >> 7);
            g = (g & 0xffff0000) | ((((X32COL3(color)) * m_m3) & 0x0000FF80) >> 7);
        }
        if (!(color & 0x80000000)) {
            r = (r & 0xffff) | ((((X32COL1(color)) * m_m1) & 0xFF800000) >> 7);
            b = (b & 0xffff) | ((((X32COL2(color)) * m_m2) & 0xFF800000) >> 7);
            g = (g & 0xffff) | ((((X32COL3(color)) * m_m3) & 0xFF800000) >> 7);
        }

    } else {
        r = (((X32COL1(color)) * m_m1) & 0xFF80FF80) >> 7;
        b = (((X32COL2(color)) * m_m2) & 0xFF80FF80) >> 7;
        g = (((X32COL3(color)) * m_m3) & 0xFF80FF80) >> 7;
    }

    if (r & 0x7FE00000) r = 0x1f0000 | (r & 0xFFFF);
    if (r & 0x7FE0) r = 0x1f | (r & 0xFFFF0000);
    if (b & 0x7FE00000) b = 0x1f0000 | (b & 0xFFFF);
    if (b & 0x7FE0) b = 0x1f | (b & 0xFFFF0000);
    if (g & 0x7FE00000) g = 0x1f0000 | (g & 0xFFFF);
    if (g & 0x7FE0) g = 0x1f | (g & 0xFFFF0000);

    if (m_checkMask) {
        uint32_t ma = *pdest;

        *pdest = (X32PSXCOL(r, g, b)) | m_setMask32 | (color & 0x80008000);

        if ((color & 0xffff) == 0) *pdest = (ma & 0xffff) | (*pdest & 0xffff0000);
        if ((color & 0xffff0000) == 0) *pdest = (ma & 0xffff0000) | (*pdest & 0xffff);
        if (ma & 0x80000000) *pdest = (ma & 0xFFFF0000) | (*pdest & 0xFFFF);
        if (ma & 0x00008000) *pdest = (ma & 0xFFFF) | (*pdest & 0xFFFF0000);

        return;
    }
    if ((color & 0xffff) == 0) {
        *pdest = (*pdest & 0xffff) | (((X32PSXCOL(r, g, b)) | m_setMask32 | (color & 0x80008000)) & 0xffff0000);
        return;
    }
    if ((color & 0xffff0000) == 0) {
        *pdest = (*pdest & 0xffff0000) | (((X32PSXCOL(r, g, b)) | m_setMask32 | (color & 0x80008000)) & 0xffff);
        return;
    }

    *pdest = (X32PSXCOL(r, g, b)) | m_setMask32 | (color & 0x80008000);
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::getTextureTransColShadeXDither(uint16_t *pdest, uint16_t color, int32_t m1,
                                                                 int32_t m2, int32_t m3) {
    int32_t r, g, b;

    if (color == 0) return;

    if (m_checkMask && *pdest & 0x8000) return;

    m1 = (((XCOL1D(color))) * m1) >> 4;
    m2 = (((XCOL2D(color))) * m2) >> 4;
    m3 = (((XCOL3D(color))) * m3) >> 4;

    if (m_drawSemiTrans && (color & 0x8000)) {
        r = ((XCOL1D(*pdest)) << 3);
        b = ((XCOL2D(*pdest)) << 3);
        g = ((XCOL3D(*pdest)) << 3);

        if (m_globalTextABR == GPU::BlendFunction::HalfBackAndHalfFront) {
            r = (r >> 1) + (m1 >> 1);
            b = (b >> 1) + (m2 >> 1);
            g = (g >> 1) + (m3 >> 1);
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

    if (r & 0x7FFFFF00) r = 0xff;
    if (b & 0x7FFFFF00) b = 0xff;
    if (g & 0x7FFFFF00) g = 0xff;

    applyDither(pdest, r, b, g, m_setMask16 | (color & 0x8000));
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::getTextureTransColShadeX(uint16_t *pdest, uint16_t color, int16_t m1, int16_t m2,
                                                           int16_t m3) {
    int32_t r, g, b;
    uint16_t l;

    if (color == 0) return;

    if (m_checkMask && *pdest & 0x8000) return;

    l = m_setMask16 | (color & 0x8000);

    if (m_drawSemiTrans && (color & 0x8000)) {
        if (m_globalTextABR == GPU::BlendFunction::HalfBackAndHalfFront) {
            uint16_t d;
            d = ((*pdest) & 0x7bde) >> 1;
            color = ((color)&0x7bde) >> 1;
            r = (XCOL1(d)) + ((((XCOL1(color))) * m1) >> 7);
            b = (XCOL2(d)) + ((((XCOL2(color))) * m2) >> 7);
            g = (XCOL3(d)) + ((((XCOL3(color))) * m3) >> 7);
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackAndFullFront) {
            r = (XCOL1(*pdest)) + ((((XCOL1(color))) * m1) >> 7);
            b = (XCOL2(*pdest)) + ((((XCOL2(color))) * m2) >> 7);
            g = (XCOL3(*pdest)) + ((((XCOL3(color))) * m3) >> 7);
        } else if (m_globalTextABR == GPU::BlendFunction::FullBackSubFullFront) {
            r = (XCOL1(*pdest)) - ((((XCOL1(color))) * m1) >> 7);
            b = (XCOL2(*pdest)) - ((((XCOL2(color))) * m2) >> 7);
            g = (XCOL3(*pdest)) - ((((XCOL3(color))) * m3) >> 7);
            if (r & 0x80000000) r = 0;
            if (b & 0x80000000) b = 0;
            if (g & 0x80000000) g = 0;
        } else {
            r = (XCOL1(*pdest)) + ((((XCOL1(color)) >> 2) * m1) >> 7);
            b = (XCOL2(*pdest)) + ((((XCOL2(color)) >> 2) * m2) >> 7);
            g = (XCOL3(*pdest)) + ((((XCOL3(color)) >> 2) * m3) >> 7);
        }
    } else {
        r = ((XCOL1(color)) * m1) >> 7;
        b = ((XCOL2(color)) * m2) >> 7;
        g = ((XCOL3(color)) * m3) >> 7;
    }

    if (r & 0x7FFFFFE0) r = 0x1f;
    if (b & 0x7FFFFC00) b = 0x3e0;
    if (g & 0x7FFF8000) g = 0x7c00;

    *pdest = (XPSXCOL(r, g, b)) | l;
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SoftGPU::SoftRenderer::getTextureTransColShadeXSolid(uint16_t *pdest, uint16_t color, int16_t m1,
                                                                       int16_t m2, int16_t m3) {
    int32_t r, g, b;

    if (color == 0) return;

    r = ((XCOL1(color)) * m1) >> 7;
    b = ((XCOL2(color)) * m2) >> 7;
    g = ((XCOL3(color)) * m3) >> 7;

    if (r & 0x7FFFFFE0) r = 0x1f;
    if (b & 0x7FFFFC00) b = 0x3e0;
    if (g & 0x7FFF8000) g = 0x7c00;

    *pdest = (XPSXCOL(r, g, b)) | m_setMask16 | (color & 0x8000);
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SoftGPU::SoftRenderer::getTextureTransColShadeX32Solid(uint32_t *pdest, uint32_t color, int16_t m1,
                                                                         int16_t m2, int16_t m3) {
    int32_t r, g, b;

    if (color == 0) return;

    r = (((X32COL1(color)) * m1) & 0xFF80FF80) >> 7;
    b = (((X32COL2(color)) * m2) & 0xFF80FF80) >> 7;
    g = (((X32COL3(color)) * m3) & 0xFF80FF80) >> 7;

    if (r & 0x7FE00000) r = 0x1f0000 | (r & 0xFFFF);
    if (r & 0x7FE0) r = 0x1f | (r & 0xFFFF0000);
    if (b & 0x7FE00000) b = 0x1f0000 | (b & 0xFFFF);
    if (b & 0x7FE0) b = 0x1f | (b & 0xFFFF0000);
    if (g & 0x7FE00000) g = 0x1f0000 | (g & 0xFFFF);
    if (g & 0x7FE0) g = 0x1f | (g & 0xFFFF0000);

    if ((color & 0xffff) == 0) {
        *pdest = (*pdest & 0xffff) | (((X32PSXCOL(r, g, b)) | m_setMask32 | (color & 0x80008000)) & 0xffff0000);
        return;
    }
    if ((color & 0xffff0000) == 0) {
        *pdest = (*pdest & 0xffff0000) | (((X32PSXCOL(r, g, b)) | m_setMask32 | (color & 0x80008000)) & 0xffff);
        return;
    }

    *pdest = (X32PSXCOL(r, g, b)) | m_setMask32 | (color & 0x80008000);
}

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

    if (y0 >= GPU_HEIGHT) return;
    if (x0 > 1023) return;

    if (y1 > GPU_HEIGHT) y1 = GPU_HEIGHT;
    if (x1 > 1024) x1 = 1024;

    dx = x1 - x0;
    dy = y1 - y0;

    if (dx == 1 && dy == 1 && x0 == 1020 && y0 == 511) {
        // interlace hack - fix me
        static int iCheat = 0;
        col += iCheat;
        iCheat ^= 1;
    }

    if (dx & 1) {
        // slow fill
        uint16_t *DSTPtr;
        uint16_t LineOffset;
        DSTPtr = m_vram16 + (1024 * y0) + x0;
        LineOffset = 1024 - dx;
        for (i = 0; i < dy; i++) {
            for (j = 0; j < dx; j++) getShadeTransCol(DSTPtr++, col);
            DSTPtr += LineOffset;
        }
    } else {
        // fast fill
        uint32_t *DSTPtr;
        uint16_t LineOffset;
        uint32_t lcol = m_setMask32 | (((uint32_t)(col)) << 16) | col;
        dx >>= 1;
        DSTPtr = (uint32_t *)(m_vram16 + (1024 * y0) + x0);
        LineOffset = 512 - dx;

        if (!m_checkMask && !m_drawSemiTrans) {
            for (i = 0; i < dy; i++) {
                for (j = 0; j < dx; j++) *DSTPtr++ = lcol;
                DSTPtr += LineOffset;
            }
        } else {
            for (i = 0; i < dy; i++) {
                for (j = 0; j < dx; j++) getShadeTransCol32(DSTPtr++, lcol);
                DSTPtr += LineOffset;
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::fillSoftwareArea(int16_t x0, int16_t y0, int16_t x1, int16_t y1, uint16_t col) {
    int16_t j, i, dx, dy;

    if (y0 > y1) return;
    if (x0 > x1) return;

    if (y0 >= GPU_HEIGHT) return;
    if (x0 > 1023) return;

    if (y1 > GPU_HEIGHT) y1 = GPU_HEIGHT;
    if (x1 > 1024) x1 = 1024;

    dx = x1 - x0;
    dy = y1 - y0;
    if (dx & 1) {
        uint16_t *DSTPtr;
        uint16_t LineOffset;

        DSTPtr = m_vram16 + (1024 * y0) + x0;
        LineOffset = 1024 - dx;

        for (i = 0; i < dy; i++) {
            for (j = 0; j < dx; j++) *DSTPtr++ = col;
            DSTPtr += LineOffset;
        }
    } else {
        uint32_t *DSTPtr;
        uint16_t LineOffset;
        uint32_t lcol = (((int32_t)col) << 16) | col;

        dx >>= 1;
        DSTPtr = (uint32_t *)(m_vram16 + (1024 * y0) + x0);
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

int PCSX::SoftGPU::SoftRenderer::rightSectionFlat3() {
    SoftVertex *v1 = m_rightArray[m_rightSection];
    SoftVertex *v2 = m_rightArray[m_rightSection - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    m_deltaRightX = (v2->x - v1->x) / height;
    m_rightX = v1->x;

    m_rightSectionHeight = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

int PCSX::SoftGPU::SoftRenderer::leftSectionFlat3() {
    SoftVertex *v1 = m_leftArray[m_leftSection];
    SoftVertex *v2 = m_leftArray[m_leftSection - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    m_deltaLeftX = (v2->x - v1->x) / height;
    m_leftX = v1->x;

    m_leftSectionHeight = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

bool PCSX::SoftGPU::SoftRenderer::nextRowFlat3() {
    if (--m_leftSectionHeight <= 0) {
        if (--m_leftSection <= 0) {
            return true;
        }
        if (leftSectionFlat3() <= 0) {
            return true;
        }
    } else {
        m_leftX += m_deltaLeftX;
    }

    if (--m_rightSectionHeight <= 0) {
        if (--m_rightSection <= 0) {
            return true;
        }
        if (rightSectionFlat3() <= 0) {
            return true;
        }
    } else {
        m_rightX += m_deltaRightX;
    }
    return false;
}

////////////////////////////////////////////////////////////////////////

bool PCSX::SoftGPU::SoftRenderer::setupSectionsFlat3(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                     int16_t y3) {
    SoftVertex *v1, *v2, *v3;
    int height, int32_test;

    v1 = m_vtx;
    v1->x = x1 << 16;
    v1->y = y1;
    v2 = m_vtx + 1;
    v2->x = x2 << 16;
    v2->y = y2;
    v3 = m_vtx + 2;
    v3->x = x3 << 16;
    v3->y = y3;

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

    height = v3->y - v1->y;
    if (height == 0) {
        return false;
    }
    int32_test = (((v2->y - v1->y) << 16) / height) * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
    if (int32_test == 0) {
        return false;
    }

    if (int32_test < 0) {
        m_rightArray[0] = v3;
        m_rightArray[1] = v2;
        m_rightArray[2] = v1;
        m_rightSection = 2;
        m_leftArray[0] = v3;
        m_leftArray[1] = v1;
        m_leftSection = 1;

        if (leftSectionFlat3() <= 0) return false;
        if (rightSectionFlat3() <= 0) {
            m_rightSection--;
            if (rightSectionFlat3() <= 0) return false;
        }
    } else {
        m_leftArray[0] = v3;
        m_leftArray[1] = v2;
        m_leftArray[2] = v1;
        m_leftSection = 2;
        m_rightArray[0] = v3;
        m_rightArray[1] = v1;
        m_rightSection = 1;

        if (rightSectionFlat3() <= 0) return false;
        if (leftSectionFlat3() <= 0) {
            m_leftSection--;
            if (leftSectionFlat3() <= 0) return false;
        }
    }

    m_yMin = v1->y;
    m_yMax = std::min(v3->y - 1, m_drawH);

    return true;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

int PCSX::SoftGPU::SoftRenderer::rightSectionShade3() {
    SoftVertex *v1 = m_rightArray[m_rightSection];
    SoftVertex *v2 = m_rightArray[m_rightSection - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    m_deltaRightX = (v2->x - v1->x) / height;
    m_rightX = v1->x;

    m_rightSectionHeight = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

int PCSX::SoftGPU::SoftRenderer::leftSectionShade3() {
    SoftVertex *v1 = m_leftArray[m_leftSection];
    SoftVertex *v2 = m_leftArray[m_leftSection - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    m_deltaLeftX = (v2->x - v1->x) / height;
    m_leftX = v1->x;

    deltaLeftR = ((v2->R - v1->R)) / height;
    m_leftR = v1->R;
    m_deltaLeftG = ((v2->G - v1->G)) / height;
    m_leftG = v1->G;
    m_deltaLeftB = ((v2->B - v1->B)) / height;
    m_leftB = v1->B;

    m_leftSectionHeight = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

bool PCSX::SoftGPU::SoftRenderer::nextRowShade3() {
    if (--m_leftSectionHeight <= 0) {
        if (--m_leftSection <= 0) return true;
        if (leftSectionShade3() <= 0) return true;
    } else {
        m_leftX += m_deltaLeftX;
        m_leftR += deltaLeftR;
        m_leftG += m_deltaLeftG;
        m_leftB += m_deltaLeftB;
    }

    if (--m_rightSectionHeight <= 0) {
        if (--m_rightSection <= 0) return true;
        if (rightSectionShade3() <= 0) return true;
    } else {
        m_rightX += m_deltaRightX;
    }
    return false;
}

////////////////////////////////////////////////////////////////////////

bool PCSX::SoftGPU::SoftRenderer::setupSectionsShade3(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                      int16_t y3, int32_t rgb1, int32_t rgb2, int32_t rgb3) {
    SoftVertex *v1, *v2, *v3;
    int height, int32_test, temp;

    v1 = m_vtx;
    v1->x = x1 << 16;
    v1->y = y1;
    v1->R = (rgb1)&0x00ff0000;
    v1->G = (rgb1 << 8) & 0x00ff0000;
    v1->B = (rgb1 << 16) & 0x00ff0000;
    v2 = m_vtx + 1;
    v2->x = x2 << 16;
    v2->y = y2;
    v2->R = (rgb2)&0x00ff0000;
    v2->G = (rgb2 << 8) & 0x00ff0000;
    v2->B = (rgb2 << 16) & 0x00ff0000;
    v3 = m_vtx + 2;
    v3->x = x3 << 16;
    v3->y = y3;
    v3->R = (rgb3)&0x00ff0000;
    v3->G = (rgb3 << 8) & 0x00ff0000;
    v3->B = (rgb3 << 16) & 0x00ff0000;

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

    height = v3->y - v1->y;
    if (height == 0) return false;
    temp = (((v2->y - v1->y) << 16) / height);
    int32_test = temp * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
    if (int32_test == 0) return false;

    if (int32_test < 0) {
        m_rightArray[0] = v3;
        m_rightArray[1] = v2;
        m_rightArray[2] = v1;
        m_rightSection = 2;
        m_leftArray[0] = v3;
        m_leftArray[1] = v1;
        m_leftSection = 1;

        if (leftSectionShade3() <= 0) return false;
        if (rightSectionShade3() <= 0) {
            m_rightSection--;
            if (rightSectionShade3() <= 0) return false;
        }
        if (int32_test > -0x1000) int32_test = -0x1000;
    } else {
        m_leftArray[0] = v3;
        m_leftArray[1] = v2;
        m_leftArray[2] = v1;
        m_leftSection = 2;
        m_rightArray[0] = v3;
        m_rightArray[1] = v1;
        m_rightSection = 1;

        if (rightSectionShade3() <= 0) return false;
        if (leftSectionShade3() <= 0) {
            m_leftSection--;
            if (leftSectionShade3() <= 0) return false;
        }
        if (int32_test < 0x1000) int32_test = 0x1000;
    }

    m_yMin = v1->y;
    m_yMax = std::min(v3->y - 1, m_drawH);

    m_deltaRightR = shl10idiv(temp * ((v3->R - v1->R) >> 10) + ((v1->R - v2->R) << 6), int32_test);
    m_deltaRightG = shl10idiv(temp * ((v3->G - v1->G) >> 10) + ((v1->G - v2->G) << 6), int32_test);
    m_deltaRightB = shl10idiv(temp * ((v3->B - v1->B) >> 10) + ((v1->B - v2->B) << 6), int32_test);

    return true;
}

////////////////////////////////////////////////////////////////////////

int PCSX::SoftGPU::SoftRenderer::rightSectionFlatTextured3() {
    SoftVertex *v1 = m_rightArray[m_rightSection];
    SoftVertex *v2 = m_rightArray[m_rightSection - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    m_deltaRightX = (v2->x - v1->x) / height;
    m_rightX = v1->x;

    m_rightSectionHeight = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

int PCSX::SoftGPU::SoftRenderer::leftSectionFlatTextured3() {
    SoftVertex *v1 = m_leftArray[m_leftSection];
    SoftVertex *v2 = m_leftArray[m_leftSection - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    m_deltaLeftX = (v2->x - v1->x) / height;
    m_leftX = v1->x;

    m_deltaLeftU = ((v2->u - v1->u)) / height;
    m_leftU = v1->u;
    m_deltaLeftV = ((v2->v - v1->v)) / height;
    m_leftV = v1->v;

    m_leftSectionHeight = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

bool PCSX::SoftGPU::SoftRenderer::nextRowFlatTextured3() {
    if (--m_leftSectionHeight <= 0) {
        if (--m_leftSection <= 0) return true;
        if (leftSectionFlatTextured3() <= 0) return true;
    } else {
        m_leftX += m_deltaLeftX;
        m_leftU += m_deltaLeftU;
        m_leftV += m_deltaLeftV;
    }

    if (--m_rightSectionHeight <= 0) {
        if (--m_rightSection <= 0) return true;
        if (rightSectionFlatTextured3() <= 0) return true;
    } else {
        m_rightX += m_deltaRightX;
    }
    return false;
}

////////////////////////////////////////////////////////////////////////

bool PCSX::SoftGPU::SoftRenderer::setupSectionsFlatTextured3(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                             int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                                                             int16_t ty2, int16_t tx3, int16_t ty3) {
    SoftVertex *v1, *v2, *v3;
    int height, int32_test, temp;

    v1 = m_vtx;
    v1->x = x1 << 16;
    v1->y = y1;
    v1->u = tx1 << 16;
    v1->v = ty1 << 16;
    v2 = m_vtx + 1;
    v2->x = x2 << 16;
    v2->y = y2;
    v2->u = tx2 << 16;
    v2->v = ty2 << 16;
    v3 = m_vtx + 2;
    v3->x = x3 << 16;
    v3->y = y3;
    v3->u = tx3 << 16;
    v3->v = ty3 << 16;

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

    height = v3->y - v1->y;
    if (height == 0) return false;

    temp = (((v2->y - v1->y) << 16) / height);
    int32_test = temp * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);

    if (int32_test == 0) return false;

    if (int32_test < 0) {
        m_rightArray[0] = v3;
        m_rightArray[1] = v2;
        m_rightArray[2] = v1;
        m_rightSection = 2;
        m_leftArray[0] = v3;
        m_leftArray[1] = v1;
        m_leftSection = 1;

        if (leftSectionFlatTextured3() <= 0) return false;
        if (rightSectionFlatTextured3() <= 0) {
            m_rightSection--;
            if (rightSectionFlatTextured3() <= 0) return false;
        }
        if (int32_test > -0x1000) int32_test = -0x1000;
    } else {
        m_leftArray[0] = v3;
        m_leftArray[1] = v2;
        m_leftArray[2] = v1;
        m_leftSection = 2;
        m_rightArray[0] = v3;
        m_rightArray[1] = v1;
        m_rightSection = 1;

        if (rightSectionFlatTextured3() <= 0) return false;
        if (leftSectionFlatTextured3() <= 0) {
            m_leftSection--;
            if (leftSectionFlatTextured3() <= 0) return false;
        }
        if (int32_test < 0x1000) int32_test = 0x1000;
    }

    m_yMin = v1->y;
    m_yMax = std::min(v3->y - 1, m_drawH);

    m_deltaRightU = shl10idiv(temp * ((v3->u - v1->u) >> 10) + ((v1->u - v2->u) << 6), int32_test);
    m_deltaRightV = shl10idiv(temp * ((v3->v - v1->v) >> 10) + ((v1->v - v2->v) << 6), int32_test);

    return true;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

int PCSX::SoftGPU::SoftRenderer::rightSectionShadeTextured3() {
    SoftVertex *v1 = m_rightArray[m_rightSection];
    SoftVertex *v2 = m_rightArray[m_rightSection - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    m_deltaRightX = (v2->x - v1->x) / height;
    m_rightX = v1->x;

    m_rightSectionHeight = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

int PCSX::SoftGPU::SoftRenderer::leftSectionShadeTextured3() {
    SoftVertex *v1 = m_leftArray[m_leftSection];
    SoftVertex *v2 = m_leftArray[m_leftSection - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    m_deltaLeftX = (v2->x - v1->x) / height;
    m_leftX = v1->x;

    m_deltaLeftU = ((v2->u - v1->u)) / height;
    m_leftU = v1->u;
    m_deltaLeftV = ((v2->v - v1->v)) / height;
    m_leftV = v1->v;

    deltaLeftR = ((v2->R - v1->R)) / height;
    m_leftR = v1->R;
    m_deltaLeftG = ((v2->G - v1->G)) / height;
    m_leftG = v1->G;
    m_deltaLeftB = ((v2->B - v1->B)) / height;
    m_leftB = v1->B;

    m_leftSectionHeight = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

bool PCSX::SoftGPU::SoftRenderer::nextRowShadeTextured3() {
    if (--m_leftSectionHeight <= 0) {
        if (--m_leftSection <= 0) return true;
        if (leftSectionShadeTextured3() <= 0) return true;
    } else {
        m_leftX += m_deltaLeftX;
        m_leftU += m_deltaLeftU;
        m_leftV += m_deltaLeftV;
        m_leftR += deltaLeftR;
        m_leftG += m_deltaLeftG;
        m_leftB += m_deltaLeftB;
    }

    if (--m_rightSectionHeight <= 0) {
        if (--m_rightSection <= 0) return true;
        if (rightSectionShadeTextured3() <= 0) return true;
    } else {
        m_rightX += m_deltaRightX;
    }
    return false;
}

////////////////////////////////////////////////////////////////////////

bool PCSX::SoftGPU::SoftRenderer::setupSectionsShadeTextured3(int16_t x1, int16_t y1, int16_t x2, int16_t y2,
                                                              int16_t x3, int16_t y3, int16_t tx1, int16_t ty1,
                                                              int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3,
                                                              int32_t rgb1, int32_t rgb2, int32_t rgb3) {
    SoftVertex *v1, *v2, *v3;
    int height, int32_test, temp;

    v1 = m_vtx;
    v1->x = x1 << 16;
    v1->y = y1;
    v1->u = tx1 << 16;
    v1->v = ty1 << 16;
    v1->R = (rgb1)&0x00ff0000;
    v1->G = (rgb1 << 8) & 0x00ff0000;
    v1->B = (rgb1 << 16) & 0x00ff0000;

    v2 = m_vtx + 1;
    v2->x = x2 << 16;
    v2->y = y2;
    v2->u = tx2 << 16;
    v2->v = ty2 << 16;
    v2->R = (rgb2)&0x00ff0000;
    v2->G = (rgb2 << 8) & 0x00ff0000;
    v2->B = (rgb2 << 16) & 0x00ff0000;

    v3 = m_vtx + 2;
    v3->x = x3 << 16;
    v3->y = y3;
    v3->u = tx3 << 16;
    v3->v = ty3 << 16;
    v3->R = (rgb3)&0x00ff0000;
    v3->G = (rgb3 << 8) & 0x00ff0000;
    v3->B = (rgb3 << 16) & 0x00ff0000;

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

    height = v3->y - v1->y;
    if (height == 0) return false;

    temp = (((v2->y - v1->y) << 16) / height);
    int32_test = temp * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);

    if (int32_test == 0) return false;

    if (int32_test < 0) {
        m_rightArray[0] = v3;
        m_rightArray[1] = v2;
        m_rightArray[2] = v1;
        m_rightSection = 2;
        m_leftArray[0] = v3;
        m_leftArray[1] = v1;
        m_leftSection = 1;

        if (leftSectionShadeTextured3() <= 0) return false;
        if (rightSectionShadeTextured3() <= 0) {
            m_rightSection--;
            if (rightSectionShadeTextured3() <= 0) return false;
        }

        if (int32_test > -0x1000) int32_test = -0x1000;
    } else {
        m_leftArray[0] = v3;
        m_leftArray[1] = v2;
        m_leftArray[2] = v1;
        m_leftSection = 2;
        m_rightArray[0] = v3;
        m_rightArray[1] = v1;
        m_rightSection = 1;

        if (rightSectionShadeTextured3() <= 0) return false;
        if (leftSectionShadeTextured3() <= 0) {
            m_leftSection--;
            if (leftSectionShadeTextured3() <= 0) return false;
        }
        if (int32_test < 0x1000) int32_test = 0x1000;
    }

    m_yMin = v1->y;
    m_yMax = std::min(v3->y - 1, m_drawH);

    m_deltaRightR = shl10idiv(temp * ((v3->R - v1->R) >> 10) + ((v1->R - v2->R) << 6), int32_test);
    m_deltaRightG = shl10idiv(temp * ((v3->G - v1->G) >> 10) + ((v1->G - v2->G) << 6), int32_test);
    m_deltaRightB = shl10idiv(temp * ((v3->B - v1->B) >> 10) + ((v1->B - v2->B) << 6), int32_test);

    m_deltaRightU = shl10idiv(temp * ((v3->u - v1->u) >> 10) + ((v1->u - v2->u) << 6), int32_test);
    m_deltaRightV = shl10idiv(temp * ((v3->v - v1->v) >> 10) + ((v1->v - v2->v) << 6), int32_test);

    return true;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

int PCSX::SoftGPU::SoftRenderer::rightSectionFlat4() {
    SoftVertex *v1 = m_rightArray[m_rightSection];
    SoftVertex *v2 = m_rightArray[m_rightSection - 1];

    int height = v2->y - v1->y;
    m_rightSectionHeight = height;
    m_rightX = v1->x;
    if (height == 0) return 0;
    m_deltaRightX = (v2->x - v1->x) / height;

    return height;
}

////////////////////////////////////////////////////////////////////////

int PCSX::SoftGPU::SoftRenderer::leftSectionFlat4() {
    SoftVertex *v1 = m_leftArray[m_leftSection];
    SoftVertex *v2 = m_leftArray[m_leftSection - 1];

    int height = v2->y - v1->y;
    m_leftSectionHeight = height;
    m_leftX = v1->x;
    if (height == 0) return 0;
    m_deltaLeftX = (v2->x - v1->x) / height;

    return height;
}

bool PCSX::SoftGPU::SoftRenderer::setupSectionsFlat4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                     int16_t y3, int16_t x4, int16_t y4) {
    SoftVertex *v1, *v2, *v3, *v4;
    int height, width, int32_test1, int32_test2;

    v1 = m_vtx;
    v1->x = x1 << 16;
    v1->y = y1;
    v2 = m_vtx + 1;
    v2->x = x2 << 16;
    v2->y = y2;
    v3 = m_vtx + 2;
    v3->x = x3 << 16;
    v3->y = y3;
    v4 = m_vtx + 3;
    v4->x = x4 << 16;
    v4->y = y4;

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
    if (v1->y > v4->y) {
        SoftVertex *v = v1;
        v1 = v4;
        v4 = v;
    }
    if (v2->y > v3->y) {
        SoftVertex *v = v2;
        v2 = v3;
        v3 = v;
    }
    if (v2->y > v4->y) {
        SoftVertex *v = v2;
        v2 = v4;
        v4 = v;
    }
    if (v3->y > v4->y) {
        SoftVertex *v = v3;
        v3 = v4;
        v4 = v;
    }

    height = v4->y - v1->y;
    if (height == 0) height = 1;
    width = (v4->x - v1->x) >> 16;
    int32_test1 = (((v2->y - v1->y) << 16) / height) * width + (v1->x - v2->x);
    int32_test2 = (((v3->y - v1->y) << 16) / height) * width + (v1->x - v3->x);

    if (int32_test1 < 0) {
        // 2 is right
        if (int32_test2 < 0) {
            // 3 is right
            m_leftArray[0] = v4;
            m_leftArray[1] = v1;
            m_leftSection = 1;

            height = v3->y - v1->y;
            if (height == 0) height = 1;
            int32_test1 = (((v2->y - v1->y) << 16) / height) * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
            if (int32_test1 >= 0) {
                m_rightArray[0] = v4;  //  1
                m_rightArray[1] = v3;  //     3
                m_rightArray[2] = v1;  //  4
                m_rightSection = 2;
            } else {
                height = v4->y - v2->y;
                if (height == 0) height = 1;
                int32_test1 = (((v3->y - v2->y) << 16) / height) * ((v4->x - v2->x) >> 16) + (v2->x - v3->x);
                if (int32_test1 >= 0) {
                    m_rightArray[0] = v4;  //  1
                    m_rightArray[1] = v2;  //     2
                    m_rightArray[2] = v1;  //  4
                    m_rightSection = 2;
                } else {
                    m_rightArray[0] = v4;  //  1
                    m_rightArray[1] = v3;  //     2
                    m_rightArray[2] = v2;  //     3
                    m_rightArray[3] = v1;  //  4
                    m_rightSection = 3;
                }
            }
        } else {
            m_leftArray[0] = v4;
            m_leftArray[1] = v3;   //    1
            m_leftArray[2] = v1;   //      2
            m_leftSection = 2;     //  3
            m_rightArray[0] = v4;  //    4
            m_rightArray[1] = v2;
            m_rightArray[2] = v1;
            m_rightSection = 2;
        }
    } else {
        if (int32_test2 < 0) {
            m_leftArray[0] = v4;  //    1
            m_leftArray[1] = v2;  //  2
            m_leftArray[2] = v1;  //      3
            m_leftSection = 2;    //    4
            m_rightArray[0] = v4;
            m_rightArray[1] = v3;
            m_rightArray[2] = v1;
            m_rightSection = 2;
        } else {
            m_rightArray[0] = v4;
            m_rightArray[1] = v1;
            m_rightSection = 1;

            height = v3->y - v1->y;
            if (height == 0) height = 1;
            int32_test1 = (((v2->y - v1->y) << 16) / height) * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
            if (int32_test1 < 0) {
                m_leftArray[0] = v4;  //    1
                m_leftArray[1] = v3;  //  3
                m_leftArray[2] = v1;  //    4
                m_leftSection = 2;
            } else {
                height = v4->y - v2->y;
                if (height == 0) height = 1;
                int32_test1 = (((v3->y - v2->y) << 16) / height) * ((v4->x - v2->x) >> 16) + (v2->x - v3->x);
                if (int32_test1 < 0) {
                    m_leftArray[0] = v4;  //    1
                    m_leftArray[1] = v2;  //  2
                    m_leftArray[2] = v1;  //    4
                    m_leftSection = 2;
                } else {
                    m_leftArray[0] = v4;  //    1
                    m_leftArray[1] = v3;  //  2
                    m_leftArray[2] = v2;  //  3
                    m_leftArray[3] = v1;  //     4
                    m_leftSection = 3;
                }
            }
        }
    }

    while (leftSectionFlat4() <= 0) {
        if (--m_leftSection <= 0) break;
    }

    while (rightSectionFlat4() <= 0) {
        if (--m_rightSection <= 0) break;
    }

    m_yMin = v1->y;
    m_yMax = std::min(v4->y - 1, m_drawH);

    return true;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

int PCSX::SoftGPU::SoftRenderer::rightSectionFlatTextured4() {
    SoftVertex *v1 = m_rightArray[m_rightSection];
    SoftVertex *v2 = m_rightArray[m_rightSection - 1];

    int height = v2->y - v1->y;
    m_rightSectionHeight = height;
    m_rightX = v1->x;
    m_rightU = v1->u;
    m_rightV = v1->v;
    if (height == 0) return 0;
    m_deltaRightX = (v2->x - v1->x) / height;
    m_deltaRightU = (v2->u - v1->u) / height;
    m_deltaRightV = (v2->v - v1->v) / height;

    return height;
}

////////////////////////////////////////////////////////////////////////

int PCSX::SoftGPU::SoftRenderer::leftSectionFlatTextured4() {
    SoftVertex *v1 = m_leftArray[m_leftSection];
    SoftVertex *v2 = m_leftArray[m_leftSection - 1];

    int height = v2->y - v1->y;
    m_leftSectionHeight = height;
    m_leftX = v1->x;
    m_leftU = v1->u;
    m_leftV = v1->v;
    if (height == 0) return 0;
    m_deltaLeftX = (v2->x - v1->x) / height;
    m_deltaLeftU = (v2->u - v1->u) / height;
    m_deltaLeftV = (v2->v - v1->v) / height;

    return height;
}

////////////////////////////////////////////////////////////////////////

bool PCSX::SoftGPU::SoftRenderer::nextRowFlatTextured4() {
    if (--m_leftSectionHeight <= 0) {
        if (--m_leftSection > 0) {
            while (leftSectionFlatTextured4() <= 0) {
                if (--m_leftSection <= 0) break;
            }
        }
    } else {
        m_leftX += m_deltaLeftX;
        m_leftU += m_deltaLeftU;
        m_leftV += m_deltaLeftV;
    }

    if (--m_rightSectionHeight <= 0) {
        if (--m_rightSection > 0) {
            while (rightSectionFlatTextured4() <= 0) {
                if (--m_rightSection <= 0) break;
            }
        }
    } else {
        m_rightX += m_deltaRightX;
        m_rightU += m_deltaRightU;
        m_rightV += m_deltaRightV;
    }
    return false;
}

////////////////////////////////////////////////////////////////////////

bool PCSX::SoftGPU::SoftRenderer::setupSectionsFlatTextured4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                             int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                                                             int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                                             int16_t ty3, int16_t tx4, int16_t ty4) {
    SoftVertex *v1, *v2, *v3, *v4;
    int height, width, int32_test1, int32_test2;

    v1 = m_vtx;
    v1->x = x1 << 16;
    v1->y = y1;
    v1->u = tx1 << 16;
    v1->v = ty1 << 16;

    v2 = m_vtx + 1;
    v2->x = x2 << 16;
    v2->y = y2;
    v2->u = tx2 << 16;
    v2->v = ty2 << 16;

    v3 = m_vtx + 2;
    v3->x = x3 << 16;
    v3->y = y3;
    v3->u = tx3 << 16;
    v3->v = ty3 << 16;

    v4 = m_vtx + 3;
    v4->x = x4 << 16;
    v4->y = y4;
    v4->u = tx4 << 16;
    v4->v = ty4 << 16;

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
    if (v1->y > v4->y) {
        SoftVertex *v = v1;
        v1 = v4;
        v4 = v;
    }
    if (v2->y > v3->y) {
        SoftVertex *v = v2;
        v2 = v3;
        v3 = v;
    }
    if (v2->y > v4->y) {
        SoftVertex *v = v2;
        v2 = v4;
        v4 = v;
    }
    if (v3->y > v4->y) {
        SoftVertex *v = v3;
        v3 = v4;
        v4 = v;
    }

    height = v4->y - v1->y;
    if (height == 0) height = 1;
    width = (v4->x - v1->x) >> 16;
    int32_test1 = (((v2->y - v1->y) << 16) / height) * width + (v1->x - v2->x);
    int32_test2 = (((v3->y - v1->y) << 16) / height) * width + (v1->x - v3->x);

    if (int32_test1 < 0) {
        // 2 is right
        if (int32_test2 < 0) {
            // 3 is right
            m_leftArray[0] = v4;
            m_leftArray[1] = v1;
            m_leftSection = 1;

            height = v3->y - v1->y;
            if (height == 0) height = 1;
            int32_test1 = (((v2->y - v1->y) << 16) / height) * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
            if (int32_test1 >= 0) {
                m_rightArray[0] = v4;  //  1
                m_rightArray[1] = v3;  //     3
                m_rightArray[2] = v1;  //  4
                m_rightSection = 2;
            } else {
                height = v4->y - v2->y;
                if (height == 0) height = 1;
                int32_test1 = (((v3->y - v2->y) << 16) / height) * ((v4->x - v2->x) >> 16) + (v2->x - v3->x);
                if (int32_test1 >= 0) {
                    m_rightArray[0] = v4;  //  1
                    m_rightArray[1] = v2;  //     2
                    m_rightArray[2] = v1;  //  4
                    m_rightSection = 2;
                } else {
                    m_rightArray[0] = v4;  //  1
                    m_rightArray[1] = v3;  //     2
                    m_rightArray[2] = v2;  //     3
                    m_rightArray[3] = v1;  //  4
                    m_rightSection = 3;
                }
            }
        } else {
            m_leftArray[0] = v4;
            m_leftArray[1] = v3;   //    1
            m_leftArray[2] = v1;   //      2
            m_leftSection = 2;     //  3
            m_rightArray[0] = v4;  //    4
            m_rightArray[1] = v2;
            m_rightArray[2] = v1;
            m_rightSection = 2;
        }
    } else {
        if (int32_test2 < 0) {
            m_leftArray[0] = v4;  //    1
            m_leftArray[1] = v2;  //  2
            m_leftArray[2] = v1;  //      3
            m_leftSection = 2;    //    4
            m_rightArray[0] = v4;
            m_rightArray[1] = v3;
            m_rightArray[2] = v1;
            m_rightSection = 2;
        } else {
            m_rightArray[0] = v4;
            m_rightArray[1] = v1;
            m_rightSection = 1;

            height = v3->y - v1->y;
            if (height == 0) height = 1;
            int32_test1 = (((v2->y - v1->y) << 16) / height) * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
            if (int32_test1 < 0) {
                m_leftArray[0] = v4;  //    1
                m_leftArray[1] = v3;  //  3
                m_leftArray[2] = v1;  //    4
                m_leftSection = 2;
            } else {
                height = v4->y - v2->y;
                if (height == 0) height = 1;
                int32_test1 = (((v3->y - v2->y) << 16) / height) * ((v4->x - v2->x) >> 16) + (v2->x - v3->x);
                if (int32_test1 < 0) {
                    m_leftArray[0] = v4;  //    1
                    m_leftArray[1] = v2;  //  2
                    m_leftArray[2] = v1;  //    4
                    m_leftSection = 2;
                } else {
                    m_leftArray[0] = v4;  //    1
                    m_leftArray[1] = v3;  //  2
                    m_leftArray[2] = v2;  //  3
                    m_leftArray[3] = v1;  //     4
                    m_leftSection = 3;
                }
            }
        }
    }

    while (leftSectionFlatTextured4() <= 0) {
        if (--m_leftSection <= 0) break;
    }

    while (rightSectionFlatTextured4() <= 0) {
        if (--m_rightSection <= 0) break;
    }

    m_yMin = v1->y;
    m_yMax = std::min(v4->y - 1, m_drawH);

    return true;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

int PCSX::SoftGPU::SoftRenderer::rightSectionShadeTextured4() {
    SoftVertex *v1 = m_rightArray[m_rightSection];
    SoftVertex *v2 = m_rightArray[m_rightSection - 1];

    int height = v2->y - v1->y;
    m_rightSectionHeight = height;
    m_rightX = v1->x;
    m_rightU = v1->u;
    m_rightV = v1->v;
    m_rightR = v1->R;
    m_rightG = v1->G;
    m_rightB = v1->B;

    if (height == 0) return 0;
    m_deltaRightX = (v2->x - v1->x) / height;
    m_deltaRightU = (v2->u - v1->u) / height;
    m_deltaRightV = (v2->v - v1->v) / height;
    m_deltaRightR = (v2->R - v1->R) / height;
    m_deltaRightG = (v2->G - v1->G) / height;
    m_deltaRightB = (v2->B - v1->B) / height;

    return height;
}

////////////////////////////////////////////////////////////////////////

int PCSX::SoftGPU::SoftRenderer::leftSectionShadeTextured4() {
    SoftVertex *v1 = m_leftArray[m_leftSection];
    SoftVertex *v2 = m_leftArray[m_leftSection - 1];

    int height = v2->y - v1->y;
    m_leftSectionHeight = height;
    m_leftX = v1->x;
    m_leftU = v1->u;
    m_leftV = v1->v;
    m_leftR = v1->R;
    m_leftG = v1->G;
    m_leftB = v1->B;

    if (height == 0) return 0;
    m_deltaLeftX = (v2->x - v1->x) / height;
    m_deltaLeftU = (v2->u - v1->u) / height;
    m_deltaLeftV = (v2->v - v1->v) / height;
    deltaLeftR = (v2->R - v1->R) / height;
    m_deltaLeftG = (v2->G - v1->G) / height;
    m_deltaLeftB = (v2->B - v1->B) / height;

    return height;
}

////////////////////////////////////////////////////////////////////////

bool PCSX::SoftGPU::SoftRenderer::setupSectionsShadeTextured4(int16_t x1, int16_t y1, int16_t x2, int16_t y2,
                                                              int16_t x3, int16_t y3, int16_t x4, int16_t y4,
                                                              int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2,
                                                              int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4,
                                                              int32_t rgb1, int32_t rgb2, int32_t rgb3, int32_t rgb4) {
    SoftVertex *v1, *v2, *v3, *v4;
    int height, width, int32_test1, int32_test2;

    v1 = m_vtx;
    v1->x = x1 << 16;
    v1->y = y1;
    v1->u = tx1 << 16;
    v1->v = ty1 << 16;
    v1->R = (rgb1)&0x00ff0000;
    v1->G = (rgb1 << 8) & 0x00ff0000;
    v1->B = (rgb1 << 16) & 0x00ff0000;

    v2 = m_vtx + 1;
    v2->x = x2 << 16;
    v2->y = y2;
    v2->u = tx2 << 16;
    v2->v = ty2 << 16;
    v2->R = (rgb2)&0x00ff0000;
    v2->G = (rgb2 << 8) & 0x00ff0000;
    v2->B = (rgb2 << 16) & 0x00ff0000;

    v3 = m_vtx + 2;
    v3->x = x3 << 16;
    v3->y = y3;
    v3->u = tx3 << 16;
    v3->v = ty3 << 16;
    v3->R = (rgb3)&0x00ff0000;
    v3->G = (rgb3 << 8) & 0x00ff0000;
    v3->B = (rgb3 << 16) & 0x00ff0000;

    v4 = m_vtx + 3;
    v4->x = x4 << 16;
    v4->y = y4;
    v4->u = tx4 << 16;
    v4->v = ty4 << 16;
    v4->R = (rgb4)&0x00ff0000;
    v4->G = (rgb4 << 8) & 0x00ff0000;
    v4->B = (rgb4 << 16) & 0x00ff0000;

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
    if (v1->y > v4->y) {
        SoftVertex *v = v1;
        v1 = v4;
        v4 = v;
    }
    if (v2->y > v3->y) {
        SoftVertex *v = v2;
        v2 = v3;
        v3 = v;
    }
    if (v2->y > v4->y) {
        SoftVertex *v = v2;
        v2 = v4;
        v4 = v;
    }
    if (v3->y > v4->y) {
        SoftVertex *v = v3;
        v3 = v4;
        v4 = v;
    }

    height = v4->y - v1->y;
    if (height == 0) height = 1;
    width = (v4->x - v1->x) >> 16;
    int32_test1 = (((v2->y - v1->y) << 16) / height) * width + (v1->x - v2->x);
    int32_test2 = (((v3->y - v1->y) << 16) / height) * width + (v1->x - v3->x);

    if (int32_test1 < 0) {
        // 2 is right
        if (int32_test2 < 0) {
            // 3 is right
            m_leftArray[0] = v4;
            m_leftArray[1] = v1;
            m_leftSection = 1;

            height = v3->y - v1->y;
            if (height == 0) height = 1;
            int32_test1 = (((v2->y - v1->y) << 16) / height) * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
            if (int32_test1 >= 0) {
                m_rightArray[0] = v4;  //  1
                m_rightArray[1] = v3;  //     3
                m_rightArray[2] = v1;  //  4
                m_rightSection = 2;
            } else {
                height = v4->y - v2->y;
                if (height == 0) height = 1;
                int32_test1 = (((v3->y - v2->y) << 16) / height) * ((v4->x - v2->x) >> 16) + (v2->x - v3->x);
                if (int32_test1 >= 0) {
                    m_rightArray[0] = v4;  //  1
                    m_rightArray[1] = v2;  //     2
                    m_rightArray[2] = v1;  //  4
                    m_rightSection = 2;
                } else {
                    m_rightArray[0] = v4;  //  1
                    m_rightArray[1] = v3;  //     2
                    m_rightArray[2] = v2;  //     3
                    m_rightArray[3] = v1;  //  4
                    m_rightSection = 3;
                }
            }
        } else {
            m_leftArray[0] = v4;
            m_leftArray[1] = v3;   //    1
            m_leftArray[2] = v1;   //      2
            m_leftSection = 2;     //  3
            m_rightArray[0] = v4;  //    4
            m_rightArray[1] = v2;
            m_rightArray[2] = v1;
            m_rightSection = 2;
        }
    } else {
        if (int32_test2 < 0) {
            m_leftArray[0] = v4;  //    1
            m_leftArray[1] = v2;  //  2
            m_leftArray[2] = v1;  //      3
            m_leftSection = 2;    //    4
            m_rightArray[0] = v4;
            m_rightArray[1] = v3;
            m_rightArray[2] = v1;
            m_rightSection = 2;
        } else {
            m_rightArray[0] = v4;
            m_rightArray[1] = v1;
            m_rightSection = 1;

            height = v3->y - v1->y;
            if (height == 0) height = 1;
            int32_test1 = (((v2->y - v1->y) << 16) / height) * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
            if (int32_test1 < 0) {
                m_leftArray[0] = v4;  //    1
                m_leftArray[1] = v3;  //  3
                m_leftArray[2] = v1;  //    4
                m_leftSection = 2;
            } else {
                height = v4->y - v2->y;
                if (height == 0) height = 1;
                int32_test1 = (((v3->y - v2->y) << 16) / height) * ((v4->x - v2->x) >> 16) + (v2->x - v3->x);
                if (int32_test1 < 0) {
                    m_leftArray[0] = v4;  //    1
                    m_leftArray[1] = v2;  //  2
                    m_leftArray[2] = v1;  //    4
                    m_leftSection = 2;
                } else {
                    m_leftArray[0] = v4;  //    1
                    m_leftArray[1] = v3;  //  2
                    m_leftArray[2] = v2;  //  3
                    m_leftArray[3] = v1;  //     4
                    m_leftSection = 3;
                }
            }
        }
    }

    while (leftSectionShadeTextured4() <= 0) {
        if (--m_leftSection <= 0) break;
    }

    while (rightSectionShadeTextured4() <= 0) {
        if (--m_rightSection <= 0) break;
    }

    m_yMin = v1->y;
    m_yMax = std::min(v4->y - 1, m_drawH);

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

void PCSX::SoftGPU::SoftRenderer::drawPoly3Fi(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                              int32_t rgb) {
    int i, j, xmin, xmax, ymin, ymax;
    uint16_t color;
    uint32_t lcolor;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawW = m_drawW;
    const auto drawH = m_drawH;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!setupSectionsFlat3(x1, y1, x2, y2, x3, y3)) return;

    ymax = m_yMax;

    color = ((rgb & 0x00f80000) >> 9) | ((rgb & 0x0000f800) >> 6) | ((rgb & 0x000000f8) >> 3);
    lcolor = m_setMask32 | (((uint32_t)(color)) << 16) | color;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRowFlat3()) return;
    }

    if (!m_checkMask && !m_drawSemiTrans) {
        color |= m_setMask16;
        for (i = ymin; i <= ymax; i++) {
            xmin = m_leftX >> 16;
            if (drawX > xmin) xmin = drawX;
            xmax = (m_rightX >> 16) - 1;
            if (drawW < xmax) xmax = drawW;

            for (j = xmin; j < xmax; j += 2) {
                *((uint32_t *)&vram16[(i << 10) + j]) = lcolor;
            }
            if (j == xmax) vram16[(i << 10) + j] = color;

            if (nextRowFlat3()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = m_leftX >> 16;
        if (drawX > xmin) xmin = drawX;
        xmax = (m_rightX >> 16) - 1;
        if (drawW < xmax) xmax = drawW;

        for (j = xmin; j < xmax; j += 2) {
            getShadeTransCol32((uint32_t *)&vram16[(i << 10) + j], lcolor);
        }
        if (j == xmax) getShadeTransCol(&vram16[(i << 10) + j], color);

        if (nextRowFlat3()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPolyFlat3(int32_t rgb) { drawPoly3Fi(m_x0, m_y0, m_x1, m_y1, m_x2, m_y2, rgb); }

void PCSX::SoftGPU::SoftRenderer::drawPolyFlat4(int32_t rgb) {
    drawPoly3Fi(m_x1, m_y1, m_x3, m_y3, m_x2, m_y2, rgb);
    drawPoly3Fi(m_x0, m_y0, m_x1, m_y1, m_x2, m_y2, rgb);
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TEx4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                                int16_t ty3, int16_t clX, int16_t clY) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, XAdjust;
    int32_t clutP;
    int16_t tC1, tC2;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawW = m_drawW;
    const auto drawH = m_drawH;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!setupSectionsFlatTextured3(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3)) return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRowFlatTextured3()) return;
    }

    clutP = (clY << 10) + clX;

    YAdjust = ((m_globalTextAddrY) << 11) + (m_globalTextAddrX << 1);
    YAdjust += (m_textureWindow.y0 << 11) + (m_textureWindow.x0 >> 1);

    difX = m_deltaRightU;
    difX2 = difX << 1;
    difY = m_deltaRightV;
    difY2 = difY << 1;

    if (!m_checkMask && !m_drawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX >> 16);
            xmax = (m_rightX >> 16);  //-1; //!!!!!!!!!!!!!!!!
            if (xmax > xmin) xmax--;

            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = m_leftU;
                posY = m_leftV;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }

                for (j = xmin; j < xmax; j += 2) {
                    XAdjust = (posX >> 16) & maskX;
                    tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    XAdjust = ((posX + difX) >> 16) & maskX;
                    tC2 =
                        vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                    tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                    getTextureTransColShade32Solid((uint32_t *)&vram16[(i << 10) + j],
                                                   vram16[clutP + tC1] | ((int32_t)vram16[clutP + tC2]) << 16);

                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    XAdjust = (posX >> 16) & maskX;
                    tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    getTextureTransColShadeSolid(&vram16[(i << 10) + j], vram16[clutP + tC1]);
                }
            }
            if (nextRowFlatTextured3()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX >> 16);
        xmax = (m_rightX >> 16) - 1;  //!!!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = m_leftU;
            posY = m_leftV;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }

            for (j = xmin; j < xmax; j += 2) {
                XAdjust = (posX >> 16) & maskX;
                tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                XAdjust = ((posX + difX) >> 16) & maskX;
                tC2 = vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                getTextureTransColShade32((uint32_t *)&vram16[(i << 10) + j],
                                          vram16[clutP + tC1] | ((int32_t)vram16[clutP + tC2]) << 16);

                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                XAdjust = (posX >> 16) & maskX;
                tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                getTextureTransColShade(&vram16[(i << 10) + j], vram16[clutP + tC1]);
            }
        }
        if (nextRowFlatTextured3()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TEx4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                int16_t x4, int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2,
                                                int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4,
                                                int16_t clX, int16_t clY) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP, XAdjust;
    int16_t tC1, tC2;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto xxleftX = m_leftX;
    const auto xxrightX = m_rightX;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto xxleftU = m_leftU;
    const auto xxleftV = m_leftV;
    const auto xxrightU = m_rightU;
    const auto xxrightV = m_rightV;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!setupSectionsFlatTextured4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRowFlatTextured4()) return;
    }

    clutP = (clY << 10) + clX;

    YAdjust = ((m_globalTextAddrY) << 11) + (m_globalTextAddrX << 1);
    YAdjust += (m_textureWindow.y0 << 11) + (m_textureWindow.x0 >> 1);

    if (!m_checkMask && !m_drawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX >> 16);
            xmax = (m_rightX >> 16);

            if (xmax >= xmin) {
                posX = m_leftU;
                posY = m_leftV;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (m_rightU - posX) / num;
                difY = (m_rightV - posY) / num;
                difX2 = difX << 1;
                difY2 = difY << 1;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }
                xmax--;
                if (drawW < xmax) xmax = drawW;

                for (j = xmin; j < xmax; j += 2) {
                    XAdjust = (posX >> 16) & maskX;
                    tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    XAdjust = ((posX + difX) >> 16) & maskX;
                    tC2 =
                        vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                    tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                    getTextureTransColShade32Solid((uint32_t *)&vram16[(i << 10) + j],
                                                   vram16[clutP + tC1] | ((int32_t)vram16[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    XAdjust = (posX >> 16) & maskX;
                    tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    getTextureTransColShadeSolid(&vram16[(i << 10) + j], vram16[clutP + tC1]);
                }
            }
            if (nextRowFlatTextured4()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX >> 16);
        xmax = (m_rightX >> 16);

        if (xmax >= xmin) {
            posX = m_leftU;
            posY = m_leftV;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (m_rightU - posX) / num;
            difY = (m_rightV - posY) / num;
            difX2 = difX << 1;
            difY2 = difY << 1;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }
            xmax--;
            if (drawW < xmax) xmax = drawW;

            for (j = xmin; j < xmax; j += 2) {
                XAdjust = (posX >> 16) & drawX;
                tC1 = vram[static_cast<int32_t>((((posY >> 16) & drawY) << 11) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                XAdjust = ((posX + difX) >> 16) & drawX;
                tC2 = vram[static_cast<int32_t>(((((posY + difY) >> 16) & drawY) << 11) + YAdjust + (XAdjust >> 1))];
                tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                getTextureTransColShade32((uint32_t *)&vram16[(i << 10) + j],
                                          vram16[clutP + tC1] | ((int32_t)vram16[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                XAdjust = (posX >> 16) & drawX;
                tC1 = vram[static_cast<int32_t>((((posY >> 16) & drawY) << 11) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                getTextureTransColShade(&vram16[(i << 10) + j], vram16[clutP + tC1]);
            }
        }
        if (nextRowFlatTextured4()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TEx4_S(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                  int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                  int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                  int16_t ty4, int16_t clX, int16_t clY) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP, XAdjust;
    int16_t tC1, tC2;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!setupSectionsFlatTextured4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRowFlatTextured4()) return;
    }

    clutP = (clY << 10) + clX;

    YAdjust = ((m_globalTextAddrY) << 11) + (m_globalTextAddrX << 1);
    YAdjust += (m_textureWindow.y0 << 11) + (m_textureWindow.x0 >> 1);

    if (!m_checkMask && !m_drawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX >> 16);
            xmax = (m_rightX >> 16);

            if (xmax >= xmin) {
                posX = m_leftU;
                posY = m_leftV;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (m_rightU - posX) / num;
                difY = (m_rightV - posY) / num;
                difX2 = difX << 1;
                difY2 = difY << 1;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }
                xmax--;
                if (drawW < xmax) xmax = drawW;

                for (j = xmin; j < xmax; j += 2) {
                    XAdjust = (posX >> 16) & maskX;
                    tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    XAdjust = ((posX + difX) >> 16) & maskX;
                    tC2 =
                        vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                    tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                    getTextureTransColShade32Solid((uint32_t *)&vram16[(i << 10) + j],
                                                   vram16[clutP + tC1] | ((int32_t)vram16[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    XAdjust = (posX >> 16) & maskX;
                    tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    getTextureTransColShadeSolid(&vram16[(i << 10) + j], vram16[clutP + tC1]);
                }
            }
            if (nextRowFlatTextured4()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX >> 16);
        xmax = (m_rightX >> 16);

        if (xmax >= xmin) {
            posX = m_leftU;
            posY = m_leftV;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (m_rightU - posX) / num;
            difY = (m_rightV - posY) / num;
            difX2 = difX << 1;
            difY2 = difY << 1;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }
            xmax--;
            if (drawW < xmax) xmax = drawW;

            for (j = xmin; j < xmax; j += 2) {
                XAdjust = (posX >> 16) & maskX;
                tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                XAdjust = ((posX + difX) >> 16) & maskX;
                tC2 = vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                getTextureTransColG32Semi((uint32_t *)&vram16[(i << 10) + j],
                                          vram16[clutP + tC1] | ((int32_t)vram16[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                XAdjust = (posX >> 16) & maskX;
                tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                getTextureTransColShadeSemi(&vram16[(i << 10) + j], vram16[clutP + tC1]);
            }
        }
        if (nextRowFlatTextured4()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TEx8(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                                int16_t ty3, int16_t clX, int16_t clY) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP;
    int16_t tC1, tC2;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!setupSectionsFlatTextured3(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3)) return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRowFlatTextured3()) return;
    }

    clutP = (clY << 10) + clX;

    YAdjust = ((m_globalTextAddrY) << 11) + (m_globalTextAddrX << 1);
    YAdjust += (m_textureWindow.y0 << 11) + (m_textureWindow.x0);

    difX = m_deltaRightU;
    difX2 = difX << 1;
    difY = m_deltaRightV;
    difY2 = difY << 1;

    if (!m_checkMask && !m_drawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX >> 16);
            xmax = (m_rightX >> 16);  //-1; //!!!!!!!!!!!!!!!!
            if (xmax > xmin) xmax--;

            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = m_leftU;
                posY = m_leftV;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }

                for (j = xmin; j < xmax; j += 2) {
                    tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + ((posX >> 16) & maskX))];
                    tC2 = vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust +
                                                    (((posX + difX) >> 16) & maskX))];
                    getTextureTransColShade32Solid((uint32_t *)&vram16[(i << 10) + j],
                                                   vram16[clutP + tC1] | ((int32_t)vram16[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }

                if (j == xmax) {
                    tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + ((posX >> 16) & maskX))];
                    getTextureTransColShadeSolid(&vram16[(i << 10) + j], vram16[clutP + tC1]);
                }
            }
            if (nextRowFlatTextured3()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX >> 16);
        xmax = (m_rightX >> 16) - 1;  //!!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = m_leftU;
            posY = m_leftV;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }

            for (j = xmin; j < xmax; j += 2) {
                tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + ((posX >> 16) & maskX))];
                tC2 = vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust +
                                                (((posX + difX) >> 16) & maskX))];
                getTextureTransColShade32((uint32_t *)&vram16[(i << 10) + j],
                                          vram16[clutP + tC1] | ((int32_t)vram16[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }

            if (j == xmax) {
                tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + ((posX >> 16) & maskX))];
                getTextureTransColShade(&vram16[(i << 10) + j], vram16[clutP + tC1]);
            }
        }
        if (nextRowFlatTextured3()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TEx8(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                int16_t x4, int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2,
                                                int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4,
                                                int16_t clX, int16_t clY) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP;
    int16_t tC1, tC2;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!setupSectionsFlatTextured4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRowFlatTextured4()) return;
    }

    clutP = (clY << 10) + clX;

    YAdjust = ((m_globalTextAddrY) << 11) + (m_globalTextAddrX << 1);
    YAdjust += (m_textureWindow.y0 << 11) + (m_textureWindow.x0);

    if (!m_checkMask && !m_drawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX >> 16);
            xmax = (m_rightX >> 16);

            if (xmax >= xmin) {
                posX = m_leftU;
                posY = m_leftV;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (m_rightU - posX) / num;
                difY = (m_rightV - posY) / num;
                difX2 = difX << 1;
                difY2 = difY << 1;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }
                xmax--;
                if (drawW < xmax) xmax = drawW;

                for (j = xmin; j < xmax; j += 2) {
                    tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + ((posX >> 16) & maskX))];
                    tC2 = vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust +
                                                    (((posX + difX) >> 16) & maskX))];
                    getTextureTransColShade32Solid((uint32_t *)&vram16[(i << 10) + j],
                                                   vram16[clutP + tC1] | ((int32_t)vram16[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    tC1 = vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust +
                                                    ((posX >> 16) & maskX))];
                    getTextureTransColShadeSolid(&vram16[(i << 10) + j], vram16[clutP + tC1]);
                }
            }
            if (nextRowFlatTextured4()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX >> 16);
        xmax = (m_rightX >> 16);

        if (xmax >= xmin) {
            posX = m_leftU;
            posY = m_leftV;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (m_rightU - posX) / num;
            difY = (m_rightV - posY) / num;
            difX2 = difX << 1;
            difY2 = difY << 1;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }
            xmax--;
            if (drawW < xmax) xmax = drawW;

            for (j = xmin; j < xmax; j += 2) {
                tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + ((posX >> 16) & maskX))];
                tC2 = vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust +
                                                (((posX + difX) >> 16) & maskX))];
                getTextureTransColShade32((uint32_t *)&vram16[(i << 10) + j],
                                          vram16[clutP + tC1] | ((int32_t)vram16[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                tC1 = vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust +
                                                ((posX >> 16) & maskX))];
                getTextureTransColShade(&vram16[(i << 10) + j], vram16[clutP + tC1]);
            }
        }
        if (nextRowFlatTextured4()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TEx8_S(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                  int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                  int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                  int16_t ty4, int16_t clX, int16_t clY) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP;
    int16_t tC1, tC2;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!setupSectionsFlatTextured4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRowFlatTextured4()) return;
    }

    clutP = (clY << 10) + clX;

    YAdjust = ((m_globalTextAddrY) << 11) + (m_globalTextAddrX << 1);
    YAdjust += (m_textureWindow.y0 << 11) + (m_textureWindow.x0);

    if (!m_checkMask && !m_drawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX >> 16);
            xmax = (m_rightX >> 16);

            if (xmax >= xmin) {
                posX = m_leftU;
                posY = m_leftV;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (m_rightU - posX) / num;
                difY = (m_rightV - posY) / num;
                difX2 = difX << 1;
                difY2 = difY << 1;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }
                xmax--;
                if (drawW < xmax) xmax = drawW;

                for (j = xmin; j < xmax; j += 2) {
                    tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + ((posX >> 16) & maskX))];
                    tC2 = vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust +
                                                    (((posX + difX) >> 16) & maskX))];
                    getTextureTransColShade32Solid((uint32_t *)&vram16[(i << 10) + j],
                                                   vram16[clutP + tC1] | ((int32_t)vram16[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    tC1 = vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust +
                                                    ((posX >> 16) & maskX))];
                    getTextureTransColShadeSolid(&vram16[(i << 10) + j], vram16[clutP + tC1]);
                }
            }
            if (nextRowFlatTextured4()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX >> 16);
        xmax = (m_rightX >> 16);

        if (xmax >= xmin) {
            posX = m_leftU;
            posY = m_leftV;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (m_rightU - posX) / num;
            difY = (m_rightV - posY) / num;
            difX2 = difX << 1;
            difY2 = difY << 1;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }
            xmax--;
            if (drawW < xmax) xmax = drawW;

            for (j = xmin; j < xmax; j += 2) {
                tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + ((posX >> 16) & maskX))];
                tC2 = vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust +
                                                (((posX + difX) >> 16) & maskX))];
                getTextureTransColG32Semi((uint32_t *)&vram16[(i << 10) + j],
                                          vram16[clutP + tC1] | ((int32_t)vram16[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                tC1 = vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust +
                                                ((posX >> 16) & maskX))];
                getTextureTransColShadeSemi(&vram16[(i << 10) + j], vram16[clutP + tC1]);
            }
        }
        if (nextRowFlatTextured4()) return;
    }
}

////////////////////////////////////////////////////////////////////////
// POLY 3 F-SHADED TEX 15 BIT
////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TD(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                              int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                              int16_t ty3) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!setupSectionsFlatTextured3(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3)) return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRowFlatTextured3()) return;
    }

    difX = m_deltaRightU;
    difX2 = difX << 1;
    difY = m_deltaRightV;
    difY2 = difY << 1;

    if (!m_checkMask && !m_drawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX >> 16);
            xmax = (m_rightX >> 16) - 1;  //!!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = m_leftU;
                posY = m_leftV;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }

                for (j = xmin; j < xmax; j += 2) {
                    getTextureTransColShade32Solid(
                        (uint32_t *)&vram16[(i << 10) + j],
                        (((int32_t)
                              vram16[(((((posY + difY) >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                                     (((posX + difX) >> 16) & maskX) + globalTextAddrX + textureWindow.x0])
                         << 16) |
                            vram16[((((posY >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                                   (((posX) >> 16) & maskX) + globalTextAddrX + textureWindow.x0]);

                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    getTextureTransColShadeSolid(
                        &vram16[(i << 10) + j],
                        vram16[((((posY >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                               ((posX >> 16) & maskX) + globalTextAddrX + textureWindow.x0]);
                }
            }
            if (nextRowFlatTextured3()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX >> 16);
        xmax = (m_rightX >> 16) - 1;  //!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = m_leftU;
            posY = m_leftV;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }

            for (j = xmin; j < xmax; j += 2) {
                getTextureTransColShade32(
                    (uint32_t *)&vram16[(i << 10) + j],
                    (((int32_t)vram16[(((((posY + difY) >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                                      (((posX + difX) >> 16) & maskX) + globalTextAddrX + textureWindow.x0])
                     << 16) |
                        vram16[((((posY >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                               (((posX) >> 16) & maskX) + globalTextAddrX + textureWindow.x0]);

                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                getTextureTransColShade(&vram16[(i << 10) + j],
                                        vram16[((((posY >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                                               ((posX >> 16) & maskX) + globalTextAddrX + textureWindow.x0]);
            }
        }
        if (nextRowFlatTextured3()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TD(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                              int16_t x4, int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2,
                                              int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!setupSectionsFlatTextured4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRowFlatTextured4()) return;
    }

    if (!m_checkMask && !m_drawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX >> 16);
            xmax = (m_rightX >> 16);

            if (xmax >= xmin) {
                posX = m_leftU;
                posY = m_leftV;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (m_rightU - posX) / num;
                difY = (m_rightV - posY) / num;
                difX2 = difX << 1;
                difY2 = difY << 1;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }
                xmax--;
                if (drawW < xmax) xmax = drawW;

                for (j = xmin; j < xmax; j += 2) {
                    getTextureTransColShade32Solid(
                        (uint32_t *)&vram16[(i << 10) + j],
                        (((int32_t)
                              vram16[(((((posY + difY) >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                                     (((posX + difX) >> 16) & maskX) + globalTextAddrX + textureWindow.x0])
                         << 16) |
                            vram16[((((posY >> 16) & maskY) + globalTextAddrY) << 10) + textureWindow.y0 +
                                   ((posX >> 16) & maskX) + globalTextAddrX + textureWindow.x0]);

                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    getTextureTransColShadeSolid(
                        &vram16[(i << 10) + j],
                        vram16[((((posY >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                               ((posX >> 16) & maskX) + globalTextAddrX + textureWindow.x0]);
                }
            }
            if (nextRowFlatTextured4()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX >> 16);
        xmax = (m_rightX >> 16);

        if (xmax >= xmin) {
            posX = m_leftU;
            posY = m_leftV;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (m_rightU - posX) / num;
            difY = (m_rightV - posY) / num;
            difX2 = difX << 1;
            difY2 = difY << 1;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }
            xmax--;
            if (drawW < xmax) xmax = drawW;

            for (j = xmin; j < xmax; j += 2) {
                getTextureTransColShade32(
                    (uint32_t *)&vram16[(i << 10) + j],
                    (((int32_t)vram16[(((((posY + difY) >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                                      (((posX + difX) >> 16) & maskX) + globalTextAddrX + textureWindow.x0])
                     << 16) |
                        vram16[((((posY >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                               ((posX >> 16) & maskX) + globalTextAddrX + textureWindow.x0]);

                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                getTextureTransColShade(&vram16[(i << 10) + j],
                                        vram16[((((posY >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                                               ((posX >> 16) & maskX) + globalTextAddrX + textureWindow.x0]);
            }
        }
        if (nextRowFlatTextured4()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TD_S(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                int16_t x4, int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2,
                                                int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!setupSectionsFlatTextured4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRowFlatTextured4()) return;
    }

    if (!m_checkMask && !m_drawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX >> 16);
            xmax = (m_rightX >> 16);

            if (xmax >= xmin) {
                posX = m_leftU;
                posY = m_leftV;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (m_rightU - posX) / num;
                difY = (m_rightV - posY) / num;
                difX2 = difX << 1;
                difY2 = difY << 1;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }
                xmax--;
                if (drawW < xmax) xmax = drawW;

                for (j = xmin; j < xmax; j += 2) {
                    getTextureTransColShade32Solid(
                        (uint32_t *)&vram16[(i << 10) + j],
                        (((int32_t)
                              vram16[(((((posY + difY) >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                                     (((posX + difX) >> 16) & maskX) + globalTextAddrX + textureWindow.x0])
                         << 16) |
                            vram16[((((posY >> 16) & maskY) + globalTextAddrY) << 10) + textureWindow.y0 +
                                   ((posX >> 16) & maskX) + globalTextAddrX + textureWindow.x0]);

                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    getTextureTransColShadeSolid(
                        &vram16[(i << 10) + j],
                        vram16[((((posY >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                               ((posX >> 16) & maskX) + globalTextAddrX + textureWindow.x0]);
                }
            }
            if (nextRowFlatTextured4()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX >> 16);
        xmax = (m_rightX >> 16);

        if (xmax >= xmin) {
            posX = m_leftU;
            posY = m_leftV;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (m_rightU - posX) / num;
            difY = (m_rightV - posY) / num;
            difX2 = difX << 1;
            difY2 = difY << 1;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }
            xmax--;
            if (drawW < xmax) xmax = drawW;

            for (j = xmin; j < xmax; j += 2) {
                getTextureTransColG32Semi(
                    (uint32_t *)&vram16[(i << 10) + j],
                    (((int32_t)vram16[(((((posY + difY) >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                                      (((posX + difX) >> 16) & maskX) + globalTextAddrX + textureWindow.x0])
                     << 16) |
                        vram16[((((posY >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                               ((posX >> 16) & maskX) + globalTextAddrX + textureWindow.x0]);

                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                getTextureTransColShadeSemi(
                    &vram16[(i << 10) + j],
                    vram16[((((posY >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                           ((posX >> 16) & maskX) + globalTextAddrX + textureWindow.x0]);
            }
        }
        if (nextRowFlatTextured4()) return;
    }
}

////////////////////////////////////////////////////////////////////////
// POLY 3/4 G-SHADED
////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3Gi(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                              int32_t rgb1, int32_t rgb2, int32_t rgb3) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t cR1, cG1, cB1;
    int32_t difR, difB, difG, difR2, difB2, difG2;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!setupSectionsShade3(x1, y1, x2, y2, x3, y3, rgb1, rgb2, rgb3)) return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRowShade3()) return;
    }

    difR = m_deltaRightR;
    difG = m_deltaRightG;
    difB = m_deltaRightB;
    difR2 = difR << 1;
    difG2 = difG << 1;
    difB2 = difB << 1;

    if (!m_checkMask && !m_drawSemiTrans && m_ditherMode != 2) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX >> 16);
            xmax = (m_rightX >> 16) - 1;
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                cR1 = leftR;
                cG1 = leftG;
                cB1 = leftB;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    cR1 += j * difR;
                    cG1 += j * difG;
                    cB1 += j * difB;
                }

                for (j = xmin; j < xmax; j += 2) {
                    *((uint32_t *)&vram16[(i << 10) + j]) =
                        ((((cR1 + difR) << 7) & 0x7c000000) | (((cG1 + difG) << 2) & 0x03e00000) |
                         (((cB1 + difB) >> 3) & 0x001f0000) | (((cR1) >> 9) & 0x7c00) | (((cG1) >> 14) & 0x03e0) |
                         (((cB1) >> 19) & 0x001f)) |
                        setMask32;

                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax) {
                    vram16[(i << 10) + j] =
                        (((cR1 >> 9) & 0x7c00) | ((cG1 >> 14) & 0x03e0) | ((cB1 >> 19) & 0x001f)) | setMask16;
                }
            }
            if (nextRowShade3()) return;
        }
        return;
    }

    if (m_ditherMode == 2) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX >> 16);
            xmax = (m_rightX >> 16) - 1;
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                cR1 = leftR;
                cG1 = leftG;
                cB1 = leftB;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    cR1 += j * difR;
                    cG1 += j * difG;
                    cB1 += j * difB;
                }

                for (j = xmin; j <= xmax; j++) {
                    getShadeTransColDither(&vram16[(i << 10) + j], (cB1 >> 16), (cG1 >> 16), (cR1 >> 16));

                    cR1 += difR;
                    cG1 += difG;
                    cB1 += difB;
                }
            }
            if (nextRowShade3()) return;
        }
    } else {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX >> 16);
            xmax = (m_rightX >> 16) - 1;
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                cR1 = leftR;
                cG1 = leftG;
                cB1 = leftB;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    cR1 += j * difR;
                    cG1 += j * difG;
                    cB1 += j * difB;
                }

                for (j = xmin; j <= xmax; j++) {
                    getShadeTransCol(&vram16[(i << 10) + j],
                                     ((cR1 >> 9) & 0x7c00) | ((cG1 >> 14) & 0x03e0) | ((cB1 >> 19) & 0x001f));

                    cR1 += difR;
                    cG1 += difG;
                    cB1 += difB;
                }
            }
            if (nextRowShade3()) return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPolyShade3(int32_t rgb1, int32_t rgb2, int32_t rgb3) {
    drawPoly3Gi(m_x0, m_y0, m_x1, m_y1, m_x2, m_y2, rgb1, rgb2, rgb3);
}

// draw two g-shaded tris for right psx shading emulation

void PCSX::SoftGPU::SoftRenderer::drawPolyShade4(int32_t rgb1, int32_t rgb2, int32_t rgb3, int32_t rgb4) {
    drawPoly3Gi(m_x1, m_y1, m_x3, m_y3, m_x2, m_y2, rgb2, rgb4, rgb3);
    drawPoly3Gi(m_x0, m_y0, m_x1, m_y1, m_x2, m_y2, rgb1, rgb2, rgb3);
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TGEx4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                 int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                                 int16_t ty3, int16_t clX, int16_t clY, int32_t col1, int32_t col2,
                                                 int32_t col3) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t cR1, cG1, cB1;
    int32_t difR, difB, difG, difR2, difB2, difG2;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP, XAdjust;
    int16_t tC1, tC2;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;
    const auto ditherMode = m_ditherMode;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!setupSectionsShadeTextured3(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3, col1, col2, col3)) return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRowShadeTextured3()) return;
    }

    clutP = (clY << 10) + clX;

    YAdjust = ((m_globalTextAddrY) << 11) + (m_globalTextAddrX << 1);
    YAdjust += (m_textureWindow.y0 << 11) + (m_textureWindow.x0 >> 1);

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
            xmin = ((m_leftX) >> 16);
            xmax = ((m_rightX) >> 16) - 1;  //!!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = m_leftU;
                posY = m_leftV;
                cR1 = leftR;
                cG1 = leftG;
                cB1 = leftB;

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
                    XAdjust = (posX >> 16) & maskX;
                    tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    XAdjust = ((posX + difX) >> 16) & maskX;
                    tC2 =
                        vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                    tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;
                    getTextureTransColShadeX32Solid(
                        (uint32_t *)&vram16[(i << 10) + j], vram16[clutP + tC1] | ((int32_t)vram16[clutP + tC2]) << 16,
                        (cB1 >> 16) | ((cB1 + difB) & 0xff0000), (cG1 >> 16) | ((cG1 + difG) & 0xff0000),
                        (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                    posX += difX2;
                    posY += difY2;
                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax) {
                    XAdjust = (posX >> 16) & maskX;
                    tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    getTextureTransColShadeXSolid(&vram16[(i << 10) + j], vram16[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                                  (cR1 >> 16));
                }
            }
            if (nextRowShadeTextured3()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX >> 16);
        xmax = (m_rightX >> 16) - 1;  //!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = m_leftU;
            posY = m_leftV;
            cR1 = leftR;
            cG1 = leftG;
            cB1 = leftB;

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
                XAdjust = (posX >> 16) & maskX;
                tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                if (ditherMode) {
                    getTextureTransColShadeXDither(&vram16[(i << 10) + j], vram16[clutP + tC1], (cB1 >> 16),
                                                   (cG1 >> 16), (cR1 >> 16));
                } else {
                    getTextureTransColShadeX(&vram16[(i << 10) + j], vram16[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                             (cR1 >> 16));
                }
                posX += difX;
                posY += difY;
                cR1 += difR;
                cG1 += difG;
                cB1 += difB;
            }
        }
        if (nextRowShadeTextured3()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TGEx4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                 int16_t x4, int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2,
                                                 int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4,
                                                 int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col3,
                                                 int32_t col4) {
    drawPoly3TGEx4(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4, clX, clY, col2, col4, col3);
    drawPoly3TGEx4(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4, clX, clY, col1, col2, col3);
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TGEx8(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                 int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                                 int16_t ty3, int16_t clX, int16_t clY, int32_t col1, int32_t col2,
                                                 int32_t col3) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t cR1, cG1, cB1;
    int32_t difR, difB, difG, difR2, difB2, difG2;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP;
    int16_t tC1, tC2;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;
    const auto ditherMode = m_ditherMode;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!setupSectionsShadeTextured3(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3, col1, col2, col3)) return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRowShadeTextured3()) return;
    }

    clutP = (clY << 10) + clX;

    YAdjust = ((m_globalTextAddrY) << 11) + (m_globalTextAddrX << 1);
    YAdjust += (m_textureWindow.y0 << 11) + (m_textureWindow.x0);

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
            xmin = (m_leftX >> 16);
            xmax = (m_rightX >> 16) - 1;  // !!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = m_leftU;
                posY = m_leftV;
                cR1 = leftR;
                cG1 = leftG;
                cB1 = leftB;

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
                    tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + ((posX >> 16) & maskX))];
                    tC2 = vram[static_cast<int32_t>(((((posY + difY) >> 16) & maskY) << 11) + YAdjust +
                                                    (((posX + difX) >> 16) & maskX))];

                    getTextureTransColShadeX32Solid(
                        (uint32_t *)&vram16[(i << 10) + j], vram16[clutP + tC1] | ((int32_t)vram16[clutP + tC2]) << 16,
                        (cB1 >> 16) | ((cB1 + difB) & 0xff0000), (cG1 >> 16) | ((cG1 + difG) & 0xff0000),
                        (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                    posX += difX2;
                    posY += difY2;
                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax) {
                    tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + ((posX >> 16) & maskX))];
                    getTextureTransColShadeXSolid(&vram16[(i << 10) + j], vram16[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                                  (cR1 >> 16));
                }
            }
            if (nextRowShadeTextured3()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX >> 16);
        xmax = (m_rightX >> 16) - 1;  //!!!!!!!!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = m_leftU;
            posY = m_leftV;
            cR1 = leftR;
            cG1 = leftG;
            cB1 = leftB;

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
                tC1 = vram[static_cast<int32_t>((((posY >> 16) & maskY) << 11) + YAdjust + ((posX >> 16) & maskX))];
                if (ditherMode) {
                    getTextureTransColShadeXDither(&vram16[(i << 10) + j], vram16[clutP + tC1], (cB1 >> 16),
                                                   (cG1 >> 16), (cR1 >> 16));
                } else {
                    getTextureTransColShadeX(&vram16[(i << 10) + j], vram16[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                             (cR1 >> 16));
                }
                posX += difX;
                posY += difY;
                cR1 += difR;
                cG1 += difG;
                cB1 += difB;
            }
        }
        if (nextRowShadeTextured3()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TGEx8(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                 int16_t x4, int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2,
                                                 int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4,
                                                 int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col3,
                                                 int32_t col4) {
    drawPoly3TGEx8(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4, clX, clY, col2, col4, col3);
    drawPoly3TGEx8(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4, clX, clY, col1, col2, col3);
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TGD(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                               int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                               int16_t ty3, int32_t col1, int32_t col2, int32_t col3) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t cR1, cG1, cB1;
    int32_t difR, difB, difG, difR2, difB2, difG2;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;
    const auto ditherMode = m_ditherMode;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!setupSectionsShadeTextured3(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3, col1, col2, col3)) return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRowShadeTextured3()) return;
    }

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
            xmin = (m_leftX >> 16);
            xmax = (m_rightX >> 16) - 1;  //!!!!!!!!!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = m_leftU;
                posY = m_leftV;
                cR1 = leftR;
                cG1 = leftG;
                cB1 = leftB;

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
                    getTextureTransColShadeX32Solid(
                        (uint32_t *)&vram16[(i << 10) + j],
                        (((int32_t)
                              vram16[(((((posY + difY) >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                                     (((posX + difX) >> 16) & maskX) + globalTextAddrX + textureWindow.x0])
                         << 16) |
                            vram16[((((posY >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                                   (((posX) >> 16) & maskX) + globalTextAddrX + textureWindow.x0],
                        (cB1 >> 16) | ((cB1 + difB) & 0xff0000), (cG1 >> 16) | ((cG1 + difG) & 0xff0000),
                        (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                    posX += difX2;
                    posY += difY2;
                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax) {
                    getTextureTransColShadeXSolid(
                        &vram16[(i << 10) + j],
                        vram16[((((posY >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                               ((posX >> 16) & maskX) + globalTextAddrX + textureWindow.x0],
                        (cB1 >> 16), (cG1 >> 16), (cR1 >> 16));
                }
            }
            if (nextRowShadeTextured3()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX >> 16);
        xmax = (m_rightX >> 16) - 1;  //!!!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = m_leftU;
            posY = m_leftV;
            cR1 = leftR;
            cG1 = leftG;
            cB1 = leftB;

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
                if (ditherMode) {
                    getTextureTransColShadeXDither(
                        &vram16[(i << 10) + j],
                        vram16[((((posY >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                               ((posX >> 16) & maskX) + globalTextAddrX + textureWindow.x0],
                        (cB1 >> 16), (cG1 >> 16), (cR1 >> 16));
                } else {
                    getTextureTransColShadeX(
                        &vram16[(i << 10) + j],
                        vram16[((((posY >> 16) & maskY) + globalTextAddrY + textureWindow.y0) << 10) +
                               ((posX >> 16) & maskX) + globalTextAddrX + textureWindow.x0],
                        (cB1 >> 16), (cG1 >> 16), (cR1 >> 16));
                }
                posX += difX;
                posY += difY;
                cR1 += difR;
                cG1 += difG;
                cB1 += difB;
            }
        }
        if (nextRowShadeTextured3()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TGD(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                               int16_t x4, int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2,
                                               int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4,
                                               int32_t col1, int32_t col2, int32_t col3, int32_t col4) {
    drawPoly3TGD(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4, col2, col4, col3);
    drawPoly3TGD(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4, col1, col2, col3);
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::line_E_SE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1) {
    int dx, dy, incrE, incrSE, d;
    uint32_t r0, g0, b0, r1, g1, b1;
    int32_t dr, dg, db;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;
    const auto ditherMode = m_ditherMode;

    r0 = (rgb0 & 0x00ff0000);
    g0 = (rgb0 & 0x0000ff00) << 8;
    b0 = (rgb0 & 0x000000ff) << 16;
    r1 = (rgb1 & 0x00ff0000);
    g1 = (rgb1 & 0x0000ff00) << 8;
    b1 = (rgb1 & 0x000000ff) << 16;

    dx = x1 - x0;
    dy = y1 - y0;

    if (dx > 0) {
        dr = ((int32_t)r1 - (int32_t)r0) / dx;
        dg = ((int32_t)g1 - (int32_t)g0) / dx;
        db = ((int32_t)b1 - (int32_t)b0) / dx;
    } else {
        dr = ((int32_t)r1 - (int32_t)r0);
        dg = ((int32_t)g1 - (int32_t)g0);
        db = ((int32_t)b1 - (int32_t)b0);
    }

    d = 2 * dy - dx;        /* Initial value of d */
    incrE = 2 * dy;         /* incr. used for move to E */
    incrSE = 2 * (dy - dx); /* incr. used for move to SE */

    if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH)) {
        getShadeTransCol(&vram16[(y0 << 10) + x0],
                         (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
    }

    while (x0 < x1) {
        if (d <= 0) {
            d = d + incrE; /* Choose E */
        } else {
            d = d + incrSE; /* Choose SE */
            y0++;
        }
        x0++;

        r0 += dr;
        g0 += dg;
        b0 += db;

        if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH)) {
            getShadeTransCol(&vram16[(y0 << 10) + x0],
                             (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
        }
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::line_S_SE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1) {
    int dx, dy, incrS, incrSE, d;
    uint32_t r0, g0, b0, r1, g1, b1;
    int32_t dr, dg, db;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;
    const auto ditherMode = m_ditherMode;

    r0 = (rgb0 & 0x00ff0000);
    g0 = (rgb0 & 0x0000ff00) << 8;
    b0 = (rgb0 & 0x000000ff) << 16;
    r1 = (rgb1 & 0x00ff0000);
    g1 = (rgb1 & 0x0000ff00) << 8;
    b1 = (rgb1 & 0x000000ff) << 16;

    dx = x1 - x0;
    dy = y1 - y0;

    if (dy > 0) {
        dr = ((int32_t)r1 - (int32_t)r0) / dy;
        dg = ((int32_t)g1 - (int32_t)g0) / dy;
        db = ((int32_t)b1 - (int32_t)b0) / dy;
    } else {
        dr = ((int32_t)r1 - (int32_t)r0);
        dg = ((int32_t)g1 - (int32_t)g0);
        db = ((int32_t)b1 - (int32_t)b0);
    }

    d = 2 * dx - dy;        /* Initial value of d */
    incrS = 2 * dx;         /* incr. used for move to S */
    incrSE = 2 * (dx - dy); /* incr. used for move to SE */

    if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH)) {
        getShadeTransCol(&vram16[(y0 << 10) + x0],
                         (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
    }

    while (y0 < y1) {
        if (d <= 0) {
            d = d + incrS; /* Choose S */
        } else {
            d = d + incrSE; /* Choose SE */
            x0++;
        }
        y0++;

        r0 += dr;
        g0 += dg;
        b0 += db;

        if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH)) {
            getShadeTransCol(&vram16[(y0 << 10) + x0],
                             (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
        }
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::line_N_NE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1) {
    int dx, dy, incrN, incrNE, d;
    uint32_t r0, g0, b0, r1, g1, b1;
    int32_t dr, dg, db;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;
    const auto ditherMode = m_ditherMode;

    r0 = (rgb0 & 0x00ff0000);
    g0 = (rgb0 & 0x0000ff00) << 8;
    b0 = (rgb0 & 0x000000ff) << 16;
    r1 = (rgb1 & 0x00ff0000);
    g1 = (rgb1 & 0x0000ff00) << 8;
    b1 = (rgb1 & 0x000000ff) << 16;

    dx = x1 - x0;
    dy = -(y1 - y0);

    if (dy > 0) {
        dr = ((int32_t)r1 - (int32_t)r0) / dy;
        dg = ((int32_t)g1 - (int32_t)g0) / dy;
        db = ((int32_t)b1 - (int32_t)b0) / dy;
    } else {
        dr = ((int32_t)r1 - (int32_t)r0);
        dg = ((int32_t)g1 - (int32_t)g0);
        db = ((int32_t)b1 - (int32_t)b0);
    }

    d = 2 * dx - dy;        /* Initial value of d */
    incrN = 2 * dx;         /* incr. used for move to N */
    incrNE = 2 * (dx - dy); /* incr. used for move to NE */

    if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH)) {
        getShadeTransCol(&vram16[(y0 << 10) + x0],
                         (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
    }

    while (y0 > y1) {
        if (d <= 0) {
            d = d + incrN; /* Choose N */
        } else {
            d = d + incrNE; /* Choose NE */
            x0++;
        }
        y0--;

        r0 += dr;
        g0 += dg;
        b0 += db;

        if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH)) {
            getShadeTransCol(&vram16[(y0 << 10) + x0],
                             (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
        }
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::line_E_NE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1) {
    int dx, dy, incrE, incrNE, d;
    uint32_t r0, g0, b0, r1, g1, b1;
    int32_t dr, dg, db;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;
    const auto ditherMode = m_ditherMode;

    r0 = (rgb0 & 0x00ff0000);
    g0 = (rgb0 & 0x0000ff00) << 8;
    b0 = (rgb0 & 0x000000ff) << 16;
    r1 = (rgb1 & 0x00ff0000);
    g1 = (rgb1 & 0x0000ff00) << 8;
    b1 = (rgb1 & 0x000000ff) << 16;

    dx = x1 - x0;
    dy = -(y1 - y0);

    if (dx > 0) {
        dr = ((int32_t)r1 - (int32_t)r0) / dx;
        dg = ((int32_t)g1 - (int32_t)g0) / dx;
        db = ((int32_t)b1 - (int32_t)b0) / dx;
    } else {
        dr = ((int32_t)r1 - (int32_t)r0);
        dg = ((int32_t)g1 - (int32_t)g0);
        db = ((int32_t)b1 - (int32_t)b0);
    }

    d = 2 * dy - dx;        /* Initial value of d */
    incrE = 2 * dy;         /* incr. used for move to E */
    incrNE = 2 * (dy - dx); /* incr. used for move to NE */

    if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH)) {
        getShadeTransCol(&vram16[(y0 << 10) + x0],
                         (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
    }

    while (x0 < x1) {
        if (d <= 0) {
            d = d + incrE; /* Choose E */
        } else {
            d = d + incrNE; /* Choose NE */
            y0--;
        }
        x0++;

        r0 += dr;
        g0 += dg;
        b0 += db;

        if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH)) {
            getShadeTransCol(&vram16[(y0 << 10) + x0],
                             (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
        }
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::vertLineShade(int x, int y0, int y1, uint32_t rgb0, uint32_t rgb1) {
    int y, dy;
    uint32_t r0, g0, b0, r1, g1, b1;
    int32_t dr, dg, db;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;
    const auto ditherMode = m_ditherMode;

    r0 = (rgb0 & 0x00ff0000);
    g0 = (rgb0 & 0x0000ff00) << 8;
    b0 = (rgb0 & 0x000000ff) << 16;
    r1 = (rgb1 & 0x00ff0000);
    g1 = (rgb1 & 0x0000ff00) << 8;
    b1 = (rgb1 & 0x000000ff) << 16;

    dy = (y1 - y0);

    if (dy > 0) {
        dr = ((int32_t)r1 - (int32_t)r0) / dy;
        dg = ((int32_t)g1 - (int32_t)g0) / dy;
        db = ((int32_t)b1 - (int32_t)b0) / dy;
    } else {
        dr = ((int32_t)r1 - (int32_t)r0);
        dg = ((int32_t)g1 - (int32_t)g0);
        db = ((int32_t)b1 - (int32_t)b0);
    }

    if (y0 < m_drawY) {
        r0 += dr * (m_drawY - y0);
        g0 += dg * (m_drawY - y0);
        b0 += db * (m_drawY - y0);
        y0 = m_drawY;
    }

    if (y1 > m_drawH) y1 = m_drawH;

    for (y = y0; y <= y1; y++) {
        getShadeTransCol(&vram16[(y << 10) + x],
                         (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
        r0 += dr;
        g0 += dg;
        b0 += db;
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::horzLineShade(int y, int x0, int x1, uint32_t rgb0, uint32_t rgb1) {
    int x, dx;
    uint32_t r0, g0, b0, r1, g1, b1;
    int32_t dr, dg, db;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;
    const auto ditherMode = m_ditherMode;

    r0 = (rgb0 & 0x00ff0000);
    g0 = (rgb0 & 0x0000ff00) << 8;
    b0 = (rgb0 & 0x000000ff) << 16;
    r1 = (rgb1 & 0x00ff0000);
    g1 = (rgb1 & 0x0000ff00) << 8;
    b1 = (rgb1 & 0x000000ff) << 16;

    dx = (x1 - x0);

    if (dx > 0) {
        dr = ((int32_t)r1 - (int32_t)r0) / dx;
        dg = ((int32_t)g1 - (int32_t)g0) / dx;
        db = ((int32_t)b1 - (int32_t)b0) / dx;
    } else {
        dr = ((int32_t)r1 - (int32_t)r0);
        dg = ((int32_t)g1 - (int32_t)g0);
        db = ((int32_t)b1 - (int32_t)b0);
    }

    if (x0 < m_drawX) {
        r0 += dr * (m_drawX - x0);
        g0 += dg * (m_drawX - x0);
        b0 += db * (m_drawX - x0);
        x0 = m_drawX;
    }

    if (x1 > m_drawW) x1 = m_drawW;

    for (x = x0; x <= x1; x++) {
        getShadeTransCol(&vram16[(y << 10) + x],
                         (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
        r0 += dr;
        g0 += dg;
        b0 += db;
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::line_E_SE_Flat(int x0, int y0, int x1, int y1, uint16_t color) {
    int dx, dy, incrE, incrSE, d, x, y;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;
    const auto ditherMode = m_ditherMode;

    dx = x1 - x0;
    dy = y1 - y0;
    d = 2 * dy - dx;        /* Initial value of d */
    incrE = 2 * dy;         /* incr. used for move to E */
    incrSE = 2 * (dy - dx); /* incr. used for move to SE */
    x = x0;
    y = y0;
    if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH)) {
        getShadeTransCol(&vram16[(y << 10) + x], color);
    }

    while (x < x1) {
        if (d <= 0) {
            d = d + incrE; /* Choose E */
            x++;
        } else {
            d = d + incrSE; /* Choose SE */
            x++;
            y++;
        }
        if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH)) {
            getShadeTransCol(&vram16[(y << 10) + x], color);
        }
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::line_S_SE_Flat(int x0, int y0, int x1, int y1, uint16_t color) {
    int dx, dy, incrS, incrSE, d, x, y;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;
    const auto ditherMode = m_ditherMode;

    dx = x1 - x0;
    dy = y1 - y0;
    d = 2 * dx - dy;        /* Initial value of d */
    incrS = 2 * dx;         /* incr. used for move to S */
    incrSE = 2 * (dx - dy); /* incr. used for move to SE */
    x = x0;
    y = y0;
    if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH)) {
        getShadeTransCol(&vram16[(y << 10) + x], color);
    }

    while (y < y1) {
        if (d <= 0) {
            d = d + incrS; /* Choose S */
            y++;
        } else {
            d = d + incrSE; /* Choose SE */
            x++;
            y++;
        }
        if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH)) {
            getShadeTransCol(&vram16[(y << 10) + x], color);
        }
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::line_N_NE_Flat(int x0, int y0, int x1, int y1, uint16_t color) {
    int dx, dy, incrN, incrNE, d, x, y;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;
    const auto ditherMode = m_ditherMode;

    dx = x1 - x0;
    dy = -(y1 - y0);
    d = 2 * dx - dy;        /* Initial value of d */
    incrN = 2 * dx;         /* incr. used for move to N */
    incrNE = 2 * (dx - dy); /* incr. used for move to NE */
    x = x0;
    y = y0;
    if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH)) {
        getShadeTransCol(&vram16[(y << 10) + x], color);
    }

    while (y > y1) {
        if (d <= 0) {
            d = d + incrN; /* Choose N */
            y--;
        } else {
            d = d + incrNE; /* Choose NE */
            x++;
            y--;
        }
        if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH)) {
            getShadeTransCol(&vram16[(y << 10) + x], color);
        }
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::line_E_NE_Flat(int x0, int y0, int x1, int y1, uint16_t color) {
    int dx, dy, incrE, incrNE, d, x, y;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;
    const auto ditherMode = m_ditherMode;

    dx = x1 - x0;
    dy = -(y1 - y0);
    d = 2 * dy - dx;        /* Initial value of d */
    incrE = 2 * dy;         /* incr. used for move to E */
    incrNE = 2 * (dy - dx); /* incr. used for move to NE */
    x = x0;
    y = y0;
    if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH)) {
        getShadeTransCol(&vram16[(y << 10) + x], color);
    }

    while (x < x1) {
        if (d <= 0) {
            d = d + incrE; /* Choose E */
            x++;
        } else {
            d = d + incrNE; /* Choose NE */
            x++;
            y--;
        }
        if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH)) {
            getShadeTransCol(&vram16[(y << 10) + x], color);
        }
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::vertLineFlat(int x, int y0, int y1, uint16_t color) {
    int y;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;
    const auto ditherMode = m_ditherMode;

    if (y0 < drawY) y0 = drawY;
    if (y1 > drawH) y1 = drawH;

    for (y = y0; y <= y1; y++) {
        getShadeTransCol(&vram16[(y << 10) + x], color);
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::horzLineFlat(int y, int x0, int x1, uint16_t color) {
    int x;

    const auto vram = m_vram;
    const auto vram16 = m_vram16;
    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;
    const auto maskX = m_textureWindow.x1 - 1;
    const auto maskY = m_textureWindow.y1 - 1;
    const auto globalTextAddrX = m_globalTextAddrX;
    const auto globalTextAddrY = m_globalTextAddrY;
    const auto textureWindow = m_textureWindow;
    const auto leftR = m_leftR;
    const auto leftG = m_leftG;
    const auto leftB = m_leftB;
    const auto setMask16 = m_setMask16;
    const auto setMask32 = m_setMask32;
    const auto ditherMode = m_ditherMode;

    if (x0 < drawX) x0 = drawX;
    if (x1 > drawW) x1 = drawW;

    for (x = x0; x <= x1; x++) {
        getShadeTransCol(&vram16[(y << 10) + x], color);
    }
}

///////////////////////////////////////////////////////////////////////

/* Bresenham Line drawing function */
void PCSX::SoftGPU::SoftRenderer::drawSoftwareLineShade(int32_t rgb0, int32_t rgb1) {
    int16_t x0, y0, x1, y1, xt, yt;
    double m, dy, dx;

    x0 = m_x0;
    y0 = m_y0;
    x1 = m_x1;
    y1 = m_y1;

    if (x0 > m_drawW && x1 > m_drawW) return;
    if (y0 > m_drawH && y1 > m_drawH) return;
    if (x0 < m_drawX && x1 < m_drawX) return;
    if (y0 < m_drawY && y1 < m_drawY) return;
    if (m_drawY >= m_drawH) return;
    if (m_drawX >= m_drawW) return;

    dx = x1 - x0;
    dy = y1 - y0;

    if (dx == 0) {
        if (dy > 0) {
            vertLineShade(x0, y0, y1, rgb0, rgb1);
        } else {
            vertLineShade(x0, y1, y0, rgb1, rgb0);
        }
    } else if (dy == 0) {
        if (dx > 0) {
            horzLineShade(y0, x0, x1, rgb0, rgb1);
        } else {
            horzLineShade(y0, x1, x0, rgb1, rgb0);
        }
    } else {
        if (dx < 0) {
            xt = x0;
            yt = y0;
            x0 = x1;
            y0 = y1;
            rgb0 = rgb1;
            x1 = xt;
            y1 = yt;
            rgb1 = rgb0;

            dx = x1 - x0;
            dy = y1 - y0;
        }

        m = dy / dx;

        if (m >= 0) {
            if (m > 1) {
                line_S_SE_Shade(x0, y0, x1, y1, rgb0, rgb1);
            } else {
                line_E_SE_Shade(x0, y0, x1, y1, rgb0, rgb1);
            }
        } else if (m < -1) {
            line_N_NE_Shade(x0, y0, x1, y1, rgb0, rgb1);
        } else {
            line_E_NE_Shade(x0, y0, x1, y1, rgb0, rgb1);
        }
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawSoftwareLineFlat(int32_t rgb) {
    int16_t x0, y0, x1, y1, xt, yt;
    double m, dy, dx;
    uint16_t color = 0;

    x0 = m_x0;
    y0 = m_y0;
    x1 = m_x1;
    y1 = m_y1;

    if (x0 > m_drawW && x1 > m_drawW) return;
    if (y0 > m_drawH && y1 > m_drawH) return;
    if (x0 < m_drawX && x1 < m_drawX) return;
    if (y0 < m_drawY && y1 < m_drawY) return;
    if (m_drawY >= m_drawH) return;
    if (m_drawX >= m_drawW) return;

    color = ((rgb & 0x00f80000) >> 9) | ((rgb & 0x0000f800) >> 6) | ((rgb & 0x000000f8) >> 3);

    dx = x1 - x0;
    dy = y1 - y0;

    if (dx == 0) {
        if (dy == 0) {
            return;  // Nothing to draw
        } else if (dy > 0) {
            vertLineFlat(x0, y0, y1, color);
        } else {
            vertLineFlat(x0, y1, y0, color);
        }
    } else if (dy == 0) {
        if (dx > 0) {
            horzLineFlat(y0, x0, x1, color);
        } else {
            horzLineFlat(y0, x1, x0, color);
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
                line_S_SE_Flat(x0, y0, x1, y1, color);
            } else {
                line_E_SE_Flat(x0, y0, x1, y1, color);
            }
        } else if (m < -1) {
            line_N_NE_Flat(x0, y0, x1, y1, color);
        } else {
            line_E_NE_Flat(x0, y0, x1, y1, color);
        }
    }
}

///////////////////////////////////////////////////////////////////////
