/***************************************************************************
                          soft.c  -  description
                             -------------------
    begin                : Sun Oct 28 2001
    copyright            : (C) 2001 by Pete Bernert
    email                : BlackDove@addcom.de
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version. See also the license.txt file for *
 *   additional informations.                                              *
 *                                                                         *
 ***************************************************************************/

//*************************************************************************//
// History of changes:
//
// 2005/06/11 - Pete
// - added y sprite mirror
//
// 2005/04/15 - Pete
// - gamefix 0x200 controls g-shaded quads now
//
// 2005/04/12 - Pete
// - 25% blending mode 3
//
// 2004/02/01 - Pete
// - added ZN stuff... Tekken "IL" texture decoding infos kindly given by smf from the MAME team
//
// 2003/08/30 - Pete
// - added game fix 0x100 (dark forces)
//
// 2002/10/03 - Farfetch'd & Pete
// - changed: mask bit handling
//
// 2002/06/04 - Lewpy
// - new line drawing funcs
//
// 2002/05/24 - Pete
// - added additional handling for tex quads to avoid texture distortions
//
// 2002/05/14 - Pete
// - redone all texture window funcs... much faster now
//
// 2002/05/12 - Pete
// - Mask bit fix on non-textured/sprite prims
//
// 2002/03/27 - Pete
// - doom adjustment
//
// 2002/02/12 - Pete
// - removed "no sprite transparency" fix
//
// 2001/12/14 - Pete
// - added support for 15 bit texture window primitives
//
// 2001/12/10 - Pete
// - fixed a mask bit bug in drawPoly4F, causing troubles in MGS
//
// 2001/11/08 - Linuzappz
// - shl10idiv converted to nasm, C version still works :define __i386_
//   to use the asm version
//
// 2001/10/28 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#define NOMINMAX

#include "gpu/soft/soft.h"

#include <algorithm>

#include "gpu/soft/externals.h"

//#define VC_INLINE
#include "gpu/soft/gpu.h"
#include "gpu/soft/menu.h"
#include "gpu/soft/prim.h"

////////////////////////////////////////////////////////////////////////////////////
// "NO EDGE BUFFER" POLY VERSION... FUNCS BASED ON FATMAP.TXT FROM MRI / Doomsday
////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////
// defines
////////////////////////////////////////////////////////////////////////////////////

// switches for painting textured quads as 2 triangles (small glitches, but better shading!)
// can be toggled by game fix 0x200 in version 1.17 anyway, so let the defines enabled!

#define POLYQUAD3
#define POLYQUAD3GT

// fast solid loops... a bit more additional code, of course

#define FASTSOLID

// psx blending mode 3 with 25% incoming color (instead 50% without the define)

#define HALFBRIGHTMODE3

// color decode defines

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

////////////////////////////////////////////////////////////////////////
// POLYGON OFFSET FUNCS
////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::offsetPSXLine(void) {
    int16_t x0, x1, y0, y1, dx, dy;
    float px, py;

    x0 = lx0 + 1 + PSXDisplay.DrawOffset.x;
    x1 = lx1 + 1 + PSXDisplay.DrawOffset.x;
    y0 = ly0 + 1 + PSXDisplay.DrawOffset.y;
    y1 = ly1 + 1 + PSXDisplay.DrawOffset.y;

    dx = x1 - x0;
    dy = y1 - y0;

    // tricky line width without sqrt

    if (dx >= 0) {
        if (dy >= 0) {
            px = 0.5f;
            if (dx > dy)
                py = -0.5f;
            else if (dx < dy)
                py = 0.5f;
            else
                py = 0.0f;
        } else {
            py = -0.5f;
            dy = -dy;
            if (dx > dy)
                px = 0.5f;
            else if (dx < dy)
                px = -0.5f;
            else
                px = 0.0f;
        }
    } else {
        if (dy >= 0) {
            py = 0.5f;
            dx = -dx;
            if (dx > dy)
                px = -0.5f;
            else if (dx < dy)
                px = 0.5f;
            else
                px = 0.0f;
        } else {
            px = -0.5f;
            if (dx > dy)
                py = -0.5f;
            else if (dx < dy)
                py = 0.5f;
            else
                py = 0.0f;
        }
    }

    lx0 = (int16_t)((float)x0 - px);
    lx3 = (int16_t)((float)x0 + py);

    ly0 = (int16_t)((float)y0 - py);
    ly3 = (int16_t)((float)y0 - px);

    lx1 = (int16_t)((float)x1 - py);
    lx2 = (int16_t)((float)x1 + px);

    ly1 = (int16_t)((float)y1 + px);
    ly2 = (int16_t)((float)y1 + py);
}

void PCSX::SoftGPU::SoftRenderer::offsetPSX2(void) {
    lx0 += PSXDisplay.DrawOffset.x;
    ly0 += PSXDisplay.DrawOffset.y;
    lx1 += PSXDisplay.DrawOffset.x;
    ly1 += PSXDisplay.DrawOffset.y;
}

void PCSX::SoftGPU::SoftRenderer::offsetPSX3(void) {
    lx0 += PSXDisplay.DrawOffset.x;
    ly0 += PSXDisplay.DrawOffset.y;
    lx1 += PSXDisplay.DrawOffset.x;
    ly1 += PSXDisplay.DrawOffset.y;
    lx2 += PSXDisplay.DrawOffset.x;
    ly2 += PSXDisplay.DrawOffset.y;
}

void PCSX::SoftGPU::SoftRenderer::offsetPSX4(void) {
    lx0 += PSXDisplay.DrawOffset.x;
    ly0 += PSXDisplay.DrawOffset.y;
    lx1 += PSXDisplay.DrawOffset.x;
    ly1 += PSXDisplay.DrawOffset.y;
    lx2 += PSXDisplay.DrawOffset.x;
    ly2 += PSXDisplay.DrawOffset.y;
    lx3 += PSXDisplay.DrawOffset.x;
    ly3 += PSXDisplay.DrawOffset.y;
}

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
// PER PIXEL FUNCS
////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////

static const unsigned char dithertable[16] = {7, 0, 6, 1, 2, 5, 3, 4, 1, 6, 0, 7, 4, 3, 5, 2};

void Dither16(uint16_t *pdest, uint32_t r, uint32_t g, uint32_t b, uint16_t sM) {
    unsigned char coeff;
    unsigned char rlow, glow, blow;
    int x, y;

    x = pdest - psxVuw;
    y = x >> 10;
    x -= (y << 10);

    coeff = dithertable[(y & 3) * 4 + (x & 3)];

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

inline void PCSX::SoftGPU::SoftRenderer::GetShadeTransCol_Dither(uint16_t *pdest, int32_t m1, int32_t m2, int32_t m3) {
    int32_t r, g, b;

    if (bCheckMask && *pdest & 0x8000) return;

    if (DrawSemiTrans) {
        r = ((XCOL1D(*pdest)) << 3);
        b = ((XCOL2D(*pdest)) << 3);
        g = ((XCOL3D(*pdest)) << 3);

        if (GlobalTextABR == 0) {
            r = (r >> 1) + (m1 >> 1);
            b = (b >> 1) + (m2 >> 1);
            g = (g >> 1) + (m3 >> 1);
        } else if (GlobalTextABR == 1) {
            r += m1;
            b += m2;
            g += m3;
        } else if (GlobalTextABR == 2) {
            r -= m1;
            b -= m2;
            g -= m3;
            if (r & 0x80000000) r = 0;
            if (b & 0x80000000) b = 0;
            if (g & 0x80000000) g = 0;
        } else {
#ifdef HALFBRIGHTMODE3
            r += (m1 >> 2);
            b += (m2 >> 2);
            g += (m3 >> 2);
#else
            r += (m1 >> 1);
            b += (m2 >> 1);
            g += (m3 >> 1);
#endif
        }
    } else {
        r = m1;
        b = m2;
        g = m3;
    }

    if (r & 0x7FFFFF00) r = 0xff;
    if (b & 0x7FFFFF00) b = 0xff;
    if (g & 0x7FFFFF00) g = 0xff;

    Dither16(pdest, r, b, g, sSetMask);
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SoftGPU::SoftRenderer::GetShadeTransCol(uint16_t *pdest, uint16_t color) {
    if (bCheckMask && *pdest & 0x8000) return;

    if (DrawSemiTrans) {
        int32_t r, g, b;

        if (GlobalTextABR == 0) {
            *pdest = ((((*pdest) & 0x7bde) >> 1) + (((color)&0x7bde) >> 1)) | sSetMask;  // 0x8000;
            return;
            /*
                 r=(XCOL1(*pdest)>>1)+((XCOL1(color))>>1);
                 b=(XCOL2(*pdest)>>1)+((XCOL2(color))>>1);
                 g=(XCOL3(*pdest)>>1)+((XCOL3(color))>>1);
            */
        } else if (GlobalTextABR == 1) {
            r = (XCOL1(*pdest)) + ((XCOL1(color)));
            b = (XCOL2(*pdest)) + ((XCOL2(color)));
            g = (XCOL3(*pdest)) + ((XCOL3(color)));
        } else if (GlobalTextABR == 2) {
            r = (XCOL1(*pdest)) - ((XCOL1(color)));
            b = (XCOL2(*pdest)) - ((XCOL2(color)));
            g = (XCOL3(*pdest)) - ((XCOL3(color)));
            if (r & 0x80000000) r = 0;
            if (b & 0x80000000) b = 0;
            if (g & 0x80000000) g = 0;
        } else {
#ifdef HALFBRIGHTMODE3
            r = (XCOL1(*pdest)) + ((XCOL1(color)) >> 2);
            b = (XCOL2(*pdest)) + ((XCOL2(color)) >> 2);
            g = (XCOL3(*pdest)) + ((XCOL3(color)) >> 2);
#else
            r = (XCOL1(*pdest)) + ((XCOL1(color)) >> 1);
            b = (XCOL2(*pdest)) + ((XCOL2(color)) >> 1);
            g = (XCOL3(*pdest)) + ((XCOL3(color)) >> 1);
#endif
        }

        if (r & 0x7FFFFFE0) r = 0x1f;
        if (b & 0x7FFFFC00) b = 0x3e0;
        if (g & 0x7FFF8000) g = 0x7c00;

        *pdest = (XPSXCOL(r, g, b)) | sSetMask;  // 0x8000;
    } else
        *pdest = color | sSetMask;
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SoftGPU::SoftRenderer::GetShadeTransCol32(uint32_t *pdest, uint32_t color) {
    if (DrawSemiTrans) {
        int32_t r, g, b;

        if (GlobalTextABR == 0) {
            if (!bCheckMask) {
                *pdest = ((((*pdest) & 0x7bde7bde) >> 1) + (((color)&0x7bde7bde) >> 1)) | lSetMask;  // 0x80008000;
                return;
            }
            r = (X32ACOL1(*pdest) >> 1) + ((X32ACOL1(color)) >> 1);
            b = (X32ACOL2(*pdest) >> 1) + ((X32ACOL2(color)) >> 1);
            g = (X32ACOL3(*pdest) >> 1) + ((X32ACOL3(color)) >> 1);
        } else if (GlobalTextABR == 1) {
            r = (X32COL1(*pdest)) + ((X32COL1(color)));
            b = (X32COL2(*pdest)) + ((X32COL2(color)));
            g = (X32COL3(*pdest)) + ((X32COL3(color)));
        } else if (GlobalTextABR == 2) {
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
#ifdef HALFBRIGHTMODE3
            r = (X32COL1(*pdest)) + ((X32BCOL1(color)) >> 2);
            b = (X32COL2(*pdest)) + ((X32BCOL2(color)) >> 2);
            g = (X32COL3(*pdest)) + ((X32BCOL3(color)) >> 2);
#else
            r = (X32COL1(*pdest)) + ((X32ACOL1(color)) >> 1);
            b = (X32COL2(*pdest)) + ((X32ACOL2(color)) >> 1);
            g = (X32COL3(*pdest)) + ((X32ACOL3(color)) >> 1);
#endif
        }

        if (r & 0x7FE00000) r = 0x1f0000 | (r & 0xFFFF);
        if (r & 0x7FE0) r = 0x1f | (r & 0xFFFF0000);
        if (b & 0x7FE00000) b = 0x1f0000 | (b & 0xFFFF);
        if (b & 0x7FE0) b = 0x1f | (b & 0xFFFF0000);
        if (g & 0x7FE00000) g = 0x1f0000 | (g & 0xFFFF);
        if (g & 0x7FE0) g = 0x1f | (g & 0xFFFF0000);

        if (bCheckMask) {
            uint32_t ma = *pdest;
            *pdest = (X32PSXCOL(r, g, b)) | lSetMask;  // 0x80008000;
            if (ma & 0x80000000) *pdest = (ma & 0xFFFF0000) | (*pdest & 0xFFFF);
            if (ma & 0x00008000) *pdest = (ma & 0xFFFF) | (*pdest & 0xFFFF0000);
            return;
        }
        *pdest = (X32PSXCOL(r, g, b)) | lSetMask;  // 0x80008000;
    } else {
        if (bCheckMask) {
            uint32_t ma = *pdest;
            *pdest = color | lSetMask;  // 0x80008000;
            if (ma & 0x80000000) *pdest = (ma & 0xFFFF0000) | (*pdest & 0xFFFF);
            if (ma & 0x00008000) *pdest = (ma & 0xFFFF) | (*pdest & 0xFFFF0000);
            return;
        }

        *pdest = color | lSetMask;  // 0x80008000;
    }
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SoftGPU::SoftRenderer::GetTextureTransColG(uint16_t *pdest, uint16_t color) {
    int32_t r, g, b;
    uint16_t l;

    if (color == 0) return;

    if (bCheckMask && *pdest & 0x8000) return;

    l = sSetMask | (color & 0x8000);

    if (DrawSemiTrans && (color & 0x8000)) {
        if (GlobalTextABR == 0) {
            uint16_t d;
            d = ((*pdest) & 0x7bde) >> 1;
            color = ((color)&0x7bde) >> 1;
            r = (XCOL1(d)) + ((((XCOL1(color))) * g_m1) >> 7);
            b = (XCOL2(d)) + ((((XCOL2(color))) * g_m2) >> 7);
            g = (XCOL3(d)) + ((((XCOL3(color))) * g_m3) >> 7);

            /*
                 r=(XCOL1(*pdest)>>1)+((((XCOL1(color))>>1)* g_m1)>>7);
                 b=(XCOL2(*pdest)>>1)+((((XCOL2(color))>>1)* g_m2)>>7);
                 g=(XCOL3(*pdest)>>1)+((((XCOL3(color))>>1)* g_m3)>>7);
            */
        } else if (GlobalTextABR == 1) {
            r = (XCOL1(*pdest)) + ((((XCOL1(color))) * g_m1) >> 7);
            b = (XCOL2(*pdest)) + ((((XCOL2(color))) * g_m2) >> 7);
            g = (XCOL3(*pdest)) + ((((XCOL3(color))) * g_m3) >> 7);
        } else if (GlobalTextABR == 2) {
            r = (XCOL1(*pdest)) - ((((XCOL1(color))) * g_m1) >> 7);
            b = (XCOL2(*pdest)) - ((((XCOL2(color))) * g_m2) >> 7);
            g = (XCOL3(*pdest)) - ((((XCOL3(color))) * g_m3) >> 7);
            if (r & 0x80000000) r = 0;
            if (b & 0x80000000) b = 0;
            if (g & 0x80000000) g = 0;
        } else {
#ifdef HALFBRIGHTMODE3
            r = (XCOL1(*pdest)) + ((((XCOL1(color)) >> 2) * g_m1) >> 7);
            b = (XCOL2(*pdest)) + ((((XCOL2(color)) >> 2) * g_m2) >> 7);
            g = (XCOL3(*pdest)) + ((((XCOL3(color)) >> 2) * g_m3) >> 7);
#else
            r = (XCOL1(*pdest)) + ((((XCOL1(color)) >> 1) * g_m1) >> 7);
            b = (XCOL2(*pdest)) + ((((XCOL2(color)) >> 1) * g_m2) >> 7);
            g = (XCOL3(*pdest)) + ((((XCOL3(color)) >> 1) * g_m3) >> 7);
#endif
        }
    } else {
        r = ((XCOL1(color)) * g_m1) >> 7;
        b = ((XCOL2(color)) * g_m2) >> 7;
        g = ((XCOL3(color)) * g_m3) >> 7;
    }

    if (r & 0x7FFFFFE0) r = 0x1f;
    if (b & 0x7FFFFC00) b = 0x3e0;
    if (g & 0x7FFF8000) g = 0x7c00;

    *pdest = (XPSXCOL(r, g, b)) | l;
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SoftGPU::SoftRenderer::GetTextureTransColG_S(uint16_t *pdest, uint16_t color) {
    int32_t r, g, b;
    uint16_t l;

    if (color == 0) return;

    l = sSetMask | (color & 0x8000);

    r = ((XCOL1(color)) * g_m1) >> 7;
    b = ((XCOL2(color)) * g_m2) >> 7;
    g = ((XCOL3(color)) * g_m3) >> 7;

    if (r & 0x7FFFFFE0) r = 0x1f;
    if (b & 0x7FFFFC00) b = 0x3e0;
    if (g & 0x7FFF8000) g = 0x7c00;

    *pdest = (XPSXCOL(r, g, b)) | l;
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SoftGPU::SoftRenderer::GetTextureTransColG_SPR(uint16_t *pdest, uint16_t color) {
    int32_t r, g, b;
    uint16_t l;

    if (color == 0) return;

    if (bCheckMask && *pdest & 0x8000) return;

    l = sSetMask | (color & 0x8000);

    if (DrawSemiTrans && (color & 0x8000)) {
        if (GlobalTextABR == 0) {
            uint16_t d;
            d = ((*pdest) & 0x7bde) >> 1;
            color = ((color)&0x7bde) >> 1;
            r = (XCOL1(d)) + ((((XCOL1(color))) * g_m1) >> 7);
            b = (XCOL2(d)) + ((((XCOL2(color))) * g_m2) >> 7);
            g = (XCOL3(d)) + ((((XCOL3(color))) * g_m3) >> 7);

            /*
                 r=(XCOL1(*pdest)>>1)+((((XCOL1(color))>>1)* g_m1)>>7);
                 b=(XCOL2(*pdest)>>1)+((((XCOL2(color))>>1)* g_m2)>>7);
                 g=(XCOL3(*pdest)>>1)+((((XCOL3(color))>>1)* g_m3)>>7);
            */
        } else if (GlobalTextABR == 1) {
            r = (XCOL1(*pdest)) + ((((XCOL1(color))) * g_m1) >> 7);
            b = (XCOL2(*pdest)) + ((((XCOL2(color))) * g_m2) >> 7);
            g = (XCOL3(*pdest)) + ((((XCOL3(color))) * g_m3) >> 7);
        } else if (GlobalTextABR == 2) {
            r = (XCOL1(*pdest)) - ((((XCOL1(color))) * g_m1) >> 7);
            b = (XCOL2(*pdest)) - ((((XCOL2(color))) * g_m2) >> 7);
            g = (XCOL3(*pdest)) - ((((XCOL3(color))) * g_m3) >> 7);
            if (r & 0x80000000) r = 0;
            if (b & 0x80000000) b = 0;
            if (g & 0x80000000) g = 0;
        } else {
#ifdef HALFBRIGHTMODE3
            r = (XCOL1(*pdest)) + ((((XCOL1(color)) >> 2) * g_m1) >> 7);
            b = (XCOL2(*pdest)) + ((((XCOL2(color)) >> 2) * g_m2) >> 7);
            g = (XCOL3(*pdest)) + ((((XCOL3(color)) >> 2) * g_m3) >> 7);
#else
            r = (XCOL1(*pdest)) + ((((XCOL1(color)) >> 1) * g_m1) >> 7);
            b = (XCOL2(*pdest)) + ((((XCOL2(color)) >> 1) * g_m2) >> 7);
            g = (XCOL3(*pdest)) + ((((XCOL3(color)) >> 1) * g_m3) >> 7);
#endif
        }
    } else {
        r = ((XCOL1(color)) * g_m1) >> 7;
        b = ((XCOL2(color)) * g_m2) >> 7;
        g = ((XCOL3(color)) * g_m3) >> 7;
    }

    if (r & 0x7FFFFFE0) r = 0x1f;
    if (b & 0x7FFFFC00) b = 0x3e0;
    if (g & 0x7FFF8000) g = 0x7c00;

    *pdest = (XPSXCOL(r, g, b)) | l;
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SoftGPU::SoftRenderer::GetTextureTransColG32(uint32_t *pdest, uint32_t color) {
    int32_t r, g, b, l;

    if (color == 0) return;

    l = lSetMask | (color & 0x80008000);

    if (DrawSemiTrans && (color & 0x80008000)) {
        if (GlobalTextABR == 0) {
            r = ((((X32TCOL1(*pdest)) + ((X32COL1(color)) * g_m1)) & 0xFF00FF00) >> 8);
            b = ((((X32TCOL2(*pdest)) + ((X32COL2(color)) * g_m2)) & 0xFF00FF00) >> 8);
            g = ((((X32TCOL3(*pdest)) + ((X32COL3(color)) * g_m3)) & 0xFF00FF00) >> 8);
        } else if (GlobalTextABR == 1) {
            r = (X32COL1(*pdest)) + (((((X32COL1(color))) * g_m1) & 0xFF80FF80) >> 7);
            b = (X32COL2(*pdest)) + (((((X32COL2(color))) * g_m2) & 0xFF80FF80) >> 7);
            g = (X32COL3(*pdest)) + (((((X32COL3(color))) * g_m3) & 0xFF80FF80) >> 7);
        } else if (GlobalTextABR == 2) {
            int32_t t;
            r = (((((X32COL1(color))) * g_m1) & 0xFF80FF80) >> 7);
            t = (*pdest & 0x001f0000) - (r & 0x003f0000);
            if (t & 0x80000000) t = 0;
            r = (*pdest & 0x0000001f) - (r & 0x0000003f);
            if (r & 0x80000000) r = 0;
            r |= t;

            b = (((((X32COL2(color))) * g_m2) & 0xFF80FF80) >> 7);
            t = ((*pdest >> 5) & 0x001f0000) - (b & 0x003f0000);
            if (t & 0x80000000) t = 0;
            b = ((*pdest >> 5) & 0x0000001f) - (b & 0x0000003f);
            if (b & 0x80000000) b = 0;
            b |= t;

            g = (((((X32COL3(color))) * g_m3) & 0xFF80FF80) >> 7);
            t = ((*pdest >> 10) & 0x001f0000) - (g & 0x003f0000);
            if (t & 0x80000000) t = 0;
            g = ((*pdest >> 10) & 0x0000001f) - (g & 0x0000003f);
            if (g & 0x80000000) g = 0;
            g |= t;
        } else {
#ifdef HALFBRIGHTMODE3
            r = (X32COL1(*pdest)) + (((((X32BCOL1(color)) >> 2) * g_m1) & 0xFF80FF80) >> 7);
            b = (X32COL2(*pdest)) + (((((X32BCOL2(color)) >> 2) * g_m2) & 0xFF80FF80) >> 7);
            g = (X32COL3(*pdest)) + (((((X32BCOL3(color)) >> 2) * g_m3) & 0xFF80FF80) >> 7);
#else
            r = (X32COL1(*pdest)) + (((((X32ACOL1(color)) >> 1) * g_m1) & 0xFF80FF80) >> 7);
            b = (X32COL2(*pdest)) + (((((X32ACOL2(color)) >> 1) * g_m2) & 0xFF80FF80) >> 7);
            g = (X32COL3(*pdest)) + (((((X32ACOL3(color)) >> 1) * g_m3) & 0xFF80FF80) >> 7);
#endif
        }

        if (!(color & 0x8000)) {
            r = (r & 0xffff0000) | ((((X32COL1(color)) * g_m1) & 0x0000FF80) >> 7);
            b = (b & 0xffff0000) | ((((X32COL2(color)) * g_m2) & 0x0000FF80) >> 7);
            g = (g & 0xffff0000) | ((((X32COL3(color)) * g_m3) & 0x0000FF80) >> 7);
        }
        if (!(color & 0x80000000)) {
            r = (r & 0xffff) | ((((X32COL1(color)) * g_m1) & 0xFF800000) >> 7);
            b = (b & 0xffff) | ((((X32COL2(color)) * g_m2) & 0xFF800000) >> 7);
            g = (g & 0xffff) | ((((X32COL3(color)) * g_m3) & 0xFF800000) >> 7);
        }

    } else {
        r = (((X32COL1(color)) * g_m1) & 0xFF80FF80) >> 7;
        b = (((X32COL2(color)) * g_m2) & 0xFF80FF80) >> 7;
        g = (((X32COL3(color)) * g_m3) & 0xFF80FF80) >> 7;
    }

    if (r & 0x7FE00000) r = 0x1f0000 | (r & 0xFFFF);
    if (r & 0x7FE0) r = 0x1f | (r & 0xFFFF0000);
    if (b & 0x7FE00000) b = 0x1f0000 | (b & 0xFFFF);
    if (b & 0x7FE0) b = 0x1f | (b & 0xFFFF0000);
    if (g & 0x7FE00000) g = 0x1f0000 | (g & 0xFFFF);
    if (g & 0x7FE0) g = 0x1f | (g & 0xFFFF0000);

    if (bCheckMask) {
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

inline void PCSX::SoftGPU::SoftRenderer::GetTextureTransColG32_S(uint32_t *pdest, uint32_t color) {
    int32_t r, g, b;

    if (color == 0) return;

    r = (((X32COL1(color)) * g_m1) & 0xFF80FF80) >> 7;
    b = (((X32COL2(color)) * g_m2) & 0xFF80FF80) >> 7;
    g = (((X32COL3(color)) * g_m3) & 0xFF80FF80) >> 7;

    if (r & 0x7FE00000) r = 0x1f0000 | (r & 0xFFFF);
    if (r & 0x7FE0) r = 0x1f | (r & 0xFFFF0000);
    if (b & 0x7FE00000) b = 0x1f0000 | (b & 0xFFFF);
    if (b & 0x7FE0) b = 0x1f | (b & 0xFFFF0000);
    if (g & 0x7FE00000) g = 0x1f0000 | (g & 0xFFFF);
    if (g & 0x7FE0) g = 0x1f | (g & 0xFFFF0000);

    if ((color & 0xffff) == 0) {
        *pdest = (*pdest & 0xffff) | (((X32PSXCOL(r, g, b)) | lSetMask | (color & 0x80008000)) & 0xffff0000);
        return;
    }
    if ((color & 0xffff0000) == 0) {
        *pdest = (*pdest & 0xffff0000) | (((X32PSXCOL(r, g, b)) | lSetMask | (color & 0x80008000)) & 0xffff);
        return;
    }

    *pdest = (X32PSXCOL(r, g, b)) | lSetMask | (color & 0x80008000);
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SoftGPU::SoftRenderer::GetTextureTransColG32_SPR(uint32_t *pdest, uint32_t color) {
    int32_t r, g, b;

    if (color == 0) return;

    if (DrawSemiTrans && (color & 0x80008000)) {
        if (GlobalTextABR == 0) {
            r = ((((X32TCOL1(*pdest)) + ((X32COL1(color)) * g_m1)) & 0xFF00FF00) >> 8);
            b = ((((X32TCOL2(*pdest)) + ((X32COL2(color)) * g_m2)) & 0xFF00FF00) >> 8);
            g = ((((X32TCOL3(*pdest)) + ((X32COL3(color)) * g_m3)) & 0xFF00FF00) >> 8);
        } else if (GlobalTextABR == 1) {
            r = (X32COL1(*pdest)) + (((((X32COL1(color))) * g_m1) & 0xFF80FF80) >> 7);
            b = (X32COL2(*pdest)) + (((((X32COL2(color))) * g_m2) & 0xFF80FF80) >> 7);
            g = (X32COL3(*pdest)) + (((((X32COL3(color))) * g_m3) & 0xFF80FF80) >> 7);
        } else if (GlobalTextABR == 2) {
            int32_t t;
            r = (((((X32COL1(color))) * g_m1) & 0xFF80FF80) >> 7);
            t = (*pdest & 0x001f0000) - (r & 0x003f0000);
            if (t & 0x80000000) t = 0;
            r = (*pdest & 0x0000001f) - (r & 0x0000003f);
            if (r & 0x80000000) r = 0;
            r |= t;

            b = (((((X32COL2(color))) * g_m2) & 0xFF80FF80) >> 7);
            t = ((*pdest >> 5) & 0x001f0000) - (b & 0x003f0000);
            if (t & 0x80000000) t = 0;
            b = ((*pdest >> 5) & 0x0000001f) - (b & 0x0000003f);
            if (b & 0x80000000) b = 0;
            b |= t;

            g = (((((X32COL3(color))) * g_m3) & 0xFF80FF80) >> 7);
            t = ((*pdest >> 10) & 0x001f0000) - (g & 0x003f0000);
            if (t & 0x80000000) t = 0;
            g = ((*pdest >> 10) & 0x0000001f) - (g & 0x0000003f);
            if (g & 0x80000000) g = 0;
            g |= t;
        } else {
#ifdef HALFBRIGHTMODE3
            r = (X32COL1(*pdest)) + (((((X32BCOL1(color)) >> 2) * g_m1) & 0xFF80FF80) >> 7);
            b = (X32COL2(*pdest)) + (((((X32BCOL2(color)) >> 2) * g_m2) & 0xFF80FF80) >> 7);
            g = (X32COL3(*pdest)) + (((((X32BCOL3(color)) >> 2) * g_m3) & 0xFF80FF80) >> 7);
#else
            r = (X32COL1(*pdest)) + (((((X32ACOL1(color)) >> 1) * g_m1) & 0xFF80FF80) >> 7);
            b = (X32COL2(*pdest)) + (((((X32ACOL2(color)) >> 1) * g_m2) & 0xFF80FF80) >> 7);
            g = (X32COL3(*pdest)) + (((((X32ACOL3(color)) >> 1) * g_m3) & 0xFF80FF80) >> 7);
#endif
        }

        if (!(color & 0x8000)) {
            r = (r & 0xffff0000) | ((((X32COL1(color)) * g_m1) & 0x0000FF80) >> 7);
            b = (b & 0xffff0000) | ((((X32COL2(color)) * g_m2) & 0x0000FF80) >> 7);
            g = (g & 0xffff0000) | ((((X32COL3(color)) * g_m3) & 0x0000FF80) >> 7);
        }
        if (!(color & 0x80000000)) {
            r = (r & 0xffff) | ((((X32COL1(color)) * g_m1) & 0xFF800000) >> 7);
            b = (b & 0xffff) | ((((X32COL2(color)) * g_m2) & 0xFF800000) >> 7);
            g = (g & 0xffff) | ((((X32COL3(color)) * g_m3) & 0xFF800000) >> 7);
        }

    } else {
        r = (((X32COL1(color)) * g_m1) & 0xFF80FF80) >> 7;
        b = (((X32COL2(color)) * g_m2) & 0xFF80FF80) >> 7;
        g = (((X32COL3(color)) * g_m3) & 0xFF80FF80) >> 7;
    }

    if (r & 0x7FE00000) r = 0x1f0000 | (r & 0xFFFF);
    if (r & 0x7FE0) r = 0x1f | (r & 0xFFFF0000);
    if (b & 0x7FE00000) b = 0x1f0000 | (b & 0xFFFF);
    if (b & 0x7FE0) b = 0x1f | (b & 0xFFFF0000);
    if (g & 0x7FE00000) g = 0x1f0000 | (g & 0xFFFF);
    if (g & 0x7FE0) g = 0x1f | (g & 0xFFFF0000);

    if (bCheckMask) {
        uint32_t ma = *pdest;

        *pdest = (X32PSXCOL(r, g, b)) | lSetMask | (color & 0x80008000);

        if ((color & 0xffff) == 0) *pdest = (ma & 0xffff) | (*pdest & 0xffff0000);
        if ((color & 0xffff0000) == 0) *pdest = (ma & 0xffff0000) | (*pdest & 0xffff);
        if (ma & 0x80000000) *pdest = (ma & 0xFFFF0000) | (*pdest & 0xFFFF);
        if (ma & 0x00008000) *pdest = (ma & 0xFFFF) | (*pdest & 0xFFFF0000);

        return;
    }
    if ((color & 0xffff) == 0) {
        *pdest = (*pdest & 0xffff) | (((X32PSXCOL(r, g, b)) | lSetMask | (color & 0x80008000)) & 0xffff0000);
        return;
    }
    if ((color & 0xffff0000) == 0) {
        *pdest = (*pdest & 0xffff0000) | (((X32PSXCOL(r, g, b)) | lSetMask | (color & 0x80008000)) & 0xffff);
        return;
    }

    *pdest = (X32PSXCOL(r, g, b)) | lSetMask | (color & 0x80008000);
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SoftGPU::SoftRenderer::GetTextureTransColGX_Dither(uint16_t *pdest, uint16_t color, int32_t m1,
                                                                     int32_t m2, int32_t m3) {
    int32_t r, g, b;

    if (color == 0) return;

    if (bCheckMask && *pdest & 0x8000) return;

    m1 = (((XCOL1D(color))) * m1) >> 4;
    m2 = (((XCOL2D(color))) * m2) >> 4;
    m3 = (((XCOL3D(color))) * m3) >> 4;

    if (DrawSemiTrans && (color & 0x8000)) {
        r = ((XCOL1D(*pdest)) << 3);
        b = ((XCOL2D(*pdest)) << 3);
        g = ((XCOL3D(*pdest)) << 3);

        if (GlobalTextABR == 0) {
            r = (r >> 1) + (m1 >> 1);
            b = (b >> 1) + (m2 >> 1);
            g = (g >> 1) + (m3 >> 1);
        } else if (GlobalTextABR == 1) {
            r += m1;
            b += m2;
            g += m3;
        } else if (GlobalTextABR == 2) {
            r -= m1;
            b -= m2;
            g -= m3;
            if (r & 0x80000000) r = 0;
            if (b & 0x80000000) b = 0;
            if (g & 0x80000000) g = 0;
        } else {
#ifdef HALFBRIGHTMODE3
            r += (m1 >> 2);
            b += (m2 >> 2);
            g += (m3 >> 2);
#else
            r += (m1 >> 1);
            b += (m2 >> 1);
            g += (m3 >> 1);
#endif
        }
    } else {
        r = m1;
        b = m2;
        g = m3;
    }

    if (r & 0x7FFFFF00) r = 0xff;
    if (b & 0x7FFFFF00) b = 0xff;
    if (g & 0x7FFFFF00) g = 0xff;

    Dither16(pdest, r, b, g, sSetMask | (color & 0x8000));
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SoftGPU::SoftRenderer::GetTextureTransColGX(uint16_t *pdest, uint16_t color, int16_t m1, int16_t m2,
                                                              int16_t m3) {
    int32_t r, g, b;
    uint16_t l;

    if (color == 0) return;

    if (bCheckMask && *pdest & 0x8000) return;

    l = sSetMask | (color & 0x8000);

    if (DrawSemiTrans && (color & 0x8000)) {
        if (GlobalTextABR == 0) {
            uint16_t d;
            d = ((*pdest) & 0x7bde) >> 1;
            color = ((color)&0x7bde) >> 1;
            r = (XCOL1(d)) + ((((XCOL1(color))) * m1) >> 7);
            b = (XCOL2(d)) + ((((XCOL2(color))) * m2) >> 7);
            g = (XCOL3(d)) + ((((XCOL3(color))) * m3) >> 7);
            /*
                 r=(XCOL1(*pdest)>>1)+((((XCOL1(color))>>1)* m1)>>7);
                 b=(XCOL2(*pdest)>>1)+((((XCOL2(color))>>1)* m2)>>7);
                 g=(XCOL3(*pdest)>>1)+((((XCOL3(color))>>1)* m3)>>7);
            */
        } else if (GlobalTextABR == 1) {
            r = (XCOL1(*pdest)) + ((((XCOL1(color))) * m1) >> 7);
            b = (XCOL2(*pdest)) + ((((XCOL2(color))) * m2) >> 7);
            g = (XCOL3(*pdest)) + ((((XCOL3(color))) * m3) >> 7);
        } else if (GlobalTextABR == 2) {
            r = (XCOL1(*pdest)) - ((((XCOL1(color))) * m1) >> 7);
            b = (XCOL2(*pdest)) - ((((XCOL2(color))) * m2) >> 7);
            g = (XCOL3(*pdest)) - ((((XCOL3(color))) * m3) >> 7);
            if (r & 0x80000000) r = 0;
            if (b & 0x80000000) b = 0;
            if (g & 0x80000000) g = 0;
        } else {
#ifdef HALFBRIGHTMODE3
            r = (XCOL1(*pdest)) + ((((XCOL1(color)) >> 2) * m1) >> 7);
            b = (XCOL2(*pdest)) + ((((XCOL2(color)) >> 2) * m2) >> 7);
            g = (XCOL3(*pdest)) + ((((XCOL3(color)) >> 2) * m3) >> 7);
#else
            r = (XCOL1(*pdest)) + ((((XCOL1(color)) >> 1) * m1) >> 7);
            b = (XCOL2(*pdest)) + ((((XCOL2(color)) >> 1) * m2) >> 7);
            g = (XCOL3(*pdest)) + ((((XCOL3(color)) >> 1) * m3) >> 7);
#endif
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

inline void PCSX::SoftGPU::SoftRenderer::GetTextureTransColGX_S(uint16_t *pdest, uint16_t color, int16_t m1, int16_t m2,
                                                                int16_t m3) {
    int32_t r, g, b;

    if (color == 0) return;

    r = ((XCOL1(color)) * m1) >> 7;
    b = ((XCOL2(color)) * m2) >> 7;
    g = ((XCOL3(color)) * m3) >> 7;

    if (r & 0x7FFFFFE0) r = 0x1f;
    if (b & 0x7FFFFC00) b = 0x3e0;
    if (g & 0x7FFF8000) g = 0x7c00;

    *pdest = (XPSXCOL(r, g, b)) | sSetMask | (color & 0x8000);
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SoftGPU::SoftRenderer::GetTextureTransColGX32_S(uint32_t *pdest, uint32_t color, int16_t m1,
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
        *pdest = (*pdest & 0xffff) | (((X32PSXCOL(r, g, b)) | lSetMask | (color & 0x80008000)) & 0xffff0000);
        return;
    }
    if ((color & 0xffff0000) == 0) {
        *pdest = (*pdest & 0xffff0000) | (((X32PSXCOL(r, g, b)) | lSetMask | (color & 0x80008000)) & 0xffff);
        return;
    }

    *pdest = (X32PSXCOL(r, g, b)) | lSetMask | (color & 0x80008000);
}

////////////////////////////////////////////////////////////////////////
// FILL FUNCS
////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::FillSoftwareAreaTrans(int16_t x0, int16_t y0, int16_t x1,  // FILL AREA TRANS
                                                        int16_t y1, uint16_t col) {
    int16_t j, i, dx, dy;

    if (y0 > y1) return;
    if (x0 > x1) return;

    if (x1 < drawX) return;
    if (y1 < drawY) return;
    if (x0 > drawW) return;
    if (y0 > drawH) return;

    x1 = std::min(x1, static_cast<int16_t>(drawW + 1));
    y1 = std::min(y1, static_cast<int16_t>(drawH + 1));
    x0 = std::max(x0, static_cast<int16_t>(drawX));
    y0 = std::max(y0, static_cast<int16_t>(drawY));

    if (y0 >= iGPUHeight) return;
    if (x0 > 1023) return;

    if (y1 > iGPUHeight) y1 = iGPUHeight;
    if (x1 > 1024) x1 = 1024;

    dx = x1 - x0;
    dy = y1 - y0;

    if (dx == 1 && dy == 1 && x0 == 1020 && y0 == 511)  // special fix for pinball game... emu protection???
    {
        /*
        m->v 1020 511 1 1
        writedatamem 0x00000000 1
        tile1 newcol 7fff (orgcol 0xffffff), oldvram 0
        v->m 1020 511 1 1
        readdatamem 0x00007fff 1
        m->v 1020 511 1 1
        writedatamem 0x00000000 1
        tile1 newcol 8000 (orgcol 0xffffff), oldvram 0
        v->m 1020 511 1 1
        readdatamem 0x00008000 1
        */

        static int iCheat = 0;
        col += iCheat;
        if (iCheat == 1)
            iCheat = 0;
        else
            iCheat = 1;
    }

    if (dx & 1)  // slow fill
    {
        uint16_t *DSTPtr;
        uint16_t LineOffset;
        DSTPtr = psxVuw + (1024 * y0) + x0;
        LineOffset = 1024 - dx;
        for (i = 0; i < dy; i++) {
            for (j = 0; j < dx; j++) GetShadeTransCol(DSTPtr++, col);
            DSTPtr += LineOffset;
        }
    } else  // fast fill
    {
        uint32_t *DSTPtr;
        uint16_t LineOffset;
        uint32_t lcol = lSetMask | (((uint32_t)(col)) << 16) | col;
        dx >>= 1;
        DSTPtr = (uint32_t *)(psxVuw + (1024 * y0) + x0);
        LineOffset = 512 - dx;

        if (!bCheckMask && !DrawSemiTrans) {
            for (i = 0; i < dy; i++) {
                for (j = 0; j < dx; j++) *DSTPtr++ = lcol;
                DSTPtr += LineOffset;
            }
        } else {
            for (i = 0; i < dy; i++) {
                for (j = 0; j < dx; j++) GetShadeTransCol32(DSTPtr++, lcol);
                DSTPtr += LineOffset;
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::FillSoftwareArea(int16_t x0, int16_t y0, int16_t x1,  // FILL AREA (BLK FILL)
                                                   int16_t y1, uint16_t col)            // no draw area check here!
{
    int16_t j, i, dx, dy;

    if (y0 > y1) return;
    if (x0 > x1) return;

    if (y0 >= iGPUHeight) return;
    if (x0 > 1023) return;

    if (y1 > iGPUHeight) y1 = iGPUHeight;
    if (x1 > 1024) x1 = 1024;

    dx = x1 - x0;
    dy = y1 - y0;
    if (dx & 1) {
        uint16_t *DSTPtr;
        uint16_t LineOffset;

        DSTPtr = psxVuw + (1024 * y0) + x0;
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
        DSTPtr = (uint32_t *)(psxVuw + (1024 * y0) + x0);
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

typedef struct SOFTVTAG {
    int x, y;
    int u, v;
    int32_t R, G, B;
} soft_vertex;

static soft_vertex vtx[4];
static soft_vertex *left_array[4], *right_array[4];
static int left_section, right_section;
static int left_section_height, right_section_height;
static int left_x, delta_left_x, right_x, delta_right_x;
static int left_u, delta_left_u, left_v, delta_left_v;
static int right_u, delta_right_u, right_v, delta_right_v;
static int left_R, delta_left_R, right_R, delta_right_R;
static int left_G, delta_left_G, right_G, delta_right_G;
static int left_B, delta_left_B, right_B, delta_right_B;

static constexpr inline int shl10idiv(int x, int y) {
    int64_t bi = x;
    bi <<= 10;
    return bi / y;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

static inline int RightSection_F(void) {
    soft_vertex *v1 = right_array[right_section];
    soft_vertex *v2 = right_array[right_section - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    delta_right_x = (v2->x - v1->x) / height;
    right_x = v1->x;

    right_section_height = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

static inline int LeftSection_F(void) {
    soft_vertex *v1 = left_array[left_section];
    soft_vertex *v2 = left_array[left_section - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    delta_left_x = (v2->x - v1->x) / height;
    left_x = v1->x;

    left_section_height = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

static inline bool NextRow_F(void) {
    if (--left_section_height <= 0) {
        if (--left_section <= 0) {
            return true;
        }
        if (LeftSection_F() <= 0) {
            return true;
        }
    } else {
        left_x += delta_left_x;
    }

    if (--right_section_height <= 0) {
        if (--right_section <= 0) {
            return true;
        }
        if (RightSection_F() <= 0) {
            return true;
        }
    } else {
        right_x += delta_right_x;
    }
    return false;
}

////////////////////////////////////////////////////////////////////////

inline bool PCSX::SoftGPU::SoftRenderer::SetupSections_F(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                         int16_t y3) {
    soft_vertex *v1, *v2, *v3;
    int height, int32_test;

    v1 = vtx;
    v1->x = x1 << 16;
    v1->y = y1;
    v2 = vtx + 1;
    v2->x = x2 << 16;
    v2->y = y2;
    v3 = vtx + 2;
    v3->x = x3 << 16;
    v3->y = y3;

    if (v1->y > v2->y) {
        soft_vertex *v = v1;
        v1 = v2;
        v2 = v;
    }
    if (v1->y > v3->y) {
        soft_vertex *v = v1;
        v1 = v3;
        v3 = v;
    }
    if (v2->y > v3->y) {
        soft_vertex *v = v2;
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
        right_array[0] = v3;
        right_array[1] = v2;
        right_array[2] = v1;
        right_section = 2;
        left_array[0] = v3;
        left_array[1] = v1;
        left_section = 1;

        if (LeftSection_F() <= 0) return false;
        if (RightSection_F() <= 0) {
            right_section--;
            if (RightSection_F() <= 0) return false;
        }
    } else {
        left_array[0] = v3;
        left_array[1] = v2;
        left_array[2] = v1;
        left_section = 2;
        right_array[0] = v3;
        right_array[1] = v1;
        right_section = 1;

        if (RightSection_F() <= 0) return false;
        if (LeftSection_F() <= 0) {
            left_section--;
            if (LeftSection_F() <= 0) return false;
        }
    }

    Ymin = v1->y;
    Ymax = std::min(v3->y - 1, drawH);

    return true;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

static inline int RightSection_G(void) {
    soft_vertex *v1 = right_array[right_section];
    soft_vertex *v2 = right_array[right_section - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    delta_right_x = (v2->x - v1->x) / height;
    right_x = v1->x;

    right_section_height = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

static inline int LeftSection_G(void) {
    soft_vertex *v1 = left_array[left_section];
    soft_vertex *v2 = left_array[left_section - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    delta_left_x = (v2->x - v1->x) / height;
    left_x = v1->x;

    delta_left_R = ((v2->R - v1->R)) / height;
    left_R = v1->R;
    delta_left_G = ((v2->G - v1->G)) / height;
    left_G = v1->G;
    delta_left_B = ((v2->B - v1->B)) / height;
    left_B = v1->B;

    left_section_height = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

static inline bool NextRow_G(void) {
    if (--left_section_height <= 0) {
        if (--left_section <= 0) {
            return true;
        }
        if (LeftSection_G() <= 0) {
            return true;
        }
    } else {
        left_x += delta_left_x;
        left_R += delta_left_R;
        left_G += delta_left_G;
        left_B += delta_left_B;
    }

    if (--right_section_height <= 0) {
        if (--right_section <= 0) {
            return true;
        }
        if (RightSection_G() <= 0) {
            return true;
        }
    } else {
        right_x += delta_right_x;
    }
    return false;
}

////////////////////////////////////////////////////////////////////////

inline bool PCSX::SoftGPU::SoftRenderer::SetupSections_G(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                         int16_t y3, int32_t rgb1, int32_t rgb2, int32_t rgb3) {
    soft_vertex *v1, *v2, *v3;
    int height, int32_test, temp;

    v1 = vtx;
    v1->x = x1 << 16;
    v1->y = y1;
    v1->R = (rgb1)&0x00ff0000;
    v1->G = (rgb1 << 8) & 0x00ff0000;
    v1->B = (rgb1 << 16) & 0x00ff0000;
    v2 = vtx + 1;
    v2->x = x2 << 16;
    v2->y = y2;
    v2->R = (rgb2)&0x00ff0000;
    v2->G = (rgb2 << 8) & 0x00ff0000;
    v2->B = (rgb2 << 16) & 0x00ff0000;
    v3 = vtx + 2;
    v3->x = x3 << 16;
    v3->y = y3;
    v3->R = (rgb3)&0x00ff0000;
    v3->G = (rgb3 << 8) & 0x00ff0000;
    v3->B = (rgb3 << 16) & 0x00ff0000;

    if (v1->y > v2->y) {
        soft_vertex *v = v1;
        v1 = v2;
        v2 = v;
    }
    if (v1->y > v3->y) {
        soft_vertex *v = v1;
        v1 = v3;
        v3 = v;
    }
    if (v2->y > v3->y) {
        soft_vertex *v = v2;
        v2 = v3;
        v3 = v;
    }

    height = v3->y - v1->y;
    if (height == 0) {
        return false;
    }
    temp = (((v2->y - v1->y) << 16) / height);
    int32_test = temp * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
    if (int32_test == 0) {
        return false;
    }

    if (int32_test < 0) {
        right_array[0] = v3;
        right_array[1] = v2;
        right_array[2] = v1;
        right_section = 2;
        left_array[0] = v3;
        left_array[1] = v1;
        left_section = 1;

        if (LeftSection_G() <= 0) return false;
        if (RightSection_G() <= 0) {
            right_section--;
            if (RightSection_G() <= 0) return false;
        }
        if (int32_test > -0x1000) int32_test = -0x1000;
    } else {
        left_array[0] = v3;
        left_array[1] = v2;
        left_array[2] = v1;
        left_section = 2;
        right_array[0] = v3;
        right_array[1] = v1;
        right_section = 1;

        if (RightSection_G() <= 0) return false;
        if (LeftSection_G() <= 0) {
            left_section--;
            if (LeftSection_G() <= 0) return false;
        }
        if (int32_test < 0x1000) int32_test = 0x1000;
    }

    Ymin = v1->y;
    Ymax = std::min(v3->y - 1, drawH);

    delta_right_R = shl10idiv(temp * ((v3->R - v1->R) >> 10) + ((v1->R - v2->R) << 6), int32_test);
    delta_right_G = shl10idiv(temp * ((v3->G - v1->G) >> 10) + ((v1->G - v2->G) << 6), int32_test);
    delta_right_B = shl10idiv(temp * ((v3->B - v1->B) >> 10) + ((v1->B - v2->B) << 6), int32_test);

    return true;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

static inline int RightSection_FT(void) {
    soft_vertex *v1 = right_array[right_section];
    soft_vertex *v2 = right_array[right_section - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    delta_right_x = (v2->x - v1->x) / height;
    right_x = v1->x;

    right_section_height = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

static inline int LeftSection_FT(void) {
    soft_vertex *v1 = left_array[left_section];
    soft_vertex *v2 = left_array[left_section - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    delta_left_x = (v2->x - v1->x) / height;
    left_x = v1->x;

    delta_left_u = ((v2->u - v1->u)) / height;
    left_u = v1->u;
    delta_left_v = ((v2->v - v1->v)) / height;
    left_v = v1->v;

    left_section_height = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

static inline bool NextRow_FT(void) {
    if (--left_section_height <= 0) {
        if (--left_section <= 0) {
            return true;
        }
        if (LeftSection_FT() <= 0) {
            return true;
        }
    } else {
        left_x += delta_left_x;
        left_u += delta_left_u;
        left_v += delta_left_v;
    }

    if (--right_section_height <= 0) {
        if (--right_section <= 0) {
            return true;
        }
        if (RightSection_FT() <= 0) {
            return true;
        }
    } else {
        right_x += delta_right_x;
    }
    return false;
}

////////////////////////////////////////////////////////////////////////

inline bool PCSX::SoftGPU::SoftRenderer::SetupSections_FT(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                          int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                                                          int16_t ty2, int16_t tx3, int16_t ty3) {
    soft_vertex *v1, *v2, *v3;
    int height, int32_test, temp;

    v1 = vtx;
    v1->x = x1 << 16;
    v1->y = y1;
    v1->u = tx1 << 16;
    v1->v = ty1 << 16;
    v2 = vtx + 1;
    v2->x = x2 << 16;
    v2->y = y2;
    v2->u = tx2 << 16;
    v2->v = ty2 << 16;
    v3 = vtx + 2;
    v3->x = x3 << 16;
    v3->y = y3;
    v3->u = tx3 << 16;
    v3->v = ty3 << 16;

    if (v1->y > v2->y) {
        soft_vertex *v = v1;
        v1 = v2;
        v2 = v;
    }
    if (v1->y > v3->y) {
        soft_vertex *v = v1;
        v1 = v3;
        v3 = v;
    }
    if (v2->y > v3->y) {
        soft_vertex *v = v2;
        v2 = v3;
        v3 = v;
    }

    height = v3->y - v1->y;
    if (height == 0) {
        return false;
    }

    temp = (((v2->y - v1->y) << 16) / height);
    int32_test = temp * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);

    if (int32_test == 0) {
        return false;
    }

    if (int32_test < 0) {
        right_array[0] = v3;
        right_array[1] = v2;
        right_array[2] = v1;
        right_section = 2;
        left_array[0] = v3;
        left_array[1] = v1;
        left_section = 1;

        if (LeftSection_FT() <= 0) return false;
        if (RightSection_FT() <= 0) {
            right_section--;
            if (RightSection_FT() <= 0) return false;
        }
        if (int32_test > -0x1000) int32_test = -0x1000;
    } else {
        left_array[0] = v3;
        left_array[1] = v2;
        left_array[2] = v1;
        left_section = 2;
        right_array[0] = v3;
        right_array[1] = v1;
        right_section = 1;

        if (RightSection_FT() <= 0) return false;
        if (LeftSection_FT() <= 0) {
            left_section--;
            if (LeftSection_FT() <= 0) return false;
        }
        if (int32_test < 0x1000) int32_test = 0x1000;
    }

    Ymin = v1->y;
    Ymax = std::min(v3->y - 1, drawH);

    delta_right_u = shl10idiv(temp * ((v3->u - v1->u) >> 10) + ((v1->u - v2->u) << 6), int32_test);
    delta_right_v = shl10idiv(temp * ((v3->v - v1->v) >> 10) + ((v1->v - v2->v) << 6), int32_test);

    /*
    Mmm... adjust neg tex deltas... will sometimes cause slight
    texture distortions

     int32_test>>=16;
     if(int32_test)
      {
       if(int32_test<0) int32_test=-int32_test;
       if(delta_right_u<0)
        delta_right_u-=delta_right_u/int32_test;
       if(delta_right_v<0)
        delta_right_v-=delta_right_v/int32_test;
      }
    */

    return true;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

static inline int RightSection_GT(void) {
    soft_vertex *v1 = right_array[right_section];
    soft_vertex *v2 = right_array[right_section - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    delta_right_x = (v2->x - v1->x) / height;
    right_x = v1->x;

    right_section_height = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

static inline int LeftSection_GT(void) {
    soft_vertex *v1 = left_array[left_section];
    soft_vertex *v2 = left_array[left_section - 1];

    int height = v2->y - v1->y;
    if (height == 0) return 0;
    delta_left_x = (v2->x - v1->x) / height;
    left_x = v1->x;

    delta_left_u = ((v2->u - v1->u)) / height;
    left_u = v1->u;
    delta_left_v = ((v2->v - v1->v)) / height;
    left_v = v1->v;

    delta_left_R = ((v2->R - v1->R)) / height;
    left_R = v1->R;
    delta_left_G = ((v2->G - v1->G)) / height;
    left_G = v1->G;
    delta_left_B = ((v2->B - v1->B)) / height;
    left_B = v1->B;

    left_section_height = height;
    return height;
}

////////////////////////////////////////////////////////////////////////

static inline bool NextRow_GT(void) {
    if (--left_section_height <= 0) {
        if (--left_section <= 0) {
            return true;
        }
        if (LeftSection_GT() <= 0) {
            return true;
        }
    } else {
        left_x += delta_left_x;
        left_u += delta_left_u;
        left_v += delta_left_v;
        left_R += delta_left_R;
        left_G += delta_left_G;
        left_B += delta_left_B;
    }

    if (--right_section_height <= 0) {
        if (--right_section <= 0) {
            return true;
        }
        if (RightSection_GT() <= 0) {
            return true;
        }
    } else {
        right_x += delta_right_x;
    }
    return false;
}

////////////////////////////////////////////////////////////////////////

inline bool PCSX::SoftGPU::SoftRenderer::SetupSections_GT(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                          int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                                                          int16_t ty2, int16_t tx3, int16_t ty3, int32_t rgb1,
                                                          int32_t rgb2, int32_t rgb3) {
    soft_vertex *v1, *v2, *v3;
    int height, int32_test, temp;

    v1 = vtx;
    v1->x = x1 << 16;
    v1->y = y1;
    v1->u = tx1 << 16;
    v1->v = ty1 << 16;
    v1->R = (rgb1)&0x00ff0000;
    v1->G = (rgb1 << 8) & 0x00ff0000;
    v1->B = (rgb1 << 16) & 0x00ff0000;

    v2 = vtx + 1;
    v2->x = x2 << 16;
    v2->y = y2;
    v2->u = tx2 << 16;
    v2->v = ty2 << 16;
    v2->R = (rgb2)&0x00ff0000;
    v2->G = (rgb2 << 8) & 0x00ff0000;
    v2->B = (rgb2 << 16) & 0x00ff0000;

    v3 = vtx + 2;
    v3->x = x3 << 16;
    v3->y = y3;
    v3->u = tx3 << 16;
    v3->v = ty3 << 16;
    v3->R = (rgb3)&0x00ff0000;
    v3->G = (rgb3 << 8) & 0x00ff0000;
    v3->B = (rgb3 << 16) & 0x00ff0000;

    if (v1->y > v2->y) {
        soft_vertex *v = v1;
        v1 = v2;
        v2 = v;
    }
    if (v1->y > v3->y) {
        soft_vertex *v = v1;
        v1 = v3;
        v3 = v;
    }
    if (v2->y > v3->y) {
        soft_vertex *v = v2;
        v2 = v3;
        v3 = v;
    }

    height = v3->y - v1->y;
    if (height == 0) {
        return false;
    }

    temp = (((v2->y - v1->y) << 16) / height);
    int32_test = temp * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);

    if (int32_test == 0) {
        return false;
    }

    if (int32_test < 0) {
        right_array[0] = v3;
        right_array[1] = v2;
        right_array[2] = v1;
        right_section = 2;
        left_array[0] = v3;
        left_array[1] = v1;
        left_section = 1;

        if (LeftSection_GT() <= 0) return false;
        if (RightSection_GT() <= 0) {
            right_section--;
            if (RightSection_GT() <= 0) return false;
        }

        if (int32_test > -0x1000) int32_test = -0x1000;
    } else {
        left_array[0] = v3;
        left_array[1] = v2;
        left_array[2] = v1;
        left_section = 2;
        right_array[0] = v3;
        right_array[1] = v1;
        right_section = 1;

        if (RightSection_GT() <= 0) return false;
        if (LeftSection_GT() <= 0) {
            left_section--;
            if (LeftSection_GT() <= 0) return false;
        }
        if (int32_test < 0x1000) int32_test = 0x1000;
    }

    Ymin = v1->y;
    Ymax = std::min(v3->y - 1, drawH);

    delta_right_R = shl10idiv(temp * ((v3->R - v1->R) >> 10) + ((v1->R - v2->R) << 6), int32_test);
    delta_right_G = shl10idiv(temp * ((v3->G - v1->G) >> 10) + ((v1->G - v2->G) << 6), int32_test);
    delta_right_B = shl10idiv(temp * ((v3->B - v1->B) >> 10) + ((v1->B - v2->B) << 6), int32_test);

    delta_right_u = shl10idiv(temp * ((v3->u - v1->u) >> 10) + ((v1->u - v2->u) << 6), int32_test);
    delta_right_v = shl10idiv(temp * ((v3->v - v1->v) >> 10) + ((v1->v - v2->v) << 6), int32_test);

    /*
    Mmm... adjust neg tex deltas... will sometimes cause slight
    texture distortions
     int32_test>>=16;
     if(int32_test)
      {
       if(int32_test<0) int32_test=-int32_test;
       if(delta_right_u<0)
        delta_right_u-=delta_right_u/int32_test;
       if(delta_right_v<0)
        delta_right_v-=delta_right_v/int32_test;
      }
    */

    return true;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

static inline int RightSection_F4(void) {
    soft_vertex *v1 = right_array[right_section];
    soft_vertex *v2 = right_array[right_section - 1];

    int height = v2->y - v1->y;
    right_section_height = height;
    right_x = v1->x;
    if (height == 0) {
        return 0;
    }
    delta_right_x = (v2->x - v1->x) / height;

    return height;
}

////////////////////////////////////////////////////////////////////////

static inline int LeftSection_F4(void) {
    soft_vertex *v1 = left_array[left_section];
    soft_vertex *v2 = left_array[left_section - 1];

    int height = v2->y - v1->y;
    left_section_height = height;
    left_x = v1->x;
    if (height == 0) {
        return 0;
    }
    delta_left_x = (v2->x - v1->x) / height;

    return height;
}

////////////////////////////////////////////////////////////////////////

static inline bool NextRow_F4(void) {
    if (--left_section_height <= 0) {
        if (--left_section > 0)
            while (LeftSection_F4() <= 0) {
                if (--left_section <= 0) break;
            }
    } else {
        left_x += delta_left_x;
    }

    if (--right_section_height <= 0) {
        if (--right_section > 0)
            while (RightSection_F4() <= 0) {
                if (--right_section <= 0) break;
            }
    } else {
        right_x += delta_right_x;
    }
    return false;
}

////////////////////////////////////////////////////////////////////////

inline bool PCSX::SoftGPU::SoftRenderer::SetupSections_F4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                          int16_t y3, int16_t x4, int16_t y4) {
    soft_vertex *v1, *v2, *v3, *v4;
    int height, width, int32_test1, int32_test2;

    v1 = vtx;
    v1->x = x1 << 16;
    v1->y = y1;
    v2 = vtx + 1;
    v2->x = x2 << 16;
    v2->y = y2;
    v3 = vtx + 2;
    v3->x = x3 << 16;
    v3->y = y3;
    v4 = vtx + 3;
    v4->x = x4 << 16;
    v4->y = y4;

    if (v1->y > v2->y) {
        soft_vertex *v = v1;
        v1 = v2;
        v2 = v;
    }
    if (v1->y > v3->y) {
        soft_vertex *v = v1;
        v1 = v3;
        v3 = v;
    }
    if (v1->y > v4->y) {
        soft_vertex *v = v1;
        v1 = v4;
        v4 = v;
    }
    if (v2->y > v3->y) {
        soft_vertex *v = v2;
        v2 = v3;
        v3 = v;
    }
    if (v2->y > v4->y) {
        soft_vertex *v = v2;
        v2 = v4;
        v4 = v;
    }
    if (v3->y > v4->y) {
        soft_vertex *v = v3;
        v3 = v4;
        v4 = v;
    }

    height = v4->y - v1->y;
    if (height == 0) height = 1;
    width = (v4->x - v1->x) >> 16;
    int32_test1 = (((v2->y - v1->y) << 16) / height) * width + (v1->x - v2->x);
    int32_test2 = (((v3->y - v1->y) << 16) / height) * width + (v1->x - v3->x);

    if (int32_test1 < 0)  // 2 is right
    {
        if (int32_test2 < 0)  // 3 is right
        {
            left_array[0] = v4;
            left_array[1] = v1;
            left_section = 1;

            height = v3->y - v1->y;
            if (height == 0) height = 1;
            int32_test1 = (((v2->y - v1->y) << 16) / height) * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
            if (int32_test1 >= 0) {
                right_array[0] = v4;  //  1
                right_array[1] = v3;  //     3
                right_array[2] = v1;  //  4
                right_section = 2;
            } else {
                height = v4->y - v2->y;
                if (height == 0) height = 1;
                int32_test1 = (((v3->y - v2->y) << 16) / height) * ((v4->x - v2->x) >> 16) + (v2->x - v3->x);
                if (int32_test1 >= 0) {
                    right_array[0] = v4;  //  1
                    right_array[1] = v2;  //     2
                    right_array[2] = v1;  //  4
                    right_section = 2;
                } else {
                    right_array[0] = v4;  //  1
                    right_array[1] = v3;  //     2
                    right_array[2] = v2;  //     3
                    right_array[3] = v1;  //  4
                    right_section = 3;
                }
            }
        } else {
            left_array[0] = v4;
            left_array[1] = v3;   //    1
            left_array[2] = v1;   //      2
            left_section = 2;     //  3
            right_array[0] = v4;  //    4
            right_array[1] = v2;
            right_array[2] = v1;
            right_section = 2;
        }
    } else {
        if (int32_test2 < 0) {
            left_array[0] = v4;  //    1
            left_array[1] = v2;  //  2
            left_array[2] = v1;  //      3
            left_section = 2;    //    4
            right_array[0] = v4;
            right_array[1] = v3;
            right_array[2] = v1;
            right_section = 2;
        } else {
            right_array[0] = v4;
            right_array[1] = v1;
            right_section = 1;

            height = v3->y - v1->y;
            if (height == 0) height = 1;
            int32_test1 = (((v2->y - v1->y) << 16) / height) * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
            if (int32_test1 < 0) {
                left_array[0] = v4;  //    1
                left_array[1] = v3;  //  3
                left_array[2] = v1;  //    4
                left_section = 2;
            } else {
                height = v4->y - v2->y;
                if (height == 0) height = 1;
                int32_test1 = (((v3->y - v2->y) << 16) / height) * ((v4->x - v2->x) >> 16) + (v2->x - v3->x);
                if (int32_test1 < 0) {
                    left_array[0] = v4;  //    1
                    left_array[1] = v2;  //  2
                    left_array[2] = v1;  //    4
                    left_section = 2;
                } else {
                    left_array[0] = v4;  //    1
                    left_array[1] = v3;  //  2
                    left_array[2] = v2;  //  3
                    left_array[3] = v1;  //     4
                    left_section = 3;
                }
            }
        }
    }

    while (LeftSection_F4() <= 0) {
        if (--left_section <= 0) break;
    }

    while (RightSection_F4() <= 0) {
        if (--right_section <= 0) break;
    }

    Ymin = v1->y;
    Ymax = std::min(v4->y - 1, drawH);

    return true;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

static inline int RightSection_FT4(void) {
    soft_vertex *v1 = right_array[right_section];
    soft_vertex *v2 = right_array[right_section - 1];

    int height = v2->y - v1->y;
    right_section_height = height;
    right_x = v1->x;
    right_u = v1->u;
    right_v = v1->v;
    if (height == 0) {
        return 0;
    }
    delta_right_x = (v2->x - v1->x) / height;
    delta_right_u = (v2->u - v1->u) / height;
    delta_right_v = (v2->v - v1->v) / height;

    return height;
}

////////////////////////////////////////////////////////////////////////

static inline int LeftSection_FT4(void) {
    soft_vertex *v1 = left_array[left_section];
    soft_vertex *v2 = left_array[left_section - 1];

    int height = v2->y - v1->y;
    left_section_height = height;
    left_x = v1->x;
    left_u = v1->u;
    left_v = v1->v;
    if (height == 0) {
        return 0;
    }
    delta_left_x = (v2->x - v1->x) / height;
    delta_left_u = (v2->u - v1->u) / height;
    delta_left_v = (v2->v - v1->v) / height;

    return height;
}

////////////////////////////////////////////////////////////////////////

static inline bool NextRow_FT4(void) {
    if (--left_section_height <= 0) {
        if (--left_section > 0)
            while (LeftSection_FT4() <= 0) {
                if (--left_section <= 0) break;
            }
    } else {
        left_x += delta_left_x;
        left_u += delta_left_u;
        left_v += delta_left_v;
    }

    if (--right_section_height <= 0) {
        if (--right_section > 0)
            while (RightSection_FT4() <= 0) {
                if (--right_section <= 0) break;
            }
    } else {
        right_x += delta_right_x;
        right_u += delta_right_u;
        right_v += delta_right_v;
    }
    return false;
}

////////////////////////////////////////////////////////////////////////

inline bool PCSX::SoftGPU::SoftRenderer::SetupSections_FT4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                           int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                           int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3,
                                                           int16_t tx4, int16_t ty4) {
    soft_vertex *v1, *v2, *v3, *v4;
    int height, width, int32_test1, int32_test2;

    v1 = vtx;
    v1->x = x1 << 16;
    v1->y = y1;
    v1->u = tx1 << 16;
    v1->v = ty1 << 16;

    v2 = vtx + 1;
    v2->x = x2 << 16;
    v2->y = y2;
    v2->u = tx2 << 16;
    v2->v = ty2 << 16;

    v3 = vtx + 2;
    v3->x = x3 << 16;
    v3->y = y3;
    v3->u = tx3 << 16;
    v3->v = ty3 << 16;

    v4 = vtx + 3;
    v4->x = x4 << 16;
    v4->y = y4;
    v4->u = tx4 << 16;
    v4->v = ty4 << 16;

    if (v1->y > v2->y) {
        soft_vertex *v = v1;
        v1 = v2;
        v2 = v;
    }
    if (v1->y > v3->y) {
        soft_vertex *v = v1;
        v1 = v3;
        v3 = v;
    }
    if (v1->y > v4->y) {
        soft_vertex *v = v1;
        v1 = v4;
        v4 = v;
    }
    if (v2->y > v3->y) {
        soft_vertex *v = v2;
        v2 = v3;
        v3 = v;
    }
    if (v2->y > v4->y) {
        soft_vertex *v = v2;
        v2 = v4;
        v4 = v;
    }
    if (v3->y > v4->y) {
        soft_vertex *v = v3;
        v3 = v4;
        v4 = v;
    }

    height = v4->y - v1->y;
    if (height == 0) height = 1;
    width = (v4->x - v1->x) >> 16;
    int32_test1 = (((v2->y - v1->y) << 16) / height) * width + (v1->x - v2->x);
    int32_test2 = (((v3->y - v1->y) << 16) / height) * width + (v1->x - v3->x);

    if (int32_test1 < 0)  // 2 is right
    {
        if (int32_test2 < 0)  // 3 is right
        {
            left_array[0] = v4;
            left_array[1] = v1;
            left_section = 1;

            height = v3->y - v1->y;
            if (height == 0) height = 1;
            int32_test1 = (((v2->y - v1->y) << 16) / height) * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
            if (int32_test1 >= 0) {
                right_array[0] = v4;  //  1
                right_array[1] = v3;  //     3
                right_array[2] = v1;  //  4
                right_section = 2;
            } else {
                height = v4->y - v2->y;
                if (height == 0) height = 1;
                int32_test1 = (((v3->y - v2->y) << 16) / height) * ((v4->x - v2->x) >> 16) + (v2->x - v3->x);
                if (int32_test1 >= 0) {
                    right_array[0] = v4;  //  1
                    right_array[1] = v2;  //     2
                    right_array[2] = v1;  //  4
                    right_section = 2;
                } else {
                    right_array[0] = v4;  //  1
                    right_array[1] = v3;  //     2
                    right_array[2] = v2;  //     3
                    right_array[3] = v1;  //  4
                    right_section = 3;
                }
            }
        } else {
            left_array[0] = v4;
            left_array[1] = v3;   //    1
            left_array[2] = v1;   //      2
            left_section = 2;     //  3
            right_array[0] = v4;  //    4
            right_array[1] = v2;
            right_array[2] = v1;
            right_section = 2;
        }
    } else {
        if (int32_test2 < 0) {
            left_array[0] = v4;  //    1
            left_array[1] = v2;  //  2
            left_array[2] = v1;  //      3
            left_section = 2;    //    4
            right_array[0] = v4;
            right_array[1] = v3;
            right_array[2] = v1;
            right_section = 2;
        } else {
            right_array[0] = v4;
            right_array[1] = v1;
            right_section = 1;

            height = v3->y - v1->y;
            if (height == 0) height = 1;
            int32_test1 = (((v2->y - v1->y) << 16) / height) * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
            if (int32_test1 < 0) {
                left_array[0] = v4;  //    1
                left_array[1] = v3;  //  3
                left_array[2] = v1;  //    4
                left_section = 2;
            } else {
                height = v4->y - v2->y;
                if (height == 0) height = 1;
                int32_test1 = (((v3->y - v2->y) << 16) / height) * ((v4->x - v2->x) >> 16) + (v2->x - v3->x);
                if (int32_test1 < 0) {
                    left_array[0] = v4;  //    1
                    left_array[1] = v2;  //  2
                    left_array[2] = v1;  //    4
                    left_section = 2;
                } else {
                    left_array[0] = v4;  //    1
                    left_array[1] = v3;  //  2
                    left_array[2] = v2;  //  3
                    left_array[3] = v1;  //     4
                    left_section = 3;
                }
            }
        }
    }

    while (LeftSection_FT4() <= 0) {
        if (--left_section <= 0) break;
    }

    while (RightSection_FT4() <= 0) {
        if (--right_section <= 0) break;
    }

    Ymin = v1->y;
    Ymax = std::min(v4->y - 1, drawH);

    return true;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

static inline int RightSection_GT4(void) {
    soft_vertex *v1 = right_array[right_section];
    soft_vertex *v2 = right_array[right_section - 1];

    int height = v2->y - v1->y;
    right_section_height = height;
    right_x = v1->x;
    right_u = v1->u;
    right_v = v1->v;
    right_R = v1->R;
    right_G = v1->G;
    right_B = v1->B;

    if (height == 0) {
        return 0;
    }
    delta_right_x = (v2->x - v1->x) / height;
    delta_right_u = (v2->u - v1->u) / height;
    delta_right_v = (v2->v - v1->v) / height;
    delta_right_R = (v2->R - v1->R) / height;
    delta_right_G = (v2->G - v1->G) / height;
    delta_right_B = (v2->B - v1->B) / height;

    return height;
}

////////////////////////////////////////////////////////////////////////

static inline int LeftSection_GT4(void) {
    soft_vertex *v1 = left_array[left_section];
    soft_vertex *v2 = left_array[left_section - 1];

    int height = v2->y - v1->y;
    left_section_height = height;
    left_x = v1->x;
    left_u = v1->u;
    left_v = v1->v;
    left_R = v1->R;
    left_G = v1->G;
    left_B = v1->B;

    if (height == 0) {
        return 0;
    }
    delta_left_x = (v2->x - v1->x) / height;
    delta_left_u = (v2->u - v1->u) / height;
    delta_left_v = (v2->v - v1->v) / height;
    delta_left_R = (v2->R - v1->R) / height;
    delta_left_G = (v2->G - v1->G) / height;
    delta_left_B = (v2->B - v1->B) / height;

    return height;
}

////////////////////////////////////////////////////////////////////////

static inline bool NextRow_GT4(void) {
    if (--left_section_height <= 0) {
        if (--left_section > 0)
            while (LeftSection_GT4() <= 0) {
                if (--left_section <= 0) break;
            }
    } else {
        left_x += delta_left_x;
        left_u += delta_left_u;
        left_v += delta_left_v;
        left_R += delta_left_R;
        left_G += delta_left_G;
        left_B += delta_left_B;
    }

    if (--right_section_height <= 0) {
        if (--right_section > 0)
            while (RightSection_GT4() <= 0) {
                if (--right_section <= 0) break;
            }
    } else {
        right_x += delta_right_x;
        right_u += delta_right_u;
        right_v += delta_right_v;
        right_R += delta_right_R;
        right_G += delta_right_G;
        right_B += delta_right_B;
    }
    return false;
}

////////////////////////////////////////////////////////////////////////

inline bool PCSX::SoftGPU::SoftRenderer::SetupSections_GT4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                           int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                           int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3,
                                                           int16_t tx4, int16_t ty4, int32_t rgb1, int32_t rgb2,
                                                           int32_t rgb3, int32_t rgb4) {
    soft_vertex *v1, *v2, *v3, *v4;
    int height, width, int32_test1, int32_test2;

    v1 = vtx;
    v1->x = x1 << 16;
    v1->y = y1;
    v1->u = tx1 << 16;
    v1->v = ty1 << 16;
    v1->R = (rgb1)&0x00ff0000;
    v1->G = (rgb1 << 8) & 0x00ff0000;
    v1->B = (rgb1 << 16) & 0x00ff0000;

    v2 = vtx + 1;
    v2->x = x2 << 16;
    v2->y = y2;
    v2->u = tx2 << 16;
    v2->v = ty2 << 16;
    v2->R = (rgb2)&0x00ff0000;
    v2->G = (rgb2 << 8) & 0x00ff0000;
    v2->B = (rgb2 << 16) & 0x00ff0000;

    v3 = vtx + 2;
    v3->x = x3 << 16;
    v3->y = y3;
    v3->u = tx3 << 16;
    v3->v = ty3 << 16;
    v3->R = (rgb3)&0x00ff0000;
    v3->G = (rgb3 << 8) & 0x00ff0000;
    v3->B = (rgb3 << 16) & 0x00ff0000;

    v4 = vtx + 3;
    v4->x = x4 << 16;
    v4->y = y4;
    v4->u = tx4 << 16;
    v4->v = ty4 << 16;
    v4->R = (rgb4)&0x00ff0000;
    v4->G = (rgb4 << 8) & 0x00ff0000;
    v4->B = (rgb4 << 16) & 0x00ff0000;

    if (v1->y > v2->y) {
        soft_vertex *v = v1;
        v1 = v2;
        v2 = v;
    }
    if (v1->y > v3->y) {
        soft_vertex *v = v1;
        v1 = v3;
        v3 = v;
    }
    if (v1->y > v4->y) {
        soft_vertex *v = v1;
        v1 = v4;
        v4 = v;
    }
    if (v2->y > v3->y) {
        soft_vertex *v = v2;
        v2 = v3;
        v3 = v;
    }
    if (v2->y > v4->y) {
        soft_vertex *v = v2;
        v2 = v4;
        v4 = v;
    }
    if (v3->y > v4->y) {
        soft_vertex *v = v3;
        v3 = v4;
        v4 = v;
    }

    height = v4->y - v1->y;
    if (height == 0) height = 1;
    width = (v4->x - v1->x) >> 16;
    int32_test1 = (((v2->y - v1->y) << 16) / height) * width + (v1->x - v2->x);
    int32_test2 = (((v3->y - v1->y) << 16) / height) * width + (v1->x - v3->x);

    if (int32_test1 < 0)  // 2 is right
    {
        if (int32_test2 < 0)  // 3 is right
        {
            left_array[0] = v4;
            left_array[1] = v1;
            left_section = 1;

            height = v3->y - v1->y;
            if (height == 0) height = 1;
            int32_test1 = (((v2->y - v1->y) << 16) / height) * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
            if (int32_test1 >= 0) {
                right_array[0] = v4;  //  1
                right_array[1] = v3;  //     3
                right_array[2] = v1;  //  4
                right_section = 2;
            } else {
                height = v4->y - v2->y;
                if (height == 0) height = 1;
                int32_test1 = (((v3->y - v2->y) << 16) / height) * ((v4->x - v2->x) >> 16) + (v2->x - v3->x);
                if (int32_test1 >= 0) {
                    right_array[0] = v4;  //  1
                    right_array[1] = v2;  //     2
                    right_array[2] = v1;  //  4
                    right_section = 2;
                } else {
                    right_array[0] = v4;  //  1
                    right_array[1] = v3;  //     2
                    right_array[2] = v2;  //     3
                    right_array[3] = v1;  //  4
                    right_section = 3;
                }
            }
        } else {
            left_array[0] = v4;
            left_array[1] = v3;   //    1
            left_array[2] = v1;   //      2
            left_section = 2;     //  3
            right_array[0] = v4;  //    4
            right_array[1] = v2;
            right_array[2] = v1;
            right_section = 2;
        }
    } else {
        if (int32_test2 < 0) {
            left_array[0] = v4;  //    1
            left_array[1] = v2;  //  2
            left_array[2] = v1;  //      3
            left_section = 2;    //    4
            right_array[0] = v4;
            right_array[1] = v3;
            right_array[2] = v1;
            right_section = 2;
        } else {
            right_array[0] = v4;
            right_array[1] = v1;
            right_section = 1;

            height = v3->y - v1->y;
            if (height == 0) height = 1;
            int32_test1 = (((v2->y - v1->y) << 16) / height) * ((v3->x - v1->x) >> 16) + (v1->x - v2->x);
            if (int32_test1 < 0) {
                left_array[0] = v4;  //    1
                left_array[1] = v3;  //  3
                left_array[2] = v1;  //    4
                left_section = 2;
            } else {
                height = v4->y - v2->y;
                if (height == 0) height = 1;
                int32_test1 = (((v3->y - v2->y) << 16) / height) * ((v4->x - v2->x) >> 16) + (v2->x - v3->x);
                if (int32_test1 < 0) {
                    left_array[0] = v4;  //    1
                    left_array[1] = v2;  //  2
                    left_array[2] = v1;  //    4
                    left_section = 2;
                } else {
                    left_array[0] = v4;  //    1
                    left_array[1] = v3;  //  2
                    left_array[2] = v2;  //  3
                    left_array[3] = v1;  //     4
                    left_section = 3;
                }
            }
        }
    }

    while (LeftSection_GT4() <= 0) {
        if (--left_section <= 0) break;
    }

    while (RightSection_GT4() <= 0) {
        if (--right_section <= 0) break;
    }

    Ymin = v1->y;
    Ymax = std::min(v4->y - 1, drawH);

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

inline void PCSX::SoftGPU::SoftRenderer::drawPoly3Fi(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                     int16_t y3, int32_t rgb) {
    int i, j, xmin, xmax, ymin, ymax;
    uint16_t color;
    uint32_t lcolor;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_F(x1, y1, x2, y2, x3, y3)) return;

    ymax = Ymax;

    color = ((rgb & 0x00f80000) >> 9) | ((rgb & 0x0000f800) >> 6) | ((rgb & 0x000000f8) >> 3);
    lcolor = lSetMask | (((uint32_t)(color)) << 16) | color;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_F()) return;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        color |= sSetMask;
        for (i = ymin; i <= ymax; i++) {
            xmin = left_x >> 16;
            if (drawX > xmin) xmin = drawX;
            xmax = (right_x >> 16) - 1;
            if (drawW < xmax) xmax = drawW;

            for (j = xmin; j < xmax; j += 2) {
                *((uint32_t *)&psxVuw[(i << 10) + j]) = lcolor;
            }
            if (j == xmax) psxVuw[(i << 10) + j] = color;

            if (NextRow_F()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = left_x >> 16;
        if (drawX > xmin) xmin = drawX;
        xmax = (right_x >> 16) - 1;
        if (drawW < xmax) xmax = drawW;

        for (j = xmin; j < xmax; j += 2) {
            GetShadeTransCol32((uint32_t *)&psxVuw[(i << 10) + j], lcolor);
        }
        if (j == xmax) GetShadeTransCol(&psxVuw[(i << 10) + j], color);

        if (NextRow_F()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3F(int32_t rgb) { drawPoly3Fi(lx0, ly0, lx1, ly1, lx2, ly2, rgb); }

#ifdef POLYQUAD3FS

void drawPoly4F_TRI(int32_t rgb) {
    drawPoly3Fi(lx1, ly1, lx3, ly3, lx2, ly2, rgb);
    drawPoly3Fi(lx0, ly0, lx1, ly1, lx2, ly2, rgb);
}

#endif

// more exact:

void PCSX::SoftGPU::SoftRenderer::drawPoly4F(int32_t rgb) {
    int i, j, xmin, xmax, ymin, ymax;
    uint16_t color;
    uint32_t lcolor;

    if (lx0 > drawW && lx1 > drawW && lx2 > drawW && lx3 > drawW) return;
    if (ly0 > drawH && ly1 > drawH && ly2 > drawH && ly3 > drawH) return;
    if (lx0 < drawX && lx1 < drawX && lx2 < drawX && lx3 < drawX) return;
    if (ly0 < drawY && ly1 < drawY && ly2 < drawY && ly3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_F4(lx0, ly0, lx1, ly1, lx2, ly2, lx3, ly3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_F4()) return;

    color = ((rgb & 0x00f80000) >> 9) | ((rgb & 0x0000f800) >> 6) | ((rgb & 0x000000f8) >> 3);
    lcolor = lSetMask | (((uint32_t)(color)) << 16) | color;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        color |= sSetMask;
        for (i = ymin; i <= ymax; i++) {
            xmin = left_x >> 16;
            if (drawX > xmin) xmin = drawX;
            xmax = (right_x >> 16) - 1;
            if (drawW < xmax) xmax = drawW;

            for (j = xmin; j < xmax; j += 2) {
                *((uint32_t *)&psxVuw[(i << 10) + j]) = lcolor;
            }
            if (j == xmax) psxVuw[(i << 10) + j] = color;

            if (NextRow_F4()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = left_x >> 16;
        if (drawX > xmin) xmin = drawX;
        xmax = (right_x >> 16) - 1;
        if (drawW < xmax) xmax = drawW;

        for (j = xmin; j < xmax; j += 2) {
            GetShadeTransCol32((uint32_t *)&psxVuw[(i << 10) + j], lcolor);
        }
        if (j == xmax) GetShadeTransCol(&psxVuw[(i << 10) + j], color);

        if (NextRow_F4()) return;
    }
}

////////////////////////////////////////////////////////////////////////
// POLY 3/4 F-SHADED TEX PAL 4
////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TEx4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                                int16_t ty3, int16_t clX, int16_t clY) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, XAdjust;
    int32_t clutP;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);

    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }

                for (j = xmin; j < xmax; j += 2) {
                    XAdjust = (posX >> 16);
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    XAdjust = ((posX + difX) >> 16);
                    tC2 = psxVub[static_cast<int32_t>((((posY + difY) >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                    tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                    GetTextureTransColG32_S((uint32_t *)&psxVuw[(i << 10) + j],
                                            psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);

                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    XAdjust = (posX >> 16);
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    GetTextureTransColG_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
                }
            }
            if (NextRow_FT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }

            for (j = xmin; j < xmax; j += 2) {
                XAdjust = (posX >> 16);
                tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                XAdjust = ((posX + difX) >> 16);
                tC2 = psxVub[static_cast<int32_t>((((posY + difY) >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                GetTextureTransColG32((uint32_t *)&psxVuw[(i << 10) + j],
                                      psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);

                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                XAdjust = (posX >> 16);
                tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                GetTextureTransColG(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
            }
        }
        if (NextRow_FT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TEx4_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                   int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2,
                                                   int16_t tx3, int16_t ty3, int16_t clX, int16_t clY) {
    int i, j, xmin, xmax, ymin, ymax, n_xi, n_yi, TXV;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, XAdjust;
    int32_t clutP;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT()) return;

    clutP = (clY << 10) + clX;

    YAdjust = (GlobalTextAddrY << 10) + GlobalTextAddrX;

    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16) - 1;
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }

                for (j = xmin; j < xmax; j += 2) {
                    XAdjust = (posX >> 16);

                    TXV = posY >> 16;
                    n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                    n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                    tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                    XAdjust = ((posX + difX) >> 16);

                    TXV = (posY + difY) >> 16;
                    n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                    n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                    tC2 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                    GetTextureTransColG32_S((uint32_t *)&psxVuw[(i << 10) + j],
                                            psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);

                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    XAdjust = (posX >> 16);

                    TXV = posY >> 16;
                    n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                    n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                    tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                    GetTextureTransColG_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
                }
            }
            if (NextRow_FT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }

            for (j = xmin; j < xmax; j += 2) {
                XAdjust = (posX >> 16);

                TXV = posY >> 16;
                n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                XAdjust = ((posX + difX) >> 16);

                TXV = (posY + difY) >> 16;
                n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                tC2 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                GetTextureTransColG32((uint32_t *)&psxVuw[(i << 10) + j],
                                      psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);

                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                XAdjust = (posX >> 16);

                TXV = posY >> 16;
                n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                GetTextureTransColG(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
            }
        }
        if (NextRow_FT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TEx4_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                   int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2,
                                                   int16_t tx3, int16_t ty3, int16_t clX, int16_t clY) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, XAdjust;
    int32_t clutP;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);
    YAdjust += (TWin.Position.y0 << 11) + (TWin.Position.x0 >> 1);

    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);  //-1; //!!!!!!!!!!!!!!!!
            if (xmax > xmin) xmax--;

            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }

                for (j = xmin; j < xmax; j += 2) {
                    XAdjust = (posX >> 16) % TWin.Position.x1;
                    tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    XAdjust = ((posX + difX) >> 16) % TWin.Position.x1;
                    tC2 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (XAdjust >> 1))];
                    tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                    GetTextureTransColG32_S((uint32_t *)&psxVuw[(i << 10) + j],
                                            psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);

                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    XAdjust = (posX >> 16) % TWin.Position.x1;
                    tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    GetTextureTransColG_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
                }
            }
            if (NextRow_FT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }

            for (j = xmin; j < xmax; j += 2) {
                XAdjust = (posX >> 16) % TWin.Position.x1;
                tC1 =
                    psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                XAdjust = ((posX + difX) >> 16) % TWin.Position.x1;
                tC2 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                  (XAdjust >> 1))];
                tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                GetTextureTransColG32((uint32_t *)&psxVuw[(i << 10) + j],
                                      psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);

                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                XAdjust = (posX >> 16) % TWin.Position.x1;
                tC1 =
                    psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                GetTextureTransColG(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
            }
        }
        if (NextRow_FT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

#ifdef POLYQUAD3

void PCSX::SoftGPU::SoftRenderer::drawPoly4TEx4_TRI(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                    int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                    int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                    int16_t ty4, int16_t clX, int16_t clY) {
    drawPoly3TEx4(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4, clX, clY);
    drawPoly3TEx4(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4, clX, clY);
}

#endif

// more exact:

void PCSX::SoftGPU::SoftRenderer::drawPoly4TEx4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                int16_t x4, int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2,
                                                int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4,
                                                int16_t clX, int16_t clY) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP, XAdjust;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT4()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (right_u - posX) / num;
                difY = (right_v - posY) / num;
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
                    XAdjust = (posX >> 16);
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    XAdjust = ((posX + difX) >> 16);
                    tC2 = psxVub[static_cast<int32_t>((((posY + difY) >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                    tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                    GetTextureTransColG32_S((uint32_t *)&psxVuw[(i << 10) + j],
                                            psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    XAdjust = (posX >> 16);
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    GetTextureTransColG_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
                }
            }
            if (NextRow_FT4()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16);

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (right_u - posX) / num;
            difY = (right_v - posY) / num;
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
                XAdjust = (posX >> 16);
                tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                XAdjust = ((posX + difX) >> 16);
                tC2 = psxVub[static_cast<int32_t>((((posY + difY) >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                GetTextureTransColG32((uint32_t *)&psxVuw[(i << 10) + j],
                                      psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                XAdjust = (posX >> 16);
                tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                GetTextureTransColG(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
            }
        }
        if (NextRow_FT4()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TEx4_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                   int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                   int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                   int16_t ty4, int16_t clX, int16_t clY) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax, n_xi, n_yi, TXV;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP, XAdjust;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT4()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 10) + GlobalTextAddrX;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (right_u - posX) / num;
                difY = (right_v - posY) / num;
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
                    XAdjust = (posX >> 16);

                    TXV = posY >> 16;
                    n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                    n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                    tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                    XAdjust = ((posX + difX) >> 16);

                    TXV = (posY + difY) >> 16;
                    n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                    n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                    tC2 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                    GetTextureTransColG32_S((uint32_t *)&psxVuw[(i << 10) + j],
                                            psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }

                if (j == xmax) {
                    XAdjust = (posX >> 16);
                    TXV = posY >> 16;
                    n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                    n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                    tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                    GetTextureTransColG_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
                }
            }
            if (NextRow_FT4()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16);

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (right_u - posX) / num;
            difY = (right_v - posY) / num;
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
                XAdjust = (posX >> 16);

                TXV = posY >> 16;
                n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                XAdjust = ((posX + difX) >> 16);

                TXV = (posY + difY) >> 16;
                n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                tC2 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                GetTextureTransColG32((uint32_t *)&psxVuw[(i << 10) + j],
                                      psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                XAdjust = (posX >> 16);
                TXV = posY >> 16;
                n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                GetTextureTransColG(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
            }
        }
        if (NextRow_FT4()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TEx4_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                   int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                   int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                   int16_t ty4, int16_t clX, int16_t clY) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP, XAdjust;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT4()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);
    YAdjust += (TWin.Position.y0 << 11) + (TWin.Position.x0 >> 1);

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (right_u - posX) / num;
                difY = (right_v - posY) / num;
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
                    XAdjust = (posX >> 16) % TWin.Position.x1;
                    tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    XAdjust = ((posX + difX) >> 16) % TWin.Position.x1;
                    tC2 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (XAdjust >> 1))];
                    tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                    GetTextureTransColG32_S((uint32_t *)&psxVuw[(i << 10) + j],
                                            psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    XAdjust = (posX >> 16) % TWin.Position.x1;
                    tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    GetTextureTransColG_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
                }
            }
            if (NextRow_FT4()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16);

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (right_u - posX) / num;
            difY = (right_v - posY) / num;
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
                XAdjust = (posX >> 16) % TWin.Position.x1;
                tC1 =
                    psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                XAdjust = ((posX + difX) >> 16) % TWin.Position.x1;
                tC2 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                  (XAdjust >> 1))];
                tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                GetTextureTransColG32((uint32_t *)&psxVuw[(i << 10) + j],
                                      psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                XAdjust = (posX >> 16) % TWin.Position.x1;
                tC1 =
                    psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                GetTextureTransColG(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
            }
        }
        if (NextRow_FT4()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TEx4_TW_S(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                     int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                     int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                     int16_t ty4, int16_t clX, int16_t clY) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP, XAdjust;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT4()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);
    YAdjust += (TWin.Position.y0 << 11) + (TWin.Position.x0 >> 1);

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (right_u - posX) / num;
                difY = (right_v - posY) / num;
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
                    XAdjust = (posX >> 16) % TWin.Position.x1;
                    tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    XAdjust = ((posX + difX) >> 16) % TWin.Position.x1;
                    tC2 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (XAdjust >> 1))];
                    tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                    GetTextureTransColG32_S((uint32_t *)&psxVuw[(i << 10) + j],
                                            psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    XAdjust = (posX >> 16) % TWin.Position.x1;
                    tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    GetTextureTransColG_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
                }
            }
            if (NextRow_FT4()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16);

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (right_u - posX) / num;
            difY = (right_v - posY) / num;
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
                XAdjust = (posX >> 16) % TWin.Position.x1;
                tC1 =
                    psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                XAdjust = ((posX + difX) >> 16) % TWin.Position.x1;
                tC2 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                  (XAdjust >> 1))];
                tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                GetTextureTransColG32_SPR((uint32_t *)&psxVuw[(i << 10) + j],
                                          psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                XAdjust = (posX >> 16) % TWin.Position.x1;
                tC1 =
                    psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                GetTextureTransColG_SPR(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
            }
        }
        if (NextRow_FT4()) return;
    }
}
////////////////////////////////////////////////////////////////////////
// POLY 3 F-SHADED TEX PAL 8
////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TEx8(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                                int16_t ty3, int16_t clX, int16_t clY) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);

    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }

                for (j = xmin; j < xmax; j += 2) {
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (posX >> 16))];
                    tC2 = psxVub[static_cast<int32_t>((((posY + difY) >> 5) & 0xFFFFF800) + YAdjust +
                                                      ((posX + difX) >> 16))];
                    GetTextureTransColG32_S((uint32_t *)&psxVuw[(i << 10) + j],
                                            psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }

                if (j == xmax) {
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (posX >> 16))];
                    GetTextureTransColG_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
                }
            }
            if (NextRow_FT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }

            for (j = xmin; j < xmax; j += 2) {
                tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (posX >> 16))];
                tC2 =
                    psxVub[static_cast<int32_t>((((posY + difY) >> 5) & 0xFFFFF800) + YAdjust + ((posX + difX) >> 16))];
                GetTextureTransColG32((uint32_t *)&psxVuw[(i << 10) + j],
                                      psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }

            if (j == xmax) {
                tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (posX >> 16))];
                GetTextureTransColG(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
            }
        }
        if (NextRow_FT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TEx8_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                   int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2,
                                                   int16_t tx3, int16_t ty3, int16_t clX, int16_t clY) {
    int i, j, xmin, xmax, ymin, ymax, n_xi, n_yi, TXV, TXU;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT()) return;

    clutP = (clY << 10) + clX;

    YAdjust = (GlobalTextAddrY << 10) + GlobalTextAddrX;

    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }

                for (j = xmin; j < xmax; j += 2) {
                    TXU = posX >> 16;
                    TXV = posY >> 16;
                    n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                    n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);

                    tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;

                    TXU = (posX + difX) >> 16;
                    TXV = (posY + difY) >> 16;
                    n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                    n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);

                    tC2 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;

                    GetTextureTransColG32_S((uint32_t *)&psxVuw[(i << 10) + j],
                                            psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }

                if (j == xmax) {
                    TXU = posX >> 16;
                    TXV = posY >> 16;
                    n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                    n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);

                    tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;

                    GetTextureTransColG_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
                }
            }
            if (NextRow_FT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }

            for (j = xmin; j < xmax; j += 2) {
                TXU = posX >> 16;
                TXV = posY >> 16;
                n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);

                tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;

                TXU = (posX + difX) >> 16;
                TXV = (posY + difY) >> 16;
                n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);

                tC2 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;

                GetTextureTransColG32((uint32_t *)&psxVuw[(i << 10) + j],
                                      psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }

            if (j == xmax) {
                TXU = posX >> 16;
                TXV = posY >> 16;
                n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);

                tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;

                GetTextureTransColG(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
            }
        }
        if (NextRow_FT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TEx8_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                   int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2,
                                                   int16_t tx3, int16_t ty3, int16_t clX, int16_t clY) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);
    YAdjust += (TWin.Position.y0 << 11) + (TWin.Position.x0);

    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);  //-1; //!!!!!!!!!!!!!!!!
            if (xmax > xmin) xmax--;

            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }

                for (j = xmin; j < xmax; j += 2) {
                    tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      ((posX >> 16) % TWin.Position.x1))];
                    tC2 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (((posX + difX) >> 16) % TWin.Position.x1))];
                    GetTextureTransColG32_S((uint32_t *)&psxVuw[(i << 10) + j],
                                            psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }

                if (j == xmax) {
                    tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      ((posX >> 16) % TWin.Position.x1))];
                    GetTextureTransColG_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
                }
            }
            if (NextRow_FT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }

            for (j = xmin; j < xmax; j += 2) {
                tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                  ((posX >> 16) % TWin.Position.x1))];
                tC2 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                  (((posX + difX) >> 16) % TWin.Position.x1))];
                GetTextureTransColG32((uint32_t *)&psxVuw[(i << 10) + j],
                                      psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }

            if (j == xmax) {
                tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                  ((posX >> 16) % TWin.Position.x1))];
                GetTextureTransColG(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
            }
        }
        if (NextRow_FT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

#ifdef POLYQUAD3

void PCSX::SoftGPU::SoftRenderer::drawPoly4TEx8_TRI(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                    int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                    int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                    int16_t ty4, int16_t clX, int16_t clY) {
    drawPoly3TEx8(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4, clX, clY);

    drawPoly3TEx8(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4, clX, clY);
}

#endif

// more exact:

void PCSX::SoftGPU::SoftRenderer::drawPoly4TEx8(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                int16_t x4, int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2,
                                                int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4,
                                                int16_t clX, int16_t clY) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT4()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (right_u - posX) / num;
                difY = (right_v - posY) / num;
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
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (posX >> 16))];
                    tC2 = psxVub[static_cast<int32_t>((((posY + difY) >> 5) & 0xFFFFF800) + YAdjust +
                                                      ((posX + difX) >> 16))];
                    GetTextureTransColG32_S((uint32_t *)&psxVuw[(i << 10) + j],
                                            psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (posX >> 16))];
                    GetTextureTransColG_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
                }
            }
            if (NextRow_FT4()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16);

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (right_u - posX) / num;
            difY = (right_v - posY) / num;
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
                tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (posX >> 16))];
                tC2 =
                    psxVub[static_cast<int32_t>((((posY + difY) >> 5) & 0xFFFFF800) + YAdjust + ((posX + difX) >> 16))];
                GetTextureTransColG32((uint32_t *)&psxVuw[(i << 10) + j],
                                      psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (posX >> 16))];
                GetTextureTransColG(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
            }
        }
        if (NextRow_FT4()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TEx8_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                   int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                   int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                   int16_t ty4, int16_t clX, int16_t clY) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax, n_xi, n_yi, TXV, TXU;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT4()) return;

    clutP = (clY << 10) + clX;

    YAdjust = (GlobalTextAddrY << 10) + GlobalTextAddrX;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (right_u - posX) / num;
                difY = (right_v - posY) / num;
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
                    TXU = posX >> 16;
                    TXV = posY >> 16;
                    n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                    n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);

                    tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;

                    TXU = (posX + difX) >> 16;
                    TXV = (posY + difY) >> 16;
                    n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                    n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);

                    tC2 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;

                    GetTextureTransColG32_S((uint32_t *)&psxVuw[(i << 10) + j],
                                            psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    TXU = posX >> 16;
                    TXV = posY >> 16;
                    n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                    n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);

                    tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;

                    GetTextureTransColG_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
                }
            }
            if (NextRow_FT4()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16);

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (right_u - posX) / num;
            difY = (right_v - posY) / num;
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
                TXU = posX >> 16;
                TXV = posY >> 16;
                n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);

                tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;

                TXU = (posX + difX) >> 16;
                TXV = (posY + difY) >> 16;
                n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);

                tC2 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;

                GetTextureTransColG32((uint32_t *)&psxVuw[(i << 10) + j],
                                      psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                TXU = posX >> 16;
                TXV = posY >> 16;
                n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);
                tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;
                GetTextureTransColG(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
            }
        }
        if (NextRow_FT4()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TEx8_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                   int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                   int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                   int16_t ty4, int16_t clX, int16_t clY) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT4()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);
    YAdjust += (TWin.Position.y0 << 11) + (TWin.Position.x0);

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (right_u - posX) / num;
                difY = (right_v - posY) / num;
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
                    tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      ((posX >> 16) % TWin.Position.x1))];
                    tC2 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (((posX + difX) >> 16) % TWin.Position.x1))];
                    GetTextureTransColG32_S((uint32_t *)&psxVuw[(i << 10) + j],
                                            psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    tC1 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      ((posX >> 16) % TWin.Position.x1))];
                    GetTextureTransColG_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
                }
            }
            if (NextRow_FT4()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16);

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (right_u - posX) / num;
            difY = (right_v - posY) / num;
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
                tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                  ((posX >> 16) % TWin.Position.x1))];
                tC2 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                  (((posX + difX) >> 16) % TWin.Position.x1))];
                GetTextureTransColG32((uint32_t *)&psxVuw[(i << 10) + j],
                                      psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                tC1 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                  ((posX >> 16) % TWin.Position.x1))];
                GetTextureTransColG(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
            }
        }
        if (NextRow_FT4()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TEx8_TW_S(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                     int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                     int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                     int16_t ty4, int16_t clX, int16_t clY) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT4()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);
    YAdjust += (TWin.Position.y0 << 11) + (TWin.Position.x0);

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (right_u - posX) / num;
                difY = (right_v - posY) / num;
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
                    tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      ((posX >> 16) % TWin.Position.x1))];
                    tC2 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (((posX + difX) >> 16) % TWin.Position.x1))];
                    GetTextureTransColG32_S((uint32_t *)&psxVuw[(i << 10) + j],
                                            psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax) {
                    tC1 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      ((posX >> 16) % TWin.Position.x1))];
                    GetTextureTransColG_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
                }
            }
            if (NextRow_FT4()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16);

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (right_u - posX) / num;
            difY = (right_v - posY) / num;
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
                tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                  ((posX >> 16) % TWin.Position.x1))];
                tC2 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                  (((posX + difX) >> 16) % TWin.Position.x1))];
                GetTextureTransColG32_SPR((uint32_t *)&psxVuw[(i << 10) + j],
                                          psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16);
                posX += difX2;
                posY += difY2;
            }
            if (j == xmax) {
                tC1 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                  ((posX >> 16) % TWin.Position.x1))];
                GetTextureTransColG_SPR(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1]);
            }
        }
        if (NextRow_FT4()) return;
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

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT()) return;

    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }

                for (j = xmin; j < xmax; j += 2) {
                    GetTextureTransColG32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j],
                        (((int32_t)psxVuw[((((posY + difY) >> 16) + GlobalTextAddrY) << 10) + ((posX + difX) >> 16) +
                                          GlobalTextAddrX])
                         << 16) |
                            psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + ((posX) >> 16) + GlobalTextAddrX]);

                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax)
                    GetTextureTransColG_S(
                        &psxVuw[(i << 10) + j],
                        psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + (posX >> 16) + GlobalTextAddrX]);
            }
            if (NextRow_FT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }

            for (j = xmin; j < xmax; j += 2) {
                GetTextureTransColG32(
                    (uint32_t *)&psxVuw[(i << 10) + j],
                    (((int32_t)psxVuw[((((posY + difY) >> 16) + GlobalTextAddrY) << 10) + ((posX + difX) >> 16) +
                                      GlobalTextAddrX])
                     << 16) |
                        psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + ((posX) >> 16) + GlobalTextAddrX]);

                posX += difX2;
                posY += difY2;
            }
            if (j == xmax)
                GetTextureTransColG(&psxVuw[(i << 10) + j],
                                    psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + (posX >> 16) + GlobalTextAddrX]);
        }
        if (NextRow_FT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TD_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                 int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                                 int16_t ty3) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT()) return;

    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                }

                for (j = xmin; j < xmax; j += 2) {
                    GetTextureTransColG32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j],
                        (((int32_t)
                              psxVuw[(((((posY + difY) >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0)
                                      << 10) +
                                     (((posX + difX) >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0])
                         << 16) |
                            psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0) << 10) +
                                   (((posX) >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0]);

                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax)
                    GetTextureTransColG_S(
                        &psxVuw[(i << 10) + j],
                        psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0) << 10) +
                               ((posX >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0]);
            }
            if (NextRow_FT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
            }

            for (j = xmin; j < xmax; j += 2) {
                GetTextureTransColG32(
                    (uint32_t *)&psxVuw[(i << 10) + j],
                    (((int32_t)psxVuw[(((((posY + difY) >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0)
                                       << 10) +
                                      (((posX + difX) >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0])
                     << 16) |
                        psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0) << 10) +
                               (((posX) >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0]);

                posX += difX2;
                posY += difY2;
            }
            if (j == xmax)
                GetTextureTransColG(
                    &psxVuw[(i << 10) + j],
                    psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0) << 10) +
                           ((posX >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0]);
        }
        if (NextRow_FT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

#ifdef POLYQUAD3

void PCSX::SoftGPU::SoftRenderer::drawPoly4TD_TRI(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                  int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                  int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                  int16_t ty4) {
    drawPoly3TD(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4);
    drawPoly3TD(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4);
}

#endif

// more exact:

void PCSX::SoftGPU::SoftRenderer::drawPoly4TD(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                              int16_t x4, int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2,
                                              int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT4()) return;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (right_u - posX) / num;
                difY = (right_v - posY) / num;
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
                    GetTextureTransColG32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j],
                        (((int32_t)psxVuw[((((posY + difY) >> 16) + GlobalTextAddrY) << 10) + ((posX + difX) >> 16) +
                                          GlobalTextAddrX])
                         << 16) |
                            psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + ((posX) >> 16) + GlobalTextAddrX]);

                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax)
                    GetTextureTransColG_S(
                        &psxVuw[(i << 10) + j],
                        psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + (posX >> 16) + GlobalTextAddrX]);
            }
            if (NextRow_FT4()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16);

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (right_u - posX) / num;
            difY = (right_v - posY) / num;
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
                GetTextureTransColG32(
                    (uint32_t *)&psxVuw[(i << 10) + j],
                    (((int32_t)psxVuw[((((posY + difY) >> 16) + GlobalTextAddrY) << 10) + ((posX + difX) >> 16) +
                                      GlobalTextAddrX])
                     << 16) |
                        psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + ((posX) >> 16) + GlobalTextAddrX]);

                posX += difX2;
                posY += difY2;
            }
            if (j == xmax)
                GetTextureTransColG(&psxVuw[(i << 10) + j],
                                    psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + (posX >> 16) + GlobalTextAddrX]);
        }
        if (NextRow_FT4()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TD_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                 int16_t x4, int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2,
                                                 int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT4()) return;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (right_u - posX) / num;
                difY = (right_v - posY) / num;
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
                    GetTextureTransColG32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j],
                        (((int32_t)
                              psxVuw[(((((posY + difY) >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0)
                                      << 10) +
                                     (((posX + difX) >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0])
                         << 16) |
                            psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY) << 10) + TWin.Position.y0 +
                                   ((posX >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0]);

                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax)
                    GetTextureTransColG_S(
                        &psxVuw[(i << 10) + j],
                        psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0) << 10) +
                               ((posX >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0]);
            }
            if (NextRow_FT4()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16);

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (right_u - posX) / num;
            difY = (right_v - posY) / num;
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
                GetTextureTransColG32(
                    (uint32_t *)&psxVuw[(i << 10) + j],
                    (((int32_t)psxVuw[(((((posY + difY) >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0)
                                       << 10) +
                                      (((posX + difX) >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0])
                     << 16) |
                        psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0) << 10) +
                               ((posX >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0]);

                posX += difX2;
                posY += difY2;
            }
            if (j == xmax)
                GetTextureTransColG(
                    &psxVuw[(i << 10) + j],
                    psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0) << 10) +
                           ((posX >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0]);
        }
        if (NextRow_FT4()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TD_TW_S(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                   int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                   int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                   int16_t ty4) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_FT4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_FT4()) return;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (right_u - posX) / num;
                difY = (right_v - posY) / num;
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
                    GetTextureTransColG32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j],
                        (((int32_t)
                              psxVuw[(((((posY + difY) >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0)
                                      << 10) +
                                     (((posX + difX) >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0])
                         << 16) |
                            psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY) << 10) + TWin.Position.y0 +
                                   ((posX >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0]);

                    posX += difX2;
                    posY += difY2;
                }
                if (j == xmax)
                    GetTextureTransColG_S(
                        &psxVuw[(i << 10) + j],
                        psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0) << 10) +
                               ((posX >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0]);
            }
            if (NextRow_FT4()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16);

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (right_u - posX) / num;
            difY = (right_v - posY) / num;
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
                GetTextureTransColG32_SPR(
                    (uint32_t *)&psxVuw[(i << 10) + j],
                    (((int32_t)psxVuw[(((((posY + difY) >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0)
                                       << 10) +
                                      (((posX + difX) >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0])
                     << 16) |
                        psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0) << 10) +
                               ((posX >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0]);

                posX += difX2;
                posY += difY2;
            }
            if (j == xmax)
                GetTextureTransColG_SPR(
                    &psxVuw[(i << 10) + j],
                    psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0) << 10) +
                           ((posX >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0]);
        }
        if (NextRow_FT4()) return;
    }
}

////////////////////////////////////////////////////////////////////////
// POLY 3/4 G-SHADED
////////////////////////////////////////////////////////////////////////

inline void PCSX::SoftGPU::SoftRenderer::drawPoly3Gi(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                     int16_t y3, int32_t rgb1, int32_t rgb2, int32_t rgb3) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t cR1, cG1, cB1;
    int32_t difR, difB, difG, difR2, difB2, difG2;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_G(x1, y1, x2, y2, x3, y3, rgb1, rgb2, rgb3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_G()) return;

    difR = delta_right_R;
    difG = delta_right_G;
    difB = delta_right_B;
    difR2 = difR << 1;
    difG2 = difG << 1;
    difB2 = difB << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans && iDither != 2) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16) - 1;
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                cR1 = left_R;
                cG1 = left_G;
                cB1 = left_B;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    cR1 += j * difR;
                    cG1 += j * difG;
                    cB1 += j * difB;
                }

                for (j = xmin; j < xmax; j += 2) {
                    *((uint32_t *)&psxVuw[(i << 10) + j]) =
                        ((((cR1 + difR) << 7) & 0x7c000000) | (((cG1 + difG) << 2) & 0x03e00000) |
                         (((cB1 + difB) >> 3) & 0x001f0000) | (((cR1) >> 9) & 0x7c00) | (((cG1) >> 14) & 0x03e0) |
                         (((cB1) >> 19) & 0x001f)) |
                        lSetMask;

                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax)
                    psxVuw[(i << 10) + j] =
                        (((cR1 >> 9) & 0x7c00) | ((cG1 >> 14) & 0x03e0) | ((cB1 >> 19) & 0x001f)) | sSetMask;
            }
            if (NextRow_G()) return;
        }
        return;
    }

#endif

    if (iDither == 2)
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16) - 1;
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                cR1 = left_R;
                cG1 = left_G;
                cB1 = left_B;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    cR1 += j * difR;
                    cG1 += j * difG;
                    cB1 += j * difB;
                }

                for (j = xmin; j <= xmax; j++) {
                    GetShadeTransCol_Dither(&psxVuw[(i << 10) + j], (cB1 >> 16), (cG1 >> 16), (cR1 >> 16));

                    cR1 += difR;
                    cG1 += difG;
                    cB1 += difB;
                }
            }
            if (NextRow_G()) return;
        }
    else
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16) - 1;
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                cR1 = left_R;
                cG1 = left_G;
                cB1 = left_B;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    cR1 += j * difR;
                    cG1 += j * difG;
                    cB1 += j * difB;
                }

                for (j = xmin; j <= xmax; j++) {
                    GetShadeTransCol(&psxVuw[(i << 10) + j],
                                     ((cR1 >> 9) & 0x7c00) | ((cG1 >> 14) & 0x03e0) | ((cB1 >> 19) & 0x001f));

                    cR1 += difR;
                    cG1 += difG;
                    cB1 += difB;
                }
            }
            if (NextRow_G()) return;
        }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3G(int32_t rgb1, int32_t rgb2, int32_t rgb3) {
    drawPoly3Gi(lx0, ly0, lx1, ly1, lx2, ly2, rgb1, rgb2, rgb3);
}

// draw two g-shaded tris for right psx shading emulation

void PCSX::SoftGPU::SoftRenderer::drawPoly4G(int32_t rgb1, int32_t rgb2, int32_t rgb3, int32_t rgb4) {
    drawPoly3Gi(lx1, ly1, lx3, ly3, lx2, ly2, rgb2, rgb4, rgb3);
    drawPoly3Gi(lx0, ly0, lx1, ly1, lx2, ly2, rgb1, rgb2, rgb3);
}

////////////////////////////////////////////////////////////////////////
// POLY 3/4 G-SHADED TEX PAL4
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

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_GT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3, col1, col2, col3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_GT()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);

    difR = delta_right_R;
    difG = delta_right_G;
    difB = delta_right_B;
    difR2 = difR << 1;
    difG2 = difG << 1;
    difB2 = difB << 1;

    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans && !iDither) {
        for (i = ymin; i <= ymax; i++) {
            xmin = ((left_x) >> 16);
            xmax = ((right_x) >> 16) - 1;  //!!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;
                cR1 = left_R;
                cG1 = left_G;
                cB1 = left_B;

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
                    XAdjust = (posX >> 16);
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    XAdjust = ((posX + difX) >> 16);
                    tC2 = psxVub[static_cast<int32_t>((((posY + difY) >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                    tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                    GetTextureTransColGX32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j], psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16,
                        (cB1 >> 16) | ((cB1 + difB) & 0xff0000), (cG1 >> 16) | ((cG1 + difG) & 0xff0000),
                        (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                    posX += difX2;
                    posY += difY2;
                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax) {
                    XAdjust = (posX >> 16);
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    GetTextureTransColGX_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                           (cR1 >> 16));
                }
            }
            if (NextRow_GT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;
            cR1 = left_R;
            cG1 = left_G;
            cB1 = left_B;

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
                XAdjust = (posX >> 16);
                tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                if (iDither)
                    GetTextureTransColGX_Dither(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                                (cR1 >> 16));
                else
                    GetTextureTransColGX(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                         (cR1 >> 16));
                posX += difX;
                posY += difY;
                cR1 += difR;
                cG1 += difG;
                cB1 += difB;
            }
        }
        if (NextRow_GT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TGEx4_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                    int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2,
                                                    int16_t tx3, int16_t ty3, int16_t clX, int16_t clY, int32_t col1,
                                                    int32_t col2, int32_t col3) {
    int i, j, xmin, xmax, ymin, ymax, n_xi, n_yi, TXV;
    int32_t cR1, cG1, cB1;
    int32_t difR, difB, difG, difR2, difB2, difG2;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP, XAdjust;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_GT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3, col1, col2, col3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_GT()) return;

    clutP = (clY << 10) + clX;

    YAdjust = (GlobalTextAddrY << 10) + GlobalTextAddrX;

    difR = delta_right_R;
    difG = delta_right_G;
    difB = delta_right_B;
    difR2 = difR << 1;
    difG2 = difG << 1;
    difB2 = difB << 1;

    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans && !iDither) {
        for (i = ymin; i <= ymax; i++) {
            xmin = ((left_x) >> 16);
            xmax = ((right_x) >> 16) - 1;  //!!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;
                cR1 = left_R;
                cG1 = left_G;
                cB1 = left_B;

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
                    XAdjust = (posX >> 16);

                    TXV = posY >> 16;
                    n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                    n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                    tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                    XAdjust = ((posX + difX) >> 16);

                    TXV = (posY + difY) >> 16;
                    n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                    n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                    tC2 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                    GetTextureTransColGX32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j], psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16,
                        (cB1 >> 16) | ((cB1 + difB) & 0xff0000), (cG1 >> 16) | ((cG1 + difG) & 0xff0000),
                        (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                    posX += difX2;
                    posY += difY2;
                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax) {
                    XAdjust = (posX >> 16);

                    TXV = posY >> 16;
                    n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                    n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                    tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                    GetTextureTransColGX_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                           (cR1 >> 16));
                }
            }
            if (NextRow_GT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;
            cR1 = left_R;
            cG1 = left_G;
            cB1 = left_B;

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
                XAdjust = (posX >> 16);

                TXV = posY >> 16;
                n_xi = ((XAdjust >> 2) & ~0x3c) + ((TXV << 2) & 0x3c);
                n_yi = (TXV & ~0xf) + ((XAdjust >> 4) & 0xf);

                tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((XAdjust & 0x03) << 2)) & 0x0f;

                if (iDither)
                    GetTextureTransColGX_Dither(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                                (cR1 >> 16));
                else
                    GetTextureTransColGX(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                         (cR1 >> 16));
                posX += difX;
                posY += difY;
                cR1 += difR;
                cG1 += difG;
                cB1 += difB;
            }
        }
        if (NextRow_GT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TGEx4_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                    int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2,
                                                    int16_t tx3, int16_t ty3, int16_t clX, int16_t clY, int32_t col1,
                                                    int32_t col2, int32_t col3) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t cR1, cG1, cB1;
    int32_t difR, difB, difG, difR2, difB2, difG2;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP, XAdjust;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_GT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3, col1, col2, col3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_GT()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);
    YAdjust += (TWin.Position.y0 << 11) + (TWin.Position.x0 >> 1);

    difR = delta_right_R;
    difG = delta_right_G;
    difB = delta_right_B;
    difR2 = difR << 1;
    difG2 = difG << 1;
    difB2 = difB << 1;

    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans && !iDither) {
        for (i = ymin; i <= ymax; i++) {
            xmin = ((left_x) >> 16);
            xmax = ((right_x) >> 16) - 1;  //!!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;
                cR1 = left_R;
                cG1 = left_G;
                cB1 = left_B;

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
                    XAdjust = (posX >> 16) % TWin.Position.x1;
                    tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    XAdjust = ((posX + difX) >> 16) % TWin.Position.x1;
                    tC2 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (XAdjust >> 1))];
                    tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;
                    GetTextureTransColGX32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j], psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16,
                        (cB1 >> 16) | ((cB1 + difB) & 0xff0000), (cG1 >> 16) | ((cG1 + difG) & 0xff0000),
                        (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                    posX += difX2;
                    posY += difY2;
                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax) {
                    XAdjust = (posX >> 16) % TWin.Position.x1;
                    tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    GetTextureTransColGX_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                           (cR1 >> 16));
                }
            }
            if (NextRow_GT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;
            cR1 = left_R;
            cG1 = left_G;
            cB1 = left_B;

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
                XAdjust = (posX >> 16) % TWin.Position.x1;
                tC1 =
                    psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                if (iDither)
                    GetTextureTransColGX_Dither(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                                (cR1 >> 16));
                else
                    GetTextureTransColGX(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                         (cR1 >> 16));
                posX += difX;
                posY += difY;
                cR1 += difR;
                cG1 += difG;
                cB1 += difB;
            }
        }
        if (NextRow_GT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

// note: the psx is doing g-shaded quads as two g-shaded tris,
// like the following func... sadly texturing is not 100%
// correct that way, so small texture distortions can
// happen...

void PCSX::SoftGPU::SoftRenderer::drawPoly4TGEx4_TRI_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                        int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                        int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                        int16_t ty4, int16_t clX, int16_t clY, int32_t col1,
                                                        int32_t col2, int32_t col3, int32_t col4) {
    drawPoly3TGEx4_IL(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4, clX, clY, col2, col4, col3);
    drawPoly3TGEx4_IL(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4, clX, clY, col1, col2, col3);
}

#ifdef POLYQUAD3GT

void PCSX::SoftGPU::SoftRenderer::drawPoly4TGEx4_TRI(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                     int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                     int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                     int16_t ty4, int16_t clX, int16_t clY, int32_t col1, int32_t col2,
                                                     int32_t col3, int32_t col4) {
    drawPoly3TGEx4(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4, clX, clY, col2, col4, col3);
    drawPoly3TGEx4(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4, clX, clY, col1, col2, col3);
}

#endif

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TGEx4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                 int16_t x4, int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2,
                                                 int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4,
                                                 int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col4,
                                                 int32_t col3) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t cR1, cG1, cB1;
    int32_t difR, difB, difG, difR2, difB2, difG2;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP, XAdjust;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_GT4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4, col1, col2, col3,
                           col4))
        return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_GT4()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans && !iDither) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (right_u - posX) / num;
                difY = (right_v - posY) / num;
                difX2 = difX << 1;
                difY2 = difY << 1;

                cR1 = left_R;
                cG1 = left_G;
                cB1 = left_B;
                difR = (right_R - cR1) / num;
                difG = (right_G - cG1) / num;
                difB = (right_B - cB1) / num;
                difR2 = difR << 1;
                difG2 = difG << 1;
                difB2 = difB << 1;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                    cR1 += j * difR;
                    cG1 += j * difG;
                    cB1 += j * difB;
                }
                xmax--;
                if (drawW < xmax) xmax = drawW;

                for (j = xmin; j < xmax; j += 2) {
                    XAdjust = (posX >> 16);
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                    XAdjust = ((posX + difX) >> 16);
                    tC2 = psxVub[static_cast<int32_t>((((posY + difY) >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                    tC2 = (tC2 >> ((XAdjust & 1) << 2)) & 0xf;

                    GetTextureTransColGX32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j], psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16,
                        (cB1 >> 16) | ((cB1 + difB) & 0xff0000), (cG1 >> 16) | ((cG1 + difG) & 0xff0000),
                        (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                    posX += difX2;
                    posY += difY2;
                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax) {
                    XAdjust = (posX >> 16);
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                    tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;

                    GetTextureTransColGX_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                           (cR1 >> 16));
                }
            }
            if (NextRow_GT4()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16);

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (right_u - posX) / num;
            difY = (right_v - posY) / num;
            difX2 = difX << 1;
            difY2 = difY << 1;

            cR1 = left_R;
            cG1 = left_G;
            cB1 = left_B;
            difR = (right_R - cR1) / num;
            difG = (right_G - cG1) / num;
            difB = (right_B - cB1) / num;
            difR2 = difR << 1;
            difG2 = difG << 1;
            difB2 = difB << 1;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
                cR1 += j * difR;
                cG1 += j * difG;
                cB1 += j * difB;
            }
            xmax--;
            if (drawW < xmax) xmax = drawW;

            for (j = xmin; j <= xmax; j++) {
                XAdjust = (posX >> 16);
                tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (XAdjust >> 1))];
                tC1 = (tC1 >> ((XAdjust & 1) << 2)) & 0xf;
                if (iDither)
                    GetTextureTransColGX_Dither(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                                (cR1 >> 16));
                else
                    GetTextureTransColGX(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                         (cR1 >> 16));
                posX += difX;
                posY += difY;
                cR1 += difR;
                cG1 += difG;
                cB1 += difB;
            }
        }
        if (NextRow_GT4()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TGEx4_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                    int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                    int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                    int16_t ty4, int16_t clX, int16_t clY, int32_t col1, int32_t col2,
                                                    int32_t col3, int32_t col4) {
    drawPoly3TGEx4_TW(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4, clX, clY, col2, col4, col3);

    drawPoly3TGEx4_TW(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4, clX, clY, col1, col2, col3);
}

////////////////////////////////////////////////////////////////////////
// POLY 3/4 G-SHADED TEX PAL8
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

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_GT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3, col1, col2, col3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_GT()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);

    difR = delta_right_R;
    difG = delta_right_G;
    difB = delta_right_B;
    difR2 = difR << 1;
    difG2 = difG << 1;
    difB2 = difB << 1;
    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans && !iDither) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16) - 1;  // !!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;
                cR1 = left_R;
                cG1 = left_G;
                cB1 = left_B;

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
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + ((posX >> 16)))];
                    tC2 = psxVub[static_cast<int32_t>((((posY + difY) >> 5) & 0xFFFFF800) + YAdjust +
                                                      (((posX + difX) >> 16)))];
                    GetTextureTransColGX32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j], psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16,
                        (cB1 >> 16) | ((cB1 + difB) & 0xff0000), (cG1 >> 16) | ((cG1 + difG) & 0xff0000),
                        (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                    posX += difX2;
                    posY += difY2;
                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax) {
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + ((posX >> 16)))];
                    GetTextureTransColGX_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                           (cR1 >> 16));
                }
            }
            if (NextRow_GT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;
            cR1 = left_R;
            cG1 = left_G;
            cB1 = left_B;

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
                tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + ((posX >> 16)))];
                if (iDither)
                    GetTextureTransColGX_Dither(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                                (cR1 >> 16));
                else
                    GetTextureTransColGX(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                         (cR1 >> 16));
                posX += difX;
                posY += difY;
                cR1 += difR;
                cG1 += difG;
                cB1 += difB;
            }
        }
        if (NextRow_GT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TGEx8_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                    int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2,
                                                    int16_t tx3, int16_t ty3, int16_t clX, int16_t clY, int32_t col1,
                                                    int32_t col2, int32_t col3) {
    int i, j, xmin, xmax, ymin, ymax, n_xi, n_yi, TXV, TXU;
    int32_t cR1, cG1, cB1;
    int32_t difR, difB, difG, difR2, difB2, difG2;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_GT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3, col1, col2, col3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_GT()) return;

    clutP = (clY << 10) + clX;

    YAdjust = (GlobalTextAddrY << 10) + GlobalTextAddrX;

    difR = delta_right_R;
    difG = delta_right_G;
    difB = delta_right_B;
    difR2 = difR << 1;
    difG2 = difG << 1;
    difB2 = difB << 1;
    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans && !iDither) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16) - 1;  // !!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;
                cR1 = left_R;
                cG1 = left_G;
                cB1 = left_B;

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
                    TXU = posX >> 16;
                    TXV = posY >> 16;
                    n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                    n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);

                    tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;

                    TXU = (posX + difX) >> 16;
                    TXV = (posY + difY) >> 16;
                    n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                    n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);

                    tC2 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;

                    GetTextureTransColGX32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j], psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16,
                        (cB1 >> 16) | ((cB1 + difB) & 0xff0000), (cG1 >> 16) | ((cG1 + difG) & 0xff0000),
                        (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                    posX += difX2;
                    posY += difY2;
                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax) {
                    TXU = posX >> 16;
                    TXV = posY >> 16;
                    n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                    n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);

                    tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;

                    GetTextureTransColGX_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                           (cR1 >> 16));
                }
            }
            if (NextRow_GT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;
            cR1 = left_R;
            cG1 = left_G;
            cB1 = left_B;

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
                TXU = posX >> 16;
                TXV = posY >> 16;
                n_xi = ((TXU >> 1) & ~0x78) + ((TXU << 2) & 0x40) + ((TXV << 3) & 0x38);
                n_yi = (TXV & ~0x7) + ((TXU >> 5) & 0x7);

                tC1 = (psxVuw[(n_yi << 10) + YAdjust + n_xi] >> ((TXU & 0x01) << 3)) & 0xff;

                if (iDither)
                    GetTextureTransColGX_Dither(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                                (cR1 >> 16));
                else
                    GetTextureTransColGX(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                         (cR1 >> 16));
                posX += difX;
                posY += difY;
                cR1 += difR;
                cG1 += difG;
                cB1 += difB;
            }
        }
        if (NextRow_GT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TGEx8_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                    int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2,
                                                    int16_t tx3, int16_t ty3, int16_t clX, int16_t clY, int32_t col1,
                                                    int32_t col2, int32_t col3) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t cR1, cG1, cB1;
    int32_t difR, difB, difG, difR2, difB2, difG2;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_GT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3, col1, col2, col3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_GT()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);
    YAdjust += (TWin.Position.y0 << 11) + (TWin.Position.x0);

    difR = delta_right_R;
    difG = delta_right_G;
    difB = delta_right_B;
    difR2 = difR << 1;
    difG2 = difG << 1;
    difB2 = difB << 1;
    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans && !iDither) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16) - 1;  // !!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;
                cR1 = left_R;
                cG1 = left_G;
                cB1 = left_B;

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
                    tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      ((posX >> 16) % TWin.Position.x1))];
                    tC2 = psxVub[static_cast<int32_t>(((((posY + difY) >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      (((posX + difX) >> 16) % TWin.Position.x1))];

                    GetTextureTransColGX32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j], psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16,
                        (cB1 >> 16) | ((cB1 + difB) & 0xff0000), (cG1 >> 16) | ((cG1 + difG) & 0xff0000),
                        (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                    posX += difX2;
                    posY += difY2;
                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax) {
                    tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                      ((posX >> 16) % TWin.Position.x1))];
                    GetTextureTransColGX_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                           (cR1 >> 16));
                }
            }
            if (NextRow_GT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;
            cR1 = left_R;
            cG1 = left_G;
            cB1 = left_B;

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
                tC1 = psxVub[static_cast<int32_t>((((posY >> 16) % TWin.Position.y1) << 11) + YAdjust +
                                                  ((posX >> 16) % TWin.Position.x1))];
                if (iDither)
                    GetTextureTransColGX_Dither(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                                (cR1 >> 16));
                else
                    GetTextureTransColGX(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                         (cR1 >> 16));
                posX += difX;
                posY += difY;
                cR1 += difR;
                cG1 += difG;
                cB1 += difB;
            }
        }
        if (NextRow_GT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

// note: two g-shaded tris: small texture distortions can happen

void PCSX::SoftGPU::SoftRenderer::drawPoly4TGEx8_TRI_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                        int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                        int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                        int16_t ty4, int16_t clX, int16_t clY, int32_t col1,
                                                        int32_t col2, int32_t col3, int32_t col4) {
    drawPoly3TGEx8_IL(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4, clX, clY, col2, col4, col3);
    drawPoly3TGEx8_IL(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4, clX, clY, col1, col2, col3);
}

#ifdef POLYQUAD3GT

void PCSX::SoftGPU::SoftRenderer::drawPoly4TGEx8_TRI(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                     int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                     int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                     int16_t ty4, int16_t clX, int16_t clY, int32_t col1, int32_t col2,
                                                     int32_t col3, int32_t col4) {
    drawPoly3TGEx8(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4, clX, clY, col2, col4, col3);
    drawPoly3TGEx8(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4, clX, clY, col1, col2, col3);
}

#endif

void PCSX::SoftGPU::SoftRenderer::drawPoly4TGEx8(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                                 int16_t x4, int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2,
                                                 int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4,
                                                 int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col4,
                                                 int32_t col3) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t cR1, cG1, cB1;
    int32_t difR, difB, difG, difR2, difB2, difG2;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY, YAdjust, clutP;
    int16_t tC1, tC2;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_GT4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4, col1, col2, col3,
                           col4))
        return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_GT4()) return;

    clutP = (clY << 10) + clX;

    YAdjust = ((GlobalTextAddrY) << 11) + (GlobalTextAddrX << 1);

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans && !iDither) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (right_u - posX) / num;
                difY = (right_v - posY) / num;
                difX2 = difX << 1;
                difY2 = difY << 1;

                cR1 = left_R;
                cG1 = left_G;
                cB1 = left_B;
                difR = (right_R - cR1) / num;
                difG = (right_G - cG1) / num;
                difB = (right_B - cB1) / num;
                difR2 = difR << 1;
                difG2 = difG << 1;
                difB2 = difB << 1;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                    cR1 += j * difR;
                    cG1 += j * difG;
                    cB1 += j * difB;
                }
                xmax--;
                if (drawW < xmax) xmax = drawW;

                for (j = xmin; j < xmax; j += 2) {
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (posX >> 16))];
                    tC2 = psxVub[static_cast<int32_t>((((posY + difY) >> 5) & 0xFFFFF800) + YAdjust +
                                                      ((posX + difX) >> 16))];

                    GetTextureTransColGX32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j], psxVuw[clutP + tC1] | ((int32_t)psxVuw[clutP + tC2]) << 16,
                        (cB1 >> 16) | ((cB1 + difB) & 0xff0000), (cG1 >> 16) | ((cG1 + difG) & 0xff0000),
                        (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                    posX += difX2;
                    posY += difY2;
                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax) {
                    tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (posX >> 16))];
                    GetTextureTransColGX_S(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                           (cR1 >> 16));
                }
            }
            if (NextRow_GT4()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16);

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (right_u - posX) / num;
            difY = (right_v - posY) / num;
            difX2 = difX << 1;
            difY2 = difY << 1;

            cR1 = left_R;
            cG1 = left_G;
            cB1 = left_B;
            difR = (right_R - cR1) / num;
            difG = (right_G - cG1) / num;
            difB = (right_B - cB1) / num;
            difR2 = difR << 1;
            difG2 = difG << 1;
            difB2 = difB << 1;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
                cR1 += j * difR;
                cG1 += j * difG;
                cB1 += j * difB;
            }
            xmax--;
            if (drawW < xmax) xmax = drawW;

            for (j = xmin; j <= xmax; j++) {
                tC1 = psxVub[static_cast<int32_t>(((posY >> 5) & 0xFFFFF800) + YAdjust + (posX >> 16))];
                if (iDither)
                    GetTextureTransColGX_Dither(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                                (cR1 >> 16));
                else
                    GetTextureTransColGX(&psxVuw[(i << 10) + j], psxVuw[clutP + tC1], (cB1 >> 16), (cG1 >> 16),
                                         (cR1 >> 16));
                posX += difX;
                posY += difY;
                cR1 += difR;
                cG1 += difG;
                cB1 += difB;
            }
        }
        if (NextRow_GT4()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TGEx8_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                    int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                    int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                    int16_t ty4, int16_t clX, int16_t clY, int32_t col1, int32_t col2,
                                                    int32_t col3, int32_t col4) {
    drawPoly3TGEx8_TW(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4, clX, clY, col2, col4, col3);
    drawPoly3TGEx8_TW(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4, clX, clY, col1, col2, col3);
}

////////////////////////////////////////////////////////////////////////
// POLY 3 G-SHADED TEX 15 BIT
////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TGD(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                               int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                               int16_t ty3, int32_t col1, int32_t col2, int32_t col3) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t cR1, cG1, cB1;
    int32_t difR, difB, difG, difR2, difB2, difG2;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_GT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3, col1, col2, col3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_GT()) return;

    difR = delta_right_R;
    difG = delta_right_G;
    difB = delta_right_B;
    difR2 = difR << 1;
    difG2 = difG << 1;
    difB2 = difB << 1;
    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans && !iDither) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;
                cR1 = left_R;
                cG1 = left_G;
                cB1 = left_B;

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
                    GetTextureTransColGX32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j],
                        (((int32_t)psxVuw[((((posY + difY) >> 16) + GlobalTextAddrY) << 10) + ((posX + difX) >> 16) +
                                          GlobalTextAddrX])
                         << 16) |
                            psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + ((posX) >> 16) + GlobalTextAddrX],
                        (cB1 >> 16) | ((cB1 + difB) & 0xff0000), (cG1 >> 16) | ((cG1 + difG) & 0xff0000),
                        (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                    posX += difX2;
                    posY += difY2;
                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax)
                    GetTextureTransColGX_S(
                        &psxVuw[(i << 10) + j],
                        psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + (posX >> 16) + GlobalTextAddrX], (cB1 >> 16),
                        (cG1 >> 16), (cR1 >> 16));
            }
            if (NextRow_GT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;
            cR1 = left_R;
            cG1 = left_G;
            cB1 = left_B;

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
                if (iDither)
                    GetTextureTransColGX_Dither(
                        &psxVuw[(i << 10) + j],
                        psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + (posX >> 16) + GlobalTextAddrX], (cB1 >> 16),
                        (cG1 >> 16), (cR1 >> 16));
                else
                    GetTextureTransColGX(
                        &psxVuw[(i << 10) + j],
                        psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + (posX >> 16) + GlobalTextAddrX], (cB1 >> 16),
                        (cG1 >> 16), (cR1 >> 16));
                posX += difX;
                posY += difY;
                cR1 += difR;
                cG1 += difG;
                cB1 += difB;
            }
        }
        if (NextRow_GT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3TGD_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                  int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2,
                                                  int16_t tx3, int16_t ty3, int32_t col1, int32_t col2, int32_t col3) {
    int i, j, xmin, xmax, ymin, ymax;
    int32_t cR1, cG1, cB1;
    int32_t difR, difB, difG, difR2, difB2, difG2;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY;

    if (x1 > drawW && x2 > drawW && x3 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_GT(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3, col1, col2, col3)) return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_GT()) return;

    difR = delta_right_R;
    difG = delta_right_G;
    difB = delta_right_B;
    difR2 = difR << 1;
    difG2 = difG << 1;
    difB2 = difB << 1;
    difX = delta_right_u;
    difX2 = difX << 1;
    difY = delta_right_v;
    difY2 = difY << 1;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans && !iDither) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!!!!!
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;
                cR1 = left_R;
                cG1 = left_G;
                cB1 = left_B;

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
                    GetTextureTransColGX32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j],
                        (((int32_t)
                              psxVuw[(((((posY + difY) >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0)
                                      << 10) +
                                     (((posX + difX) >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0])
                         << 16) |
                            psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0) << 10) +
                                   (((posX) >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0],
                        (cB1 >> 16) | ((cB1 + difB) & 0xff0000), (cG1 >> 16) | ((cG1 + difG) & 0xff0000),
                        (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                    posX += difX2;
                    posY += difY2;
                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax)
                    GetTextureTransColGX_S(
                        &psxVuw[(i << 10) + j],
                        psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0) << 10) +
                               ((posX >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0],
                        (cB1 >> 16), (cG1 >> 16), (cR1 >> 16));
            }
            if (NextRow_GT()) {
                return;
            }
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16) - 1;  //!!!!!!!!!!!!!!!!!!
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;
            cR1 = left_R;
            cG1 = left_G;
            cB1 = left_B;

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
                if (iDither)
                    GetTextureTransColGX_Dither(
                        &psxVuw[(i << 10) + j],
                        psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0) << 10) +
                               ((posX >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0],
                        (cB1 >> 16), (cG1 >> 16), (cR1 >> 16));
                else
                    GetTextureTransColGX(
                        &psxVuw[(i << 10) + j],
                        psxVuw[((((posY >> 16) % TWin.Position.y1) + GlobalTextAddrY + TWin.Position.y0) << 10) +
                               ((posX >> 16) % TWin.Position.x1) + GlobalTextAddrX + TWin.Position.x0],
                        (cB1 >> 16), (cG1 >> 16), (cR1 >> 16));
                posX += difX;
                posY += difY;
                cR1 += difR;
                cG1 += difG;
                cB1 += difB;
            }
        }
        if (NextRow_GT()) {
            return;
        }
    }
}

////////////////////////////////////////////////////////////////////////

// note: two g-shaded tris: small texture distortions can happen

#ifdef POLYQUAD3GT

void PCSX::SoftGPU::SoftRenderer::drawPoly4TGD_TRI(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                   int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                   int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                   int16_t ty4, int32_t col1, int32_t col2, int32_t col3,
                                                   int32_t col4) {
    drawPoly3TGD(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4, col2, col4, col3);
    drawPoly3TGD(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4, col1, col2, col3);
}

#endif

void PCSX::SoftGPU::SoftRenderer::drawPoly4TGD(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                               int16_t x4, int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2,
                                               int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4,
                                               int32_t col1, int32_t col2, int32_t col4, int32_t col3) {
    int32_t num;
    int32_t i, j, xmin, xmax, ymin, ymax;
    int32_t cR1, cG1, cB1;
    int32_t difR, difB, difG, difR2, difB2, difG2;
    int32_t difX, difY, difX2, difY2;
    int32_t posX, posY;

    if (x1 > drawW && x2 > drawW && x3 > drawW && x4 > drawW) return;
    if (y1 > drawH && y2 > drawH && y3 > drawH && y4 > drawH) return;
    if (x1 < drawX && x2 < drawX && x3 < drawX && x4 < drawX) return;
    if (y1 < drawY && y2 < drawY && y3 < drawY && y4 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    if (!SetupSections_GT4(x1, y1, x2, y2, x3, y3, x4, y4, tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4, col1, col2, col3,
                           col4))
        return;

    ymax = Ymax;

    for (ymin = Ymin; ymin < drawY; ymin++)
        if (NextRow_GT4()) return;

#ifdef FASTSOLID

    if (!bCheckMask && !DrawSemiTrans && !iDither) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (left_x >> 16);
            xmax = (right_x >> 16);

            if (xmax >= xmin) {
                posX = left_u;
                posY = left_v;

                num = (xmax - xmin);
                if (num == 0) num = 1;
                difX = (right_u - posX) / num;
                difY = (right_v - posY) / num;
                difX2 = difX << 1;
                difY2 = difY << 1;

                cR1 = left_R;
                cG1 = left_G;
                cB1 = left_B;
                difR = (right_R - cR1) / num;
                difG = (right_G - cG1) / num;
                difB = (right_B - cB1) / num;
                difR2 = difR << 1;
                difG2 = difG << 1;
                difB2 = difB << 1;

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    posX += j * difX;
                    posY += j * difY;
                    cR1 += j * difR;
                    cG1 += j * difG;
                    cB1 += j * difB;
                }
                xmax--;
                if (drawW < xmax) xmax = drawW;

                for (j = xmin; j < xmax; j += 2) {
                    GetTextureTransColGX32_S(
                        (uint32_t *)&psxVuw[(i << 10) + j],
                        (((int32_t)psxVuw[((((posY + difY) >> 16) + GlobalTextAddrY) << 10) + ((posX + difX) >> 16) +
                                          GlobalTextAddrX])
                         << 16) |
                            psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + ((posX) >> 16) + GlobalTextAddrX],
                        (cB1 >> 16) | ((cB1 + difB) & 0xff0000), (cG1 >> 16) | ((cG1 + difG) & 0xff0000),
                        (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                    posX += difX2;
                    posY += difY2;
                    cR1 += difR2;
                    cG1 += difG2;
                    cB1 += difB2;
                }
                if (j == xmax)
                    GetTextureTransColGX_S(
                        &psxVuw[(i << 10) + j],
                        psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + (posX >> 16) + GlobalTextAddrX], (cB1 >> 16),
                        (cG1 >> 16), (cR1 >> 16));
            }
            if (NextRow_GT4()) return;
        }
        return;
    }

#endif

    for (i = ymin; i <= ymax; i++) {
        xmin = (left_x >> 16);
        xmax = (right_x >> 16);

        if (xmax >= xmin) {
            posX = left_u;
            posY = left_v;

            num = (xmax - xmin);
            if (num == 0) num = 1;
            difX = (right_u - posX) / num;
            difY = (right_v - posY) / num;
            difX2 = difX << 1;
            difY2 = difY << 1;

            cR1 = left_R;
            cG1 = left_G;
            cB1 = left_B;
            difR = (right_R - cR1) / num;
            difG = (right_G - cG1) / num;
            difB = (right_B - cB1) / num;
            difR2 = difR << 1;
            difG2 = difG << 1;
            difB2 = difB << 1;

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                posX += j * difX;
                posY += j * difY;
                cR1 += j * difR;
                cG1 += j * difG;
                cB1 += j * difB;
            }
            xmax--;
            if (drawW < xmax) xmax = drawW;

            for (j = xmin; j <= xmax; j++) {
                if (iDither)
                    GetTextureTransColGX(
                        &psxVuw[(i << 10) + j],
                        psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + (posX >> 16) + GlobalTextAddrX], (cB1 >> 16),
                        (cG1 >> 16), (cR1 >> 16));
                else
                    GetTextureTransColGX(
                        &psxVuw[(i << 10) + j],
                        psxVuw[(((posY >> 16) + GlobalTextAddrY) << 10) + (posX >> 16) + GlobalTextAddrX], (cB1 >> 16),
                        (cG1 >> 16), (cR1 >> 16));
                posX += difX;
                posY += difY;
                cR1 += difR;
                cG1 += difG;
                cB1 += difB;
            }
        }
        if (NextRow_GT4()) return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4TGD_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                  int16_t y3, int16_t x4, int16_t y4, int16_t tx1, int16_t ty1,
                                                  int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                                                  int16_t ty4, int32_t col1, int32_t col2, int32_t col3, int32_t col4) {
    drawPoly3TGD_TW(x2, y2, x3, y3, x4, y4, tx2, ty2, tx3, ty3, tx4, ty4, col2, col4, col3);
    drawPoly3TGD_TW(x1, y1, x2, y2, x4, y4, tx1, ty1, tx2, ty2, tx4, ty4, col1, col2, col3);
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

/*
// no real rect test, but it does its job the way I need it
static inline bool IsNoRect(void)
{
 if(lx0==lx1 && lx2==lx3) return false;
 if(lx0==lx2 && lx1==lx3) return false;
 if(lx0==lx3 && lx1==lx2) return false;
 return true;
}
*/

// real rect test
inline bool PCSX::SoftGPU::SoftRenderer::IsNoRect() {
    if (!(dwActFixes & 0x200)) return false;

    if (ly0 == ly1) {
        if (lx1 == lx3 && ly3 == ly2 && lx2 == lx0) return false;
        if (lx1 == lx2 && ly2 == ly3 && lx3 == lx0) return false;
        return true;
    }

    if (ly0 == ly2) {
        if (lx2 == lx3 && ly3 == ly1 && lx1 == lx0) return false;
        if (lx2 == lx1 && ly1 == ly3 && lx3 == lx0) return false;
        return true;
    }

    if (ly0 == ly3) {
        if (lx3 == lx2 && ly2 == ly1 && lx1 == lx0) return false;
        if (lx3 == lx1 && ly1 == ly2 && lx2 == lx0) return false;
        return true;
    }
    return true;
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3FT(unsigned char *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);

    if (GlobalTextIL && GlobalTextTP < 2) {
        if (GlobalTextTP == 0)
            drawPoly3TEx4_IL(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                             (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff),
                             ((gpuData[6] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                             ((gpuData[2] >> 22) & iGPUHeightMask));
        else
            drawPoly3TEx8_IL(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                             (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff),
                             ((gpuData[6] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                             ((gpuData[2] >> 22) & iGPUHeightMask));
        return;
    }

    if (!bUsingTWin && !(dwActFixes & 0x100)) {
        switch (GlobalTextTP)  // depending on texture mode
        {
            case 0:
                drawPoly3TEx4(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                              (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff),
                              ((gpuData[6] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                              ((gpuData[2] >> 22) & iGPUHeightMask));
                return;
            case 1:
                drawPoly3TEx8(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                              (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff),
                              ((gpuData[6] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                              ((gpuData[2] >> 22) & iGPUHeightMask));
                return;
            case 2:
                drawPoly3TD(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                            (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff),
                            ((gpuData[6] >> 8) & 0x000000ff));
                return;
        }
        return;
    }

    switch (GlobalTextTP)  // depending on texture mode
    {
        case 0:
            drawPoly3TEx4_TW(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                             (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff),
                             ((gpuData[6] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                             ((gpuData[2] >> 22) & iGPUHeightMask));
            return;
        case 1:
            drawPoly3TEx8_TW(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                             (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff),
                             ((gpuData[6] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                             ((gpuData[2] >> 22) & iGPUHeightMask));
            return;
        case 2:
            drawPoly3TD_TW(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                           (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff),
                           ((gpuData[6] >> 8) & 0x000000ff));
            return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4FT(unsigned char *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);

    if (GlobalTextIL && GlobalTextTP < 2) {
        if (GlobalTextTP == 0)
            drawPoly4TEx4_IL(
                lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                ((gpuData[8] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff), ((gpuData[6] >> 8) & 0x000000ff),
                ((gpuData[2] >> 12) & 0x3f0), ((gpuData[2] >> 22) & iGPUHeightMask));
        else
            drawPoly4TEx8_IL(
                lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                ((gpuData[8] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff), ((gpuData[6] >> 8) & 0x000000ff),
                ((gpuData[2] >> 12) & 0x3f0), ((gpuData[2] >> 22) & iGPUHeightMask));
        return;
    }

    if (!bUsingTWin) {
#ifdef POLYQUAD3GT
        if (IsNoRect()) {
            switch (GlobalTextTP) {
                case 0:
                    drawPoly4TEx4_TRI(lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff),
                                      ((gpuData[2] >> 8) & 0x000000ff), (gpuData[4] & 0x000000ff),
                                      ((gpuData[4] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                                      ((gpuData[8] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff),
                                      ((gpuData[6] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                                      ((gpuData[2] >> 22) & iGPUHeightMask));
                    return;
                case 1:
                    drawPoly4TEx8_TRI(lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff),
                                      ((gpuData[2] >> 8) & 0x000000ff), (gpuData[4] & 0x000000ff),
                                      ((gpuData[4] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                                      ((gpuData[8] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff),
                                      ((gpuData[6] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                                      ((gpuData[2] >> 22) & iGPUHeightMask));
                    return;
                case 2:
                    drawPoly4TD_TRI(lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff),
                                    ((gpuData[2] >> 8) & 0x000000ff), (gpuData[4] & 0x000000ff),
                                    ((gpuData[4] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                                    ((gpuData[8] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff),
                                    ((gpuData[6] >> 8) & 0x000000ff));
                    return;
            }
            return;
        }
#endif

        switch (GlobalTextTP) {
            case 0:  // grandia investigations needed
                drawPoly4TEx4(
                    lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                    (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                    ((gpuData[8] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff), ((gpuData[6] >> 8) & 0x000000ff),
                    ((gpuData[2] >> 12) & 0x3f0), ((gpuData[2] >> 22) & iGPUHeightMask));
                return;
            case 1:
                drawPoly4TEx8(
                    lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                    (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                    ((gpuData[8] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff), ((gpuData[6] >> 8) & 0x000000ff),
                    ((gpuData[2] >> 12) & 0x3f0), ((gpuData[2] >> 22) & iGPUHeightMask));
                return;
            case 2:
                drawPoly4TD(
                    lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                    (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                    ((gpuData[8] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff), ((gpuData[6] >> 8) & 0x000000ff));
                return;
        }
        return;
    }

    switch (GlobalTextTP) {
        case 0:
            drawPoly4TEx4_TW(
                lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                ((gpuData[8] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff), ((gpuData[6] >> 8) & 0x000000ff),
                ((gpuData[2] >> 12) & 0x3f0), ((gpuData[2] >> 22) & iGPUHeightMask));
            return;
        case 1:
            drawPoly4TEx8_TW(
                lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                ((gpuData[8] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff), ((gpuData[6] >> 8) & 0x000000ff),
                ((gpuData[2] >> 12) & 0x3f0), ((gpuData[2] >> 22) & iGPUHeightMask));
            return;
        case 2:
            drawPoly4TD_TW(
                lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                (gpuData[4] & 0x000000ff), ((gpuData[4] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                ((gpuData[8] >> 8) & 0x000000ff), (gpuData[6] & 0x000000ff), ((gpuData[6] >> 8) & 0x000000ff));
            return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly3GT(unsigned char *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);

    if (GlobalTextIL && GlobalTextTP < 2) {
        if (GlobalTextTP == 0)
            drawPoly3TGEx4_IL(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                              (gpuData[5] & 0x000000ff), ((gpuData[5] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                              ((gpuData[8] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                              ((gpuData[2] >> 22) & iGPUHeightMask), gpuData[0], gpuData[3], gpuData[6]);
        else
            drawPoly3TGEx8_IL(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                              (gpuData[5] & 0x000000ff), ((gpuData[5] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                              ((gpuData[8] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                              ((gpuData[2] >> 22) & iGPUHeightMask), gpuData[0], gpuData[3], gpuData[6]);
        return;
    }

    if (!bUsingTWin) {
        switch (GlobalTextTP) {
            case 0:
                drawPoly3TGEx4(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff),
                               ((gpuData[2] >> 8) & 0x000000ff), (gpuData[5] & 0x000000ff),
                               ((gpuData[5] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                               ((gpuData[8] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                               ((gpuData[2] >> 22) & iGPUHeightMask), gpuData[0], gpuData[3], gpuData[6]);
                return;
            case 1:
                drawPoly3TGEx8(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff),
                               ((gpuData[2] >> 8) & 0x000000ff), (gpuData[5] & 0x000000ff),
                               ((gpuData[5] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                               ((gpuData[8] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                               ((gpuData[2] >> 22) & iGPUHeightMask), gpuData[0], gpuData[3], gpuData[6]);
                return;
            case 2:
                drawPoly3TGD(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                             (gpuData[5] & 0x000000ff), ((gpuData[5] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                             ((gpuData[8] >> 8) & 0x000000ff), gpuData[0], gpuData[3], gpuData[6]);
                return;
        }
        return;
    }

    switch (GlobalTextTP) {
        case 0:
            drawPoly3TGEx4_TW(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                              (gpuData[5] & 0x000000ff), ((gpuData[5] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                              ((gpuData[8] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                              ((gpuData[2] >> 22) & iGPUHeightMask), gpuData[0], gpuData[3], gpuData[6]);
            return;
        case 1:
            drawPoly3TGEx8_TW(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                              (gpuData[5] & 0x000000ff), ((gpuData[5] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                              ((gpuData[8] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                              ((gpuData[2] >> 22) & iGPUHeightMask), gpuData[0], gpuData[3], gpuData[6]);
            return;
        case 2:
            drawPoly3TGD_TW(lx0, ly0, lx1, ly1, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                            (gpuData[5] & 0x000000ff), ((gpuData[5] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                            ((gpuData[8] >> 8) & 0x000000ff), gpuData[0], gpuData[3], gpuData[6]);
            return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::drawPoly4GT(unsigned char *baseAddr) {
    uint32_t *gpuData = ((uint32_t *)baseAddr);

    if (GlobalTextIL && GlobalTextTP < 2) {
        if (GlobalTextTP == 0)
            drawPoly4TGEx4_TRI_IL(
                lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                (gpuData[5] & 0x000000ff), ((gpuData[5] >> 8) & 0x000000ff), (gpuData[11] & 0x000000ff),
                ((gpuData[11] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff), ((gpuData[8] >> 8) & 0x000000ff),
                ((gpuData[2] >> 12) & 0x3f0), ((gpuData[2] >> 22) & iGPUHeightMask), gpuData[0], gpuData[3], gpuData[6],
                gpuData[9]);
        else
            drawPoly4TGEx8_TRI_IL(
                lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff), ((gpuData[2] >> 8) & 0x000000ff),
                (gpuData[5] & 0x000000ff), ((gpuData[5] >> 8) & 0x000000ff), (gpuData[11] & 0x000000ff),
                ((gpuData[11] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff), ((gpuData[8] >> 8) & 0x000000ff),
                ((gpuData[2] >> 12) & 0x3f0), ((gpuData[2] >> 22) & iGPUHeightMask), gpuData[0], gpuData[3], gpuData[6],
                gpuData[9]);
        return;
    }

    if (!bUsingTWin) {
#ifdef POLYQUAD3GT
        if (IsNoRect()) {
            switch (GlobalTextTP) {
                case 0:
                    drawPoly4TGEx4_TRI(
                        lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff),
                        ((gpuData[2] >> 8) & 0x000000ff), (gpuData[5] & 0x000000ff), ((gpuData[5] >> 8) & 0x000000ff),
                        (gpuData[11] & 0x000000ff), ((gpuData[11] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                        ((gpuData[8] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                        ((gpuData[2] >> 22) & iGPUHeightMask), gpuData[0], gpuData[3], gpuData[6], gpuData[9]);

                    return;
                case 1:
                    drawPoly4TGEx8_TRI(
                        lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff),
                        ((gpuData[2] >> 8) & 0x000000ff), (gpuData[5] & 0x000000ff), ((gpuData[5] >> 8) & 0x000000ff),
                        (gpuData[11] & 0x000000ff), ((gpuData[11] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                        ((gpuData[8] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                        ((gpuData[2] >> 22) & iGPUHeightMask), gpuData[0], gpuData[3], gpuData[6], gpuData[9]);
                    return;
                case 2:
                    drawPoly4TGD_TRI(lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff),
                                     ((gpuData[2] >> 8) & 0x000000ff), (gpuData[5] & 0x000000ff),
                                     ((gpuData[5] >> 8) & 0x000000ff), (gpuData[11] & 0x000000ff),
                                     ((gpuData[11] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                                     ((gpuData[8] >> 8) & 0x000000ff), gpuData[0], gpuData[3], gpuData[6], gpuData[9]);
                    return;
            }
            return;
        }
#endif

        switch (GlobalTextTP) {
            case 0:
                drawPoly4TGEx4(lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff),
                               ((gpuData[2] >> 8) & 0x000000ff), (gpuData[5] & 0x000000ff),
                               ((gpuData[5] >> 8) & 0x000000ff), (gpuData[11] & 0x000000ff),
                               ((gpuData[11] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                               ((gpuData[8] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                               ((gpuData[2] >> 22) & iGPUHeightMask), gpuData[0], gpuData[3], gpuData[6], gpuData[9]);

                return;
            case 1:
                drawPoly4TGEx8(lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff),
                               ((gpuData[2] >> 8) & 0x000000ff), (gpuData[5] & 0x000000ff),
                               ((gpuData[5] >> 8) & 0x000000ff), (gpuData[11] & 0x000000ff),
                               ((gpuData[11] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                               ((gpuData[8] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                               ((gpuData[2] >> 22) & iGPUHeightMask), gpuData[0], gpuData[3], gpuData[6], gpuData[9]);
                return;
            case 2:
                drawPoly4TGD(lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff),
                             ((gpuData[2] >> 8) & 0x000000ff), (gpuData[5] & 0x000000ff),
                             ((gpuData[5] >> 8) & 0x000000ff), (gpuData[11] & 0x000000ff),
                             ((gpuData[11] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                             ((gpuData[8] >> 8) & 0x000000ff), gpuData[0], gpuData[3], gpuData[6], gpuData[9]);
                return;
        }
        return;
    }

    switch (GlobalTextTP) {
        case 0:
            drawPoly4TGEx4_TW(lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff),
                              ((gpuData[2] >> 8) & 0x000000ff), (gpuData[5] & 0x000000ff),
                              ((gpuData[5] >> 8) & 0x000000ff), (gpuData[11] & 0x000000ff),
                              ((gpuData[11] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                              ((gpuData[8] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                              ((gpuData[2] >> 22) & iGPUHeightMask), gpuData[0], gpuData[3], gpuData[6], gpuData[9]);
            return;
        case 1:
            drawPoly4TGEx8_TW(lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff),
                              ((gpuData[2] >> 8) & 0x000000ff), (gpuData[5] & 0x000000ff),
                              ((gpuData[5] >> 8) & 0x000000ff), (gpuData[11] & 0x000000ff),
                              ((gpuData[11] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                              ((gpuData[8] >> 8) & 0x000000ff), ((gpuData[2] >> 12) & 0x3f0),
                              ((gpuData[2] >> 22) & iGPUHeightMask), gpuData[0], gpuData[3], gpuData[6], gpuData[9]);
            return;
        case 2:
            drawPoly4TGD_TW(lx0, ly0, lx1, ly1, lx3, ly3, lx2, ly2, (gpuData[2] & 0x000000ff),
                            ((gpuData[2] >> 8) & 0x000000ff), (gpuData[5] & 0x000000ff),
                            ((gpuData[5] >> 8) & 0x000000ff), (gpuData[11] & 0x000000ff),
                            ((gpuData[11] >> 8) & 0x000000ff), (gpuData[8] & 0x000000ff),
                            ((gpuData[8] >> 8) & 0x000000ff), gpuData[0], gpuData[3], gpuData[6], gpuData[9]);
            return;
    }
}

////////////////////////////////////////////////////////////////////////
// SPRITE FUNCS
////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::DrawSoftwareSpriteTWin(unsigned char *baseAddr, int32_t w, int32_t h) {
    uint32_t *gpuData = (uint32_t *)baseAddr;
    int16_t sx0, sy0, sx1, sy1, sx2, sy2, sx3, sy3;
    int16_t tx0, ty0, tx1, ty1, tx2, ty2, tx3, ty3;

    sx0 = lx0;
    sy0 = ly0;

    sx0 = sx3 = sx0 + PSXDisplay.DrawOffset.x;
    sx1 = sx2 = sx0 + w;
    sy0 = sy1 = sy0 + PSXDisplay.DrawOffset.y;
    sy2 = sy3 = sy0 + h;

    tx0 = tx3 = gpuData[2] & 0xff;
    tx1 = tx2 = tx0 + w;
    ty0 = ty1 = (gpuData[2] >> 8) & 0xff;
    ty2 = ty3 = ty0 + h;

    switch (GlobalTextTP) {
        case 0:
            drawPoly4TEx4_TW_S(sx0, sy0, sx1, sy1, sx2, sy2, sx3, sy3, tx0, ty0, tx1, ty1, tx2, ty2, tx3, ty3,
                               ((gpuData[2] >> 12) & 0x3f0), ((gpuData[2] >> 22) & iGPUHeightMask));
            return;
        case 1:
            drawPoly4TEx8_TW_S(sx0, sy0, sx1, sy1, sx2, sy2, sx3, sy3, tx0, ty0, tx1, ty1, tx2, ty2, tx3, ty3,
                               ((gpuData[2] >> 12) & 0x3f0), ((gpuData[2] >> 22) & iGPUHeightMask));
            return;
        case 2:
            drawPoly4TD_TW_S(sx0, sy0, sx1, sy1, sx2, sy2, sx3, sy3, tx0, ty0, tx1, ty1, tx2, ty2, tx3, ty3);
            return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::DrawSoftwareSpriteMirror(unsigned char *baseAddr, int32_t w, int32_t h) {
    int32_t sprtY, sprtX, sprtW, sprtH, lXDir, lYDir;
    int32_t clutY0, clutX0, clutP, textX0, textY0, sprtYa, sprCY, sprCX, sprA;
    int16_t tC;
    uint32_t *gpuData = (uint32_t *)baseAddr;
    sprtY = ly0;
    sprtX = lx0;
    sprtH = h;
    sprtW = w;
    clutY0 = (gpuData[2] >> 22) & iGPUHeightMask;
    clutX0 = (gpuData[2] >> 12) & 0x3f0;
    clutP = (clutY0 << 11) + (clutX0 << 1);
    textY0 = ((gpuData[2] >> 8) & 0x000000ff) + GlobalTextAddrY;
    textX0 = (gpuData[2] & 0x000000ff);

    sprtX += PSXDisplay.DrawOffset.x;
    sprtY += PSXDisplay.DrawOffset.y;

    // while (sprtX>1023)             sprtX-=1024;
    // while (sprtY>MAXYLINESMIN1)    sprtY-=MAXYLINES;

    if (sprtX > drawW) {
        //   if((sprtX+sprtW)>1023) sprtX-=1024;
        //   else return;
        return;
    }

    if (sprtY > drawH) {
        //   if ((sprtY+sprtH)>MAXYLINESMIN1) sprtY-=MAXYLINES;
        //   else return;
        return;
    }

    if (sprtY < drawY) {
        if ((sprtY + sprtH) < drawY) return;
        sprtH -= (drawY - sprtY);
        textY0 += (drawY - sprtY);
        sprtY = drawY;
    }

    if (sprtX < drawX) {
        if ((sprtX + sprtW) < drawX) return;
        sprtW -= (drawX - sprtX);
        textX0 += (drawX - sprtX);
        sprtX = drawX;
    }

    if ((sprtY + sprtH) > drawH) sprtH = drawH - sprtY + 1;
    if ((sprtX + sprtW) > drawW) sprtW = drawW - sprtX + 1;

    if (usMirror & 0x1000)
        lXDir = -1;
    else
        lXDir = 1;
    if (usMirror & 0x2000)
        lYDir = -1;
    else
        lYDir = 1;

    switch (GlobalTextTP) {
        case 0:  // texture is 4-bit

            sprtW = sprtW / 2;
            textX0 = (GlobalTextAddrX << 1) + (textX0 >> 1);
            sprtYa = (sprtY << 10);
            clutP = (clutY0 << 10) + clutX0;
            for (sprCY = 0; sprCY < sprtH; sprCY++)
                for (sprCX = 0; sprCX < sprtW; sprCX++) {
                    tC = psxVub[static_cast<int32_t>(((textY0 + (sprCY * lYDir)) << 11) + textX0 + (sprCX * lXDir))];
                    sprA = sprtYa + (sprCY << 10) + sprtX + (sprCX << 1);
                    GetTextureTransColG_SPR(&psxVuw[sprA], psxVuw[clutP + ((tC >> 4) & 0xf)]);
                    GetTextureTransColG_SPR(&psxVuw[sprA + 1], psxVuw[clutP + (tC & 0xf)]);
                }
            return;

        case 1:

            clutP >>= 1;
            for (sprCY = 0; sprCY < sprtH; sprCY++)
                for (sprCX = 0; sprCX < sprtW; sprCX++) {
                    tC = psxVub[static_cast<int32_t>(((textY0 + (sprCY * lYDir)) << 11) + (GlobalTextAddrX << 1) +
                                                     textX0 + (sprCX * lXDir))] &
                         0xff;
                    GetTextureTransColG_SPR(&psxVuw[((sprtY + sprCY) << 10) + sprtX + sprCX], psxVuw[clutP + tC]);
                }
            return;

        case 2:

            for (sprCY = 0; sprCY < sprtH; sprCY++)
                for (sprCX = 0; sprCX < sprtW; sprCX++) {
                    GetTextureTransColG_SPR(
                        &psxVuw[((sprtY + sprCY) << 10) + sprtX + sprCX],
                        psxVuw[((textY0 + (sprCY * lYDir)) << 10) + GlobalTextAddrX + textX0 + (sprCX * lXDir)]);
                }
            return;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::DrawSoftwareSprite_IL(unsigned char *baseAddr, int16_t w, int16_t h, int32_t tx,
                                                        int32_t ty) {
    int32_t sprtY, sprtX, sprtW, sprtH, tdx, tdy;
    uint32_t *gpuData = (uint32_t *)baseAddr;

    sprtY = ly0;
    sprtX = lx0;
    sprtH = h;
    sprtW = w;

    sprtX += PSXDisplay.DrawOffset.x;
    sprtY += PSXDisplay.DrawOffset.y;

    if (sprtX > drawW) return;
    if (sprtY > drawH) return;

    tdx = tx + sprtW;
    tdy = ty + sprtH;

    sprtW += sprtX;
    sprtH += sprtY;

    // Pete is too lazy to make a faster version ;)

    if (GlobalTextTP == 0)
        drawPoly4TEx4_IL(sprtX, sprtY, sprtX, sprtH, sprtW, sprtH, sprtW, sprtY, tx, ty, tx, tdy, tdx, tdy, tdx, ty,
                         (gpuData[2] >> 12) & 0x3f0, ((gpuData[2] >> 22) & iGPUHeightMask));

    else
        drawPoly4TEx8_IL(sprtX, sprtY, sprtX, sprtH, sprtW, sprtH, sprtW, sprtY, tx, ty, tx, tdy, tdx, tdy, tdx, ty,
                         (gpuData[2] >> 12) & 0x3f0, ((gpuData[2] >> 22) & iGPUHeightMask));
}

////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::DrawSoftwareSprite(unsigned char *baseAddr, int16_t w, int16_t h, int32_t tx,
                                                     int32_t ty) {
    int32_t sprtY, sprtX, sprtW, sprtH;
    int32_t clutY0, clutX0, clutP, textX0, textY0, sprtYa, sprCY, sprCX, sprA;
    int16_t tC, tC2;
    uint32_t *gpuData = (uint32_t *)baseAddr;
    unsigned char *pV;
    bool bWT, bWS;

    if (GlobalTextIL && GlobalTextTP < 2) {
        DrawSoftwareSprite_IL(baseAddr, w, h, tx, ty);
        return;
    }

    sprtY = ly0;
    sprtX = lx0;
    sprtH = h;
    sprtW = w;
    clutY0 = (gpuData[2] >> 22) & iGPUHeightMask;
    clutX0 = (gpuData[2] >> 12) & 0x3f0;

    clutP = (clutY0 << 11) + (clutX0 << 1);

    textY0 = ty + GlobalTextAddrY;
    textX0 = tx;

    sprtX += PSXDisplay.DrawOffset.x;
    sprtY += PSXDisplay.DrawOffset.y;

    // while (sprtX>1023)             sprtX-=1024;
    // while (sprtY>MAXYLINESMIN1)    sprtY-=MAXYLINES;

    if (sprtX > drawW) {
        //   if((sprtX+sprtW)>1023) sprtX-=1024;
        //   else return;
        return;
    }

    if (sprtY > drawH) {
        //   if ((sprtY+sprtH)>MAXYLINESMIN1) sprtY-=MAXYLINES;
        //   else return;
        return;
    }

    if (sprtY < drawY) {
        if ((sprtY + sprtH) < drawY) return;
        sprtH -= (drawY - sprtY);
        textY0 += (drawY - sprtY);
        sprtY = drawY;
    }

    if (sprtX < drawX) {
        if ((sprtX + sprtW) < drawX) return;

        sprtW -= (drawX - sprtX);
        textX0 += (drawX - sprtX);
        sprtX = drawX;
    }

    if ((sprtY + sprtH) > drawH) sprtH = drawH - sprtY + 1;
    if ((sprtX + sprtW) > drawW) sprtW = drawW - sprtX + 1;

    bWT = false;
    bWS = false;

    switch (GlobalTextTP) {
        case 0:

            if (textX0 & 1) {
                bWS = true;
                sprtW--;
            }
            if (sprtW & 1) bWT = true;

            sprtW = sprtW >> 1;
            textX0 = (GlobalTextAddrX << 1) + (textX0 >> 1) + (textY0 << 11);
            sprtYa = (sprtY << 10) + sprtX;
            clutP = (clutY0 << 10) + clutX0;

#ifdef FASTSOLID

            if (!bCheckMask && !DrawSemiTrans) {
                for (sprCY = 0; sprCY < sprtH; sprCY++) {
                    sprA = sprtYa + (sprCY << 10);
                    pV = &psxVub[static_cast<int32_t>((sprCY << 11) + textX0)];

                    if (bWS) {
                        tC = *pV++;
                        GetTextureTransColG_S(&psxVuw[sprA++], psxVuw[clutP + ((tC >> 4) & 0xf)]);
                    }

                    for (sprCX = 0; sprCX < sprtW; sprCX++, sprA += 2) {
                        tC = *pV++;

                        GetTextureTransColG32_S(
                            (uint32_t *)&psxVuw[sprA],
                            (((int32_t)psxVuw[clutP + ((tC >> 4) & 0xf)]) << 16) | psxVuw[clutP + (tC & 0x0f)]);
                    }

                    if (bWT) {
                        tC = *pV;
                        GetTextureTransColG_S(&psxVuw[sprA], psxVuw[clutP + (tC & 0x0f)]);
                    }
                }
                return;
            }

#endif

            for (sprCY = 0; sprCY < sprtH; sprCY++) {
                sprA = sprtYa + (sprCY << 10);
                pV = &psxVub[static_cast<int32_t>((sprCY << 11) + textX0)];

                if (bWS) {
                    tC = *pV++;
                    GetTextureTransColG_SPR(&psxVuw[sprA++], psxVuw[clutP + ((tC >> 4) & 0xf)]);
                }

                for (sprCX = 0; sprCX < sprtW; sprCX++, sprA += 2) {
                    tC = *pV++;

                    GetTextureTransColG32_SPR(
                        (uint32_t *)&psxVuw[sprA],
                        (((int32_t)psxVuw[clutP + ((tC >> 4) & 0xf)]) << 16) | psxVuw[clutP + (tC & 0x0f)]);
                }

                if (bWT) {
                    tC = *pV;
                    GetTextureTransColG_SPR(&psxVuw[sprA], psxVuw[clutP + (tC & 0x0f)]);
                }
            }
            return;

        case 1:
            clutP >>= 1;
            sprtW--;
            textX0 += (GlobalTextAddrX << 1) + (textY0 << 11);

#ifdef FASTSOLID

            if (!bCheckMask && !DrawSemiTrans) {
                for (sprCY = 0; sprCY < sprtH; sprCY++) {
                    sprA = ((sprtY + sprCY) << 10) + sprtX;
                    pV = &psxVub[static_cast<int32_t>((sprCY << 11) + textX0)];
                    for (sprCX = 0; sprCX < sprtW; sprCX += 2, sprA += 2) {
                        tC = *pV++;
                        tC2 = *pV++;
                        GetTextureTransColG32_S((uint32_t *)&psxVuw[sprA],
                                                (((int32_t)psxVuw[clutP + tC2]) << 16) | psxVuw[clutP + tC]);
                    }
                    if (sprCX == sprtW) GetTextureTransColG_S(&psxVuw[sprA], psxVuw[clutP + (*pV)]);
                }
                return;
            }

#endif

            for (sprCY = 0; sprCY < sprtH; sprCY++) {
                sprA = ((sprtY + sprCY) << 10) + sprtX;
                pV = &psxVub[static_cast<int32_t>((sprCY << 11) + textX0)];
                for (sprCX = 0; sprCX < sprtW; sprCX += 2, sprA += 2) {
                    tC = *pV++;
                    tC2 = *pV++;
                    GetTextureTransColG32_SPR((uint32_t *)&psxVuw[sprA],
                                              (((int32_t)psxVuw[clutP + tC2]) << 16) | psxVuw[clutP + tC]);
                }
                if (sprCX == sprtW) GetTextureTransColG_SPR(&psxVuw[sprA], psxVuw[clutP + (*pV)]);
            }
            return;

        case 2:

            textX0 += (GlobalTextAddrX) + (textY0 << 10);
            sprtW--;

#ifdef FASTSOLID

            if (!bCheckMask && !DrawSemiTrans) {
                for (sprCY = 0; sprCY < sprtH; sprCY++) {
                    sprA = ((sprtY + sprCY) << 10) + sprtX;

                    for (sprCX = 0; sprCX < sprtW; sprCX += 2, sprA += 2) {
                        GetTextureTransColG32_S((uint32_t *)&psxVuw[sprA],
                                                (((int32_t)psxVuw[(sprCY << 10) + textX0 + sprCX + 1]) << 16) |
                                                    psxVuw[(sprCY << 10) + textX0 + sprCX]);
                    }
                    if (sprCX == sprtW) GetTextureTransColG_S(&psxVuw[sprA], psxVuw[(sprCY << 10) + textX0 + sprCX]);
                }
                return;
            }

#endif

            for (sprCY = 0; sprCY < sprtH; sprCY++) {
                sprA = ((sprtY + sprCY) << 10) + sprtX;

                for (sprCX = 0; sprCX < sprtW; sprCX += 2, sprA += 2) {
                    GetTextureTransColG32_SPR((uint32_t *)&psxVuw[sprA],
                                              (((int32_t)psxVuw[(sprCY << 10) + textX0 + sprCX + 1]) << 16) |
                                                  psxVuw[(sprCY << 10) + textX0 + sprCX]);
                }
                if (sprCX == sprtW) GetTextureTransColG_SPR(&psxVuw[sprA], psxVuw[(sprCY << 10) + textX0 + sprCX]);
            }
            return;
    }
}

///////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
// LINE FUNCS
////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::Line_E_SE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1) {
    int dx, dy, incrE, incrSE, d;
    uint32_t r0, g0, b0, r1, g1, b1;
    int32_t dr, dg, db;

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

    if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH))
        GetShadeTransCol(&psxVuw[(y0 << 10) + x0],
                         (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
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

        if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH))
            GetShadeTransCol(&psxVuw[(y0 << 10) + x0],
                             (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::Line_S_SE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1) {
    int dx, dy, incrS, incrSE, d;
    uint32_t r0, g0, b0, r1, g1, b1;
    int32_t dr, dg, db;

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

    if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH))
        GetShadeTransCol(&psxVuw[(y0 << 10) + x0],
                         (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
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

        if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH))
            GetShadeTransCol(&psxVuw[(y0 << 10) + x0],
                             (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::Line_N_NE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1) {
    int dx, dy, incrN, incrNE, d;
    uint32_t r0, g0, b0, r1, g1, b1;
    int32_t dr, dg, db;

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

    if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH))
        GetShadeTransCol(&psxVuw[(y0 << 10) + x0],
                         (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
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

        if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH))
            GetShadeTransCol(&psxVuw[(y0 << 10) + x0],
                             (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::Line_E_NE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1) {
    int dx, dy, incrE, incrNE, d;
    uint32_t r0, g0, b0, r1, g1, b1;
    int32_t dr, dg, db;

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

    if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH))
        GetShadeTransCol(&psxVuw[(y0 << 10) + x0],
                         (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
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

        if ((x0 >= drawX) && (x0 < drawW) && (y0 >= drawY) && (y0 < drawH))
            GetShadeTransCol(&psxVuw[(y0 << 10) + x0],
                             (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::VertLineShade(int x, int y0, int y1, uint32_t rgb0, uint32_t rgb1) {
    int y, dy;
    uint32_t r0, g0, b0, r1, g1, b1;
    int32_t dr, dg, db;

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

    if (y0 < drawY) {
        r0 += dr * (drawY - y0);
        g0 += dg * (drawY - y0);
        b0 += db * (drawY - y0);
        y0 = drawY;
    }

    if (y1 > drawH) y1 = drawH;

    for (y = y0; y <= y1; y++) {
        GetShadeTransCol(&psxVuw[(y << 10) + x],
                         (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
        r0 += dr;
        g0 += dg;
        b0 += db;
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::HorzLineShade(int y, int x0, int x1, uint32_t rgb0, uint32_t rgb1) {
    int x, dx;
    uint32_t r0, g0, b0, r1, g1, b1;
    int32_t dr, dg, db;

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

    if (x0 < drawX) {
        r0 += dr * (drawX - x0);
        g0 += dg * (drawX - x0);
        b0 += db * (drawX - x0);
        x0 = drawX;
    }

    if (x1 > drawW) x1 = drawW;

    for (x = x0; x <= x1; x++) {
        GetShadeTransCol(&psxVuw[(y << 10) + x],
                         (uint16_t)(((r0 >> 9) & 0x7c00) | ((g0 >> 14) & 0x03e0) | ((b0 >> 19) & 0x001f)));
        r0 += dr;
        g0 += dg;
        b0 += db;
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::Line_E_SE_Flat(int x0, int y0, int x1, int y1, uint16_t colour) {
    int dx, dy, incrE, incrSE, d, x, y;

    dx = x1 - x0;
    dy = y1 - y0;
    d = 2 * dy - dx;        /* Initial value of d */
    incrE = 2 * dy;         /* incr. used for move to E */
    incrSE = 2 * (dy - dx); /* incr. used for move to SE */
    x = x0;
    y = y0;
    if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH)) GetShadeTransCol(&psxVuw[(y << 10) + x], colour);
    while (x < x1) {
        if (d <= 0) {
            d = d + incrE; /* Choose E */
            x++;
        } else {
            d = d + incrSE; /* Choose SE */
            x++;
            y++;
        }
        if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH))
            GetShadeTransCol(&psxVuw[(y << 10) + x], colour);
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::Line_S_SE_Flat(int x0, int y0, int x1, int y1, uint16_t colour) {
    int dx, dy, incrS, incrSE, d, x, y;

    dx = x1 - x0;
    dy = y1 - y0;
    d = 2 * dx - dy;        /* Initial value of d */
    incrS = 2 * dx;         /* incr. used for move to S */
    incrSE = 2 * (dx - dy); /* incr. used for move to SE */
    x = x0;
    y = y0;
    if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH)) GetShadeTransCol(&psxVuw[(y << 10) + x], colour);
    while (y < y1) {
        if (d <= 0) {
            d = d + incrS; /* Choose S */
            y++;
        } else {
            d = d + incrSE; /* Choose SE */
            x++;
            y++;
        }
        if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH))
            GetShadeTransCol(&psxVuw[(y << 10) + x], colour);
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::Line_N_NE_Flat(int x0, int y0, int x1, int y1, uint16_t colour) {
    int dx, dy, incrN, incrNE, d, x, y;

    dx = x1 - x0;
    dy = -(y1 - y0);
    d = 2 * dx - dy;        /* Initial value of d */
    incrN = 2 * dx;         /* incr. used for move to N */
    incrNE = 2 * (dx - dy); /* incr. used for move to NE */
    x = x0;
    y = y0;
    if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH)) GetShadeTransCol(&psxVuw[(y << 10) + x], colour);
    while (y > y1) {
        if (d <= 0) {
            d = d + incrN; /* Choose N */
            y--;
        } else {
            d = d + incrNE; /* Choose NE */
            x++;
            y--;
        }
        if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH))
            GetShadeTransCol(&psxVuw[(y << 10) + x], colour);
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::Line_E_NE_Flat(int x0, int y0, int x1, int y1, uint16_t colour) {
    int dx, dy, incrE, incrNE, d, x, y;

    dx = x1 - x0;
    dy = -(y1 - y0);
    d = 2 * dy - dx;        /* Initial value of d */
    incrE = 2 * dy;         /* incr. used for move to E */
    incrNE = 2 * (dy - dx); /* incr. used for move to NE */
    x = x0;
    y = y0;
    if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH)) GetShadeTransCol(&psxVuw[(y << 10) + x], colour);
    while (x < x1) {
        if (d <= 0) {
            d = d + incrE; /* Choose E */
            x++;
        } else {
            d = d + incrNE; /* Choose NE */
            x++;
            y--;
        }
        if ((x >= drawX) && (x < drawW) && (y >= drawY) && (y < drawH))
            GetShadeTransCol(&psxVuw[(y << 10) + x], colour);
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::VertLineFlat(int x, int y0, int y1, uint16_t colour) {
    int y;

    if (y0 < drawY) y0 = drawY;

    if (y1 > drawH) y1 = drawH;

    for (y = y0; y <= y1; y++) GetShadeTransCol(&psxVuw[(y << 10) + x], colour);
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::HorzLineFlat(int y, int x0, int x1, uint16_t colour) {
    int x;

    if (x0 < drawX) x0 = drawX;

    if (x1 > drawW) x1 = drawW;

    for (x = x0; x <= x1; x++) GetShadeTransCol(&psxVuw[(y << 10) + x], colour);
}

///////////////////////////////////////////////////////////////////////

/* Bresenham Line drawing function */
void PCSX::SoftGPU::SoftRenderer::DrawSoftwareLineShade(int32_t rgb0, int32_t rgb1) {
    int16_t x0, y0, x1, y1, xt, yt;
    int32_t rgbt;
    double m, dy, dx;

    if (lx0 > drawW && lx1 > drawW) return;
    if (ly0 > drawH && ly1 > drawH) return;
    if (lx0 < drawX && lx1 < drawX) return;
    if (ly0 < drawY && ly1 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    x0 = lx0;
    y0 = ly0;
    x1 = lx1;
    y1 = ly1;

    dx = x1 - x0;
    dy = y1 - y0;

    if (dx == 0) {
        if (dy > 0)
            VertLineShade(x0, y0, y1, rgb0, rgb1);
        else
            VertLineShade(x0, y1, y0, rgb1, rgb0);
    } else if (dy == 0) {
        if (dx > 0)
            HorzLineShade(y0, x0, x1, rgb0, rgb1);
        else
            HorzLineShade(y0, x1, x0, rgb1, rgb0);
    } else {
        if (dx < 0) {
            xt = x0;
            yt = y0;
            rgbt = rgb0;
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
            if (m > 1)
                Line_S_SE_Shade(x0, y0, x1, y1, rgb0, rgb1);
            else
                Line_E_SE_Shade(x0, y0, x1, y1, rgb0, rgb1);
        } else if (m < -1)
            Line_N_NE_Shade(x0, y0, x1, y1, rgb0, rgb1);
        else
            Line_E_NE_Shade(x0, y0, x1, y1, rgb0, rgb1);
    }
}

///////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::SoftRenderer::DrawSoftwareLineFlat(int32_t rgb) {
    int16_t x0, y0, x1, y1, xt, yt;
    double m, dy, dx;
    uint16_t colour = 0;

    if (lx0 > drawW && lx1 > drawW) return;
    if (ly0 > drawH && ly1 > drawH) return;
    if (lx0 < drawX && lx1 < drawX) return;
    if (ly0 < drawY && ly1 < drawY) return;
    if (drawY >= drawH) return;
    if (drawX >= drawW) return;

    colour = ((rgb & 0x00f80000) >> 9) | ((rgb & 0x0000f800) >> 6) | ((rgb & 0x000000f8) >> 3);

    x0 = lx0;
    y0 = ly0;
    x1 = lx1;
    y1 = ly1;

    dx = x1 - x0;
    dy = y1 - y0;

    if (dx == 0) {
        if (dy == 0)
            return;  // Nothing to draw
        else if (dy > 0)
            VertLineFlat(x0, y0, y1, colour);
        else
            VertLineFlat(x0, y1, y0, colour);
    } else if (dy == 0) {
        if (dx > 0)
            HorzLineFlat(y0, x0, x1, colour);
        else
            HorzLineFlat(y0, x1, x0, colour);
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
            if (m > 1)
                Line_S_SE_Flat(x0, y0, x1, y1, colour);
            else
                Line_E_SE_Flat(x0, y0, x1, y1, colour);
        } else if (m < -1)
            Line_N_NE_Flat(x0, y0, x1, y1, colour);
        else
            Line_E_NE_Flat(x0, y0, x1, y1, colour);
    }
}

///////////////////////////////////////////////////////////////////////
