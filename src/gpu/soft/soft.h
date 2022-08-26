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

#pragma once

#include <stdint.h>

#include "core/gpu.h"
#include "gpu/soft/externals.h"

namespace PCSX {

namespace SoftGPU {

struct SoftRenderer {
    inline void reset() {
        GlobalTextAddrX = 0;
        GlobalTextAddrY = 0;
        GlobalTextTP = GPU::TexDepth::Tex4Bits;
        GlobalTextABR = GPU::BlendFunction::HalfBackAndHalfFront;
        drawX = drawY = 0;
        drawW = drawH = 0;
        bCheckMask = false;
        sSetMask = 0;
        lSetMask = 0;
    }

    int m_useDither = 0;

    int32_t GlobalTextREST;

    bool CheckCoord4();
    bool CheckCoord3();

    void texturePage(GPU::TPage *prim);
    void twindow(GPU::TWindow *prim);
    void drawingAreaStart(GPU::DrawingAreaStart *prim);
    void drawingAreaEnd(GPU::DrawingAreaEnd *prim);
    void drawingOffset(GPU::DrawingOffset *prim);
    void maskBit(GPU::MaskBit *prim);
    
    TWin_t TWin;
    int iDither = 0;
    int drawX, drawY, drawW, drawH;

    bool DrawSemiTrans = false;
    int16_t g_m1 = 255, g_m2 = 255, g_m3 = 255;
    int16_t ly0, lx0, ly1, lx1, ly2, lx2, ly3, lx3;  // global psx vertex coords

    int32_t GlobalTextAddrX;
    int32_t GlobalTextAddrY;
    GPU::TexDepth GlobalTextTP;
    GPU::BlendFunction GlobalTextABR;

    bool bCheckMask = false;
    uint16_t sSetMask = 0;
    uint32_t lSetMask = 0;

    void offsetPSX2();
    void offsetPSX3();
    void offsetPSX4();

    void FillSoftwareAreaTrans(int16_t x0, int16_t y0, int16_t x1, int16_t y1, uint16_t col);
    void FillSoftwareArea(int16_t x0, int16_t y0, int16_t x1, int16_t y1, uint16_t col);
    void drawPoly3G(int32_t rgb1, int32_t rgb2, int32_t rgb3);
    void drawPoly4G(int32_t rgb1, int32_t rgb2, int32_t rgb3, int32_t rgb4);
    void drawPoly3F(int32_t rgb);
    void drawPoly4F(int32_t rgb);
    void DrawSoftwareLineShade(int32_t rgb0, int32_t rgb1);
    void DrawSoftwareLineFlat(int32_t rgb);

    int16_t Ymin;
    int16_t Ymax;

    bool SetupSections_F(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3);
    bool SetupSections_G(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int32_t rgb1,
                         int32_t rgb2, int32_t rgb3);
    bool SetupSections_FT(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1,
                          int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3);
    bool SetupSections_GT(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1,
                          int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int32_t rgb1, int32_t rgb2,
                          int32_t rgb3);
    bool SetupSections_F4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4,
                          int16_t y4);
    bool SetupSections_FT4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4,
                           int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3,
                           int16_t tx4, int16_t ty4);
    bool SetupSections_GT4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4,
                           int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3,
                           int16_t tx4, int16_t ty4, int32_t rgb1, int32_t rgb2, int32_t rgb3, int32_t rgb4);

    void GetShadeTransCol_Dither(uint16_t *pdest, int32_t m1, int32_t m2, int32_t m3);
    void GetShadeTransCol(uint16_t *pdest, uint16_t color);
    void GetShadeTransCol32(uint32_t *pdest, uint32_t color);
    void GetTextureTransColG(uint16_t *pdest, uint16_t color);
    void GetTextureTransColG_S(uint16_t *pdest, uint16_t color);
    void GetTextureTransColG_SPR(uint16_t *pdest, uint16_t color);
    void GetTextureTransColG32(uint32_t *pdest, uint32_t color);
    void GetTextureTransColG32_S(uint32_t *pdest, uint32_t color);
    void GetTextureTransColG32_SPR(uint32_t *pdest, uint32_t color);
    void GetTextureTransColGX_Dither(uint16_t *pdest, uint16_t color, int32_t m1, int32_t m2, int32_t m3);
    void GetTextureTransColGX(uint16_t *pdest, uint16_t color, int16_t m1, int16_t m2, int16_t m3);
    void GetTextureTransColGX_S(uint16_t *pdest, uint16_t color, int16_t m1, int16_t m2, int16_t m3);
    void GetTextureTransColGX32_S(uint32_t *pdest, uint32_t color, int16_t m1, int16_t m2, int16_t m3);
    void drawPoly3Fi(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int32_t rgb);
    void drawPoly3TEx4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1,
                       int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY);
    void drawPoly4TEx4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4,
                       int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                       int16_t ty4, int16_t clX, int16_t clY);
    void drawPoly4TEx4_S(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4,
                         int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                         int16_t ty4, int16_t clX, int16_t clY);
    void drawPoly3TEx8(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1,
                       int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY);
    void drawPoly4TEx8(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4,
                       int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                       int16_t ty4, int16_t clX, int16_t clY);
    void drawPoly4TEx8_S(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4,
                         int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                         int16_t ty4, int16_t clX, int16_t clY);
    void drawPoly3TD(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1,
                     int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3);
    void drawPoly4TD(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4,
                     int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                     int16_t ty4);
    void drawPoly4TD_S(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4,
                       int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                       int16_t ty4);
    void drawPoly3Gi(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int32_t rgb1, int32_t rgb2,
                     int32_t rgb3);
    void drawPoly3TGEx4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1,
                        int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY,
                        int32_t col1, int32_t col2, int32_t col3);
    void drawPoly4TGEx4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4,
                        int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                        int16_t ty4, int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col3, int32_t col4);
    void drawPoly3TGEx8(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1,
                        int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY,
                        int32_t col1, int32_t col2, int32_t col3);
    void drawPoly4TGEx8(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4,
                        int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                        int16_t ty4, int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col3, int32_t col4);
    void drawPoly3TGD(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1,
                      int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int32_t col1, int32_t col2, int32_t col3);
    void drawPoly4TGD(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4,
                      int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                      int16_t ty4, int32_t col1, int32_t col2, int32_t col3, int32_t col4);
    void Line_E_SE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1);
    void Line_S_SE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1);
    void Line_N_NE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1);
    void Line_E_NE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1);
    void VertLineShade(int x, int y0, int y1, uint32_t rgb0, uint32_t rgb1);
    void HorzLineShade(int y, int x0, int x1, uint32_t rgb0, uint32_t rgb1);
    void Line_E_SE_Flat(int x0, int y0, int x1, int y1, uint16_t colour);
    void Line_S_SE_Flat(int x0, int y0, int x1, int y1, uint16_t colour);
    void Line_N_NE_Flat(int x0, int y0, int x1, int y1, uint16_t colour);
    void Line_E_NE_Flat(int x0, int y0, int x1, int y1, uint16_t colour);
    void VertLineFlat(int x, int y0, int y1, uint16_t colour);
    void HorzLineFlat(int y, int x0, int x1, uint16_t colour);
};

}  // namespace SoftGPU

}  // namespace PCSX
