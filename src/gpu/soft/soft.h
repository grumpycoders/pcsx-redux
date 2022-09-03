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

namespace PCSX {

namespace SoftGPU {

struct SoftRenderer {
    inline void resetRenderer() {
        m_lobalTextAddrX = 0;
        m_globalTextAddrY = 0;
        m_globalTextTP = GPU::TexDepth::Tex4Bits;
        m_globalTextABR = GPU::BlendFunction::HalfBackAndHalfFront;
        m_drawX = m_drawY = 0;
        m_drawW = m_drawH = 0;
        m_checkMask = false;
        m_setMask16 = 0;
        m_setMask32 = 0;
    }

    int m_useDither = 0;

    bool checkCoord4();
    bool checkCoord3();

    void texturePage(GPU::TPage *prim);
    void twindow(GPU::TWindow *prim);
    void drawingAreaStart(GPU::DrawingAreaStart *prim);
    void drawingAreaEnd(GPU::DrawingAreaEnd *prim);
    void drawingOffset(GPU::DrawingOffset *prim);
    void maskBit(GPU::MaskBit *prim);

    struct Point {
        int32_t x;
        int32_t y;
    };

    struct ShortPoint {
        int16_t x;
        int16_t y;
    };

    struct SoftRect {
        int16_t x0;
        int16_t x1;
        int16_t y0;
        int16_t y1;
    };

    struct SoftDisplay {
        Point DisplayModeNew;
        Point DisplayMode;
        Point DisplayPosition;
        Point DisplayEnd;

        int32_t Double;
        int32_t Height;
        int32_t PAL;
        int32_t InterlacedNew;
        int32_t Interlaced;
        int32_t RGB24New;
        int32_t RGB24;
        ShortPoint DrawOffset;
        int32_t Disabled;
        SoftRect Range;
    };

    struct TextureWindow {
        SoftRect Position;
    };

    TextureWindow m_textureWindow;
    int m_ditherMode = 0;
    int m_drawX, m_drawY, m_drawW, m_drawH;

    static constexpr int GPU_HEIGHT = 512;
    static constexpr int GPU_HEIGHT_MASK = 511;

    bool m_drawSemiTrans = false;
    int16_t m_m1 = 255, m_m2 = 255, m_m3 = 255;
    int16_t m_y0, m_x0, m_y1, m_x1, m_y2, m_x2, m_y3, m_x3;  // global psx vertex coords

    int32_t m_lobalTextAddrX;
    int32_t m_globalTextAddrY;
    GPU::TexDepth m_globalTextTP;
    GPU::BlendFunction m_globalTextABR;

    bool m_checkMask = false;
    uint16_t m_setMask16 = 0;
    uint32_t m_setMask32 = 0;
    int32_t m_statusRet;
    uint32_t m_textureWindowRaw;
    uint32_t m_drawingStartRaw;
    uint32_t m_drawingEndRaw;
    uint32_t m_drawingOffsetRaw;
    SoftDisplay m_softDisplay;
    uint8_t *m_vram;
    uint16_t *m_vram16;

    void applyOffset2();
    void applyOffset3();
    void applyOffset4();

    void applyDither(uint16_t *pdest, uint32_t r, uint32_t g, uint32_t b, uint16_t sM);

    void fillSoftwareAreaTrans(int16_t x0, int16_t y0, int16_t x1, int16_t y1, uint16_t col);
    void fillSoftwareArea(int16_t x0, int16_t y0, int16_t x1, int16_t y1, uint16_t col);
    void drawPolyShade3(int32_t rgb1, int32_t rgb2, int32_t rgb3);
    void drawPolyShade4(int32_t rgb1, int32_t rgb2, int32_t rgb3, int32_t rgb4);
    void drawPolyFlat3(int32_t rgb);
    void drawPolyFlat4(int32_t rgb);
    void drawSoftwareLineShade(int32_t rgb0, int32_t rgb1);
    void drawSoftwareLineFlat(int32_t rgb);

    int16_t m_yMin;
    int16_t m_yMax;

    bool setupSectionsFlat3(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3);
    bool setupSectionsShade3(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int32_t rgb1,
                             int32_t rgb2, int32_t rgb3);
    bool setupSectionsFlatTextured3(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1,
                                    int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3);
    bool setupSectionsShadeTextured3(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                     int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3,
                                     int32_t rgb1, int32_t rgb2, int32_t rgb3);
    bool setupSectionsFlat4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4,
                            int16_t y4);
    bool setupSectionsFlatTextured4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4,
                                    int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                    int16_t ty3, int16_t tx4, int16_t ty4);
    bool setupSectionsShadeTextured4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4,
                                     int16_t y4, int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                     int16_t ty3, int16_t tx4, int16_t ty4, int32_t rgb1, int32_t rgb2, int32_t rgb3,
                                     int32_t rgb4);

    void getShadeTransColDither(uint16_t *pdest, int32_t m1, int32_t m2, int32_t m3);
    void getShadeTransCol(uint16_t *pdest, uint16_t color);
    void getShadeTransCol32(uint32_t *pdest, uint32_t color);
    void getTextureTransColShade(uint16_t *pdest, uint16_t color);
    void getTextureTransColShadeSolid(uint16_t *pdest, uint16_t color);
    void getTextureTransColShadeSemi(uint16_t *pdest, uint16_t color);
    void getTextureTransColShade32(uint32_t *pdest, uint32_t color);
    void getTextureTransColShade32Solid(uint32_t *pdest, uint32_t color);
    void getTextureTransColG32Semi(uint32_t *pdest, uint32_t color);
    void getTextureTransColShadeXDither(uint16_t *pdest, uint16_t color, int32_t m1, int32_t m2, int32_t m3);
    void getTextureTransColShadeX(uint16_t *pdest, uint16_t color, int16_t m1, int16_t m2, int16_t m3);
    void getTextureTransColShadeXSolid(uint16_t *pdest, uint16_t color, int16_t m1, int16_t m2, int16_t m3);
    void getTextureTransColShadeX32Solid(uint32_t *pdest, uint32_t color, int16_t m1, int16_t m2, int16_t m3);
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
    void line_E_SE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1);
    void line_S_SE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1);
    void line_N_NE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1);
    void line_E_NE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1);
    void vertLineShade(int x, int y0, int y1, uint32_t rgb0, uint32_t rgb1);
    void horzLineShade(int y, int x0, int x1, uint32_t rgb0, uint32_t rgb1);
    void line_E_SE_Flat(int x0, int y0, int x1, int y1, uint16_t col);
    void line_S_SE_Flat(int x0, int y0, int x1, int y1, uint16_t col);
    void line_N_NE_Flat(int x0, int y0, int x1, int y1, uint16_t col);
    void line_E_NE_Flat(int x0, int y0, int x1, int y1, uint16_t col);
    void vertLineFlat(int x, int y0, int y1, uint16_t col);
    void horzLineFlat(int y, int x0, int x1, uint16_t col);

  private:
    int rightSectionFlat3();
    int leftSectionFlat3();
    bool nextRowFlat3();
    int rightSectionShade3();
    int leftSectionShade3();
    bool nextRowShade3();
    int rightSectionFlatTextured3();
    int leftSectionFlatTextured3();
    bool nextRowFlatTextured3();
    int rightSectionShadeTextured3();
    int leftSectionShadeTextured3();
    bool nextRowShadeTextured3();
    int rightSectionFlat4();
    int leftSectionFlat4();
    int rightSectionFlatTextured4();
    int leftSectionFlatTextured4();
    bool nextRowFlatTextured4();
    int rightSectionShadeTextured4();
    int leftSectionShadeTextured4();
    struct SoftVertex {
        int x, y;
        int u, v;
        int32_t R, G, B;
    };

    SoftVertex m_vtx[4];
    SoftVertex *m_leftArray[4], *m_rightArray[4];
    int m_leftSection, m_rightSection;
    int m_leftSectionHeight, m_rightSectionHeight;
    int m_leftX, m_deltaLeftX, m_rightX, m_deltaRightX;
    int m_leftU, m_deltaLeftU, m_leftV, m_deltaLeftV;
    int m_rightU, m_deltaRightU, m_rightV, m_deltaRightV;
    int m_leftR, deltaLeftR, m_rightR, m_deltaRightR;
    int m_leftG, m_deltaLeftG, m_rightG, m_deltaRightG;
    int m_leftB, m_deltaLeftB, m_rightB, m_deltaRightB;

    static constexpr inline int shl10idiv(int x, int y) {
        int64_t bi = x;
        bi <<= 10;
        return bi / y;
    }
};

}  // namespace SoftGPU

}  // namespace PCSX
