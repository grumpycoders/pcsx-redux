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
#include "gpu/soft/raster-state.h"

namespace PCSX {

namespace SoftGPU {

// Bresenham line-octant axes for the soft GPU line rasterizer.
//
// MajorAxis  - which axis advances every iteration. X for shallow lines
//              (|slope| <= 1), Y for steep lines (|slope| > 1).
// MajorSign  - direction of the major-axis step. X-major lines always
//              advance left-to-right after the dispatcher's swap, so
//              MajorSign::Plus there is structural. Y-major lines run
//              either downward (Plus) or upward (Minus) depending on
//              whether the original slope was positive or negative.
// MinorSign  - direction the minor axis takes on the Bresenham diagonal
//              decision. Pairs with MajorAxis: for X-major it nudges Y,
//              for Y-major it nudges X.
// Bias       - the initial value of the Bresenham error term. Shallow
//              uses the pixel-centre-biased 3*dy - dx that matches the
//              PlayStation GPU's minor-axis tie-break at half-pixel
//              crossings (phase-2 / phase-10 hardware-verified, see
//              learnings/pcsx-redux/gpu.md). Steep uses the standard
//              midpoint 2*dx - dy which already matches hardware for
//              Y-major lines. The bias is hardware-load-bearing and
//              MUST track MajorAxis explicitly; do not unify the two
//              policies without re-running phase-2 and phase-10.
namespace Line {
enum class Axis { X, Y };
enum class MajorSign { Plus, Minus };
enum class MinorSign { Plus, Minus };
enum class Bias { Shallow, Steep };
}  // namespace Line

struct SoftRenderer {
    ~SoftRenderer();
    inline void resetRenderer() {
        m_globalTextAddrX = 0;
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
    bool m_disableTexturesInPolygons = false;
    bool m_disableTexturesInRectangles = false;

    bool checkCoord4(int16_t &x0, int16_t &y0, int16_t &x1, int16_t &y1, int16_t &x2, int16_t &y2, int16_t &x3,
                     int16_t &y3);
    bool checkCoord3(int16_t &x0, int16_t &y0, int16_t &x1, int16_t &y1, int16_t &x2, int16_t &y2);

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
        bool RGB24New;
        bool RGB24;
        ShortPoint DrawOffset;
        int32_t Disabled;
        SoftRect Range;
    };

    SoftRect m_textureWindow;
    // Bit-substitution form of the GP0(E2) texture window, computed in
    // twindow() and consumed by Sampler<TexMode>. mask = mask_field * 8
    // (the bits of u/v the window overwrites); off = (off_field * 8) &
    // mask (pre-masked bits that get OR'd back in). See twindow() for the
    // hardware citation.
    uint8_t m_textureWindowMaskU = 0;
    uint8_t m_textureWindowMaskV = 0;
    uint8_t m_textureWindowOffU = 0;
    uint8_t m_textureWindowOffV = 0;
    bool m_ditherMode = false;
    int m_drawX, m_drawY, m_drawW, m_drawH;

    bool m_drawSemiTrans = false;
    int16_t m_m1 = 255, m_m2 = 255, m_m3 = 255;

    int32_t m_globalTextAddrX;
    int32_t m_globalTextAddrY;
    GPU::TexDepth m_globalTextTP;
    GPU::BlendFunction m_globalTextABR;

    bool m_checkMask = false;
    uint16_t m_setMask16 = 0;
    uint32_t m_setMask32 = 0;
    int32_t m_statusRet;
    SoftDisplay m_softDisplay;
    uint8_t *m_vram;
    uint16_t *m_vram16;

    void applyOffset2(int16_t &x0, int16_t &y0, int16_t &x1, int16_t &y1) {
        x0 += m_softDisplay.DrawOffset.x;
        y0 += m_softDisplay.DrawOffset.y;
        x1 += m_softDisplay.DrawOffset.x;
        y1 += m_softDisplay.DrawOffset.y;
    }
    void applyOffset3(int16_t &x0, int16_t &y0, int16_t &x1, int16_t &y1, int16_t &x2, int16_t &y2) {
        x0 += m_softDisplay.DrawOffset.x;
        y0 += m_softDisplay.DrawOffset.y;
        x1 += m_softDisplay.DrawOffset.x;
        y1 += m_softDisplay.DrawOffset.y;
        x2 += m_softDisplay.DrawOffset.x;
        y2 += m_softDisplay.DrawOffset.y;
    }
    void applyOffset4(int16_t &x0, int16_t &y0, int16_t &x1, int16_t &y1, int16_t &x2, int16_t &y2, int16_t &x3,
                      int16_t &y3) {
        x0 += m_softDisplay.DrawOffset.x;
        y0 += m_softDisplay.DrawOffset.y;
        x1 += m_softDisplay.DrawOffset.x;
        y1 += m_softDisplay.DrawOffset.y;
        x2 += m_softDisplay.DrawOffset.x;
        y2 += m_softDisplay.DrawOffset.y;
        x3 += m_softDisplay.DrawOffset.x;
        y3 += m_softDisplay.DrawOffset.y;
    }

    void fillSoftwareAreaTrans(int16_t x0, int16_t y0, int16_t x1, int16_t y1, uint16_t col);
    void fillSoftwareArea(int16_t x0, int16_t y0, int16_t x1, int16_t y1, uint16_t col);
    template <PCSX::GPU::Shading Shading, bool useCachedDither>
    void drawPoly3i(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int32_t rgb1, int32_t rgb2,
                    int32_t rgb3);
    void drawPoly3G(int16_t x0, int16_t y0, int16_t x1, int16_t y1, int16_t x2, int16_t y2, int32_t rgb1,
                        int32_t rgb2, int32_t rgb3);
    void drawPoly4G(int16_t x0, int16_t y0, int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                        int32_t rgb1, int32_t rgb2, int32_t rgb3, int32_t rgb4);
    template <PCSX::GPU::Shading Shading>
    void drawSoftwareLine(int16_t x0, int16_t y0, int16_t x1, int16_t y1, int32_t rgb0, int32_t rgb1 = 0);

    int16_t m_yMin;
    int16_t m_yMax;

    template <bool useCachedDither>
    void getShadeTransColDither(uint16_t *pdest, int32_t m1, int32_t m2, int32_t m3);
    void getTextureTransColShadeSemi(uint16_t *pdest, uint16_t color);
    void getTextureTransColShadeSemi32(uint32_t *pdest, uint32_t color);
    template <bool useCachedDither>
    void getTextureTransColShadeDither(uint16_t *pdest, uint16_t color, int32_t m1, int32_t m2, int32_t m3);
    void drawPoly3F(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int32_t rgb);
    template <TexMode Tex>
    void drawPoly3T(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1,
                    int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY);
    template <TexMode Tex, bool useCachedDither>
    void drawPoly3TGi(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1,
                      int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY, int32_t col1,
                      int32_t col2, int32_t col3);
    template <TexMode Tex>
    void drawPoly3TG(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1,
                     int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY, int32_t col1,
                     int32_t col2, int32_t col3);
    // Sprite/textured-rectangle rasterizer. Axis-aligned by definition
    // (GP0 0x64-0x67, 0x74-0x77 etc.); 1:1 UV-to-screen step, no fractional
    // edges. The dedicated implementation drops the edge-walker entirely
    // and walks an integer-aligned blit rectangle. Replaces the previous
    // drawPoly4T<Semi> dispatch from the textured-rect path.
    template <TexMode Tex>
    void drawSprite(int16_t x, int16_t y, int16_t w, int16_t h, int16_t u, int16_t v, int16_t clX, int16_t clY);
    // Unified 4-vertex gouraud-textured wrapper. Picks the cached-dither
    // template parameter once based on s_ditherLUT and emits the two
    // PSX-ordered triangles. clX/clY are unused for Direct15 (callers pass
    // 0, 0). See soft.cc.
    template <TexMode Tex>
    void drawPoly4TG(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4,
                     int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4,
                     int16_t ty4, int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col3, int32_t col4);
    // Unified Bresenham line-octant rasterizers. One body handles all four
    // canonical post-dispatch octants per shading mode; the template
    // parameters select major axis, major-axis sign (Y-major only), minor
    // step direction, and the hardware-load-bearing initial-d bias. See
    // the Line namespace block above for the bias-vs-axis contract.
    template <Line::Axis MajorAxis, Line::MajorSign MaSign, Line::MinorSign MiSign, Line::Bias B,
              PCSX::GPU::Shading Shading>
    void drawLineOctant(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1 = 0);
    // Axis-aligned line variants. Iter selects the iteration axis: X for
    // horizontal lines (y is fixed, x walks varStart..varEnd), Y for
    // vertical lines (x is fixed, y walks varStart..varEnd). Callers must
    // pass the range so that varStart <= varEnd; the dispatcher already
    // performs that swap on dispatch.
    template <Line::Axis Iter, PCSX::GPU::Shading Shading>
    void drawAxisLine(int constCoord, int varStart, int varEnd, uint32_t rgb0, uint32_t rgb1 = 0);

    void enableCachedDithering();
    void disableCachedDithering();

  private:
    // Primitive draw-area rejection. Returns true when the primitive should
    // be skipped: either every vertex sits past one edge of the draw rect
    // (so nothing inside the rect can be covered), or the rect itself is
    // degenerate. The caller passes parallel arrays of the primitive's
    // vertex x and y coordinates; N is the vertex count (3 for triangles,
    // 4 for quads). The comparisons use the renderer's m_drawX/Y/W/H rect
    // members directly - the per-primitive bodies that captured these into
    // locals are unaffected because the compiler folds the loads back.
    template <size_t N>
    inline bool primitiveOutsideDrawArea(const int16_t (&xs)[N], const int16_t (&ys)[N]) const {
        if (m_drawY >= m_drawH) return true;
        if (m_drawX >= m_drawW) return true;
        bool allR = true, allD = true, allL = true, allA = true;
        for (size_t i = 0; i < N; i++) {
            if (xs[i] <= m_drawW) allR = false;
            if (ys[i] <= m_drawH) allD = false;
            if (xs[i] >= m_drawX) allL = false;
            if (ys[i] >= m_drawY) allA = false;
        }
        return allR || allD || allL || allA;
    }

    // RasterState builders: capture the renderer's stable per-primitive state
    // into a value type so the inner loops read from a single struct instead
    // of repeatedly dereferencing renderer members.
    //
    // makeBaseRasterState() fills the fields every primitive needs: ABR, the
    // mask-write policy (checkMask + setMask16/32), and the drawSemiTrans
    // toggle. Untextured paths (fills, lines, flat triangles, gouraud
    // triangles without sampling) need nothing more.
    //
    // makeTexturedRasterState<Tex>(drawX, drawY, drawW, drawH, clX, clY)
    // adds the VRAM pointers, the texture window, the texture page base,
    // the draw rect, the per-call modulation factors, and the CLUT pointer.
    // clutP is set to zero for Direct15 (the field is unused), and to
    // `(clY << 10) + clX` for the CLUT4 / CLUT8 modes.
    inline RasterState makeBaseRasterState() const {
        RasterState rs{};
        rs.abr = m_globalTextABR;
        rs.checkMask = m_checkMask;
        rs.setMask16 = m_setMask16;
        rs.setMask32 = m_setMask32;
        rs.drawSemiTrans = m_drawSemiTrans;
        return rs;
    }

    template <TexMode Tex>
    inline RasterState makeTexturedRasterState(int drawX, int drawY, int drawW, int drawH, int clX, int clY) const {
        RasterState rs{};
        rs.vram = m_vram;
        rs.vram16 = m_vram16;
        rs.texWindowX0 = m_textureWindowOffU;
        rs.texWindowY0 = m_textureWindowOffV;
        rs.maskX = m_textureWindowMaskU;
        rs.maskY = m_textureWindowMaskV;
        rs.texBaseX = m_globalTextAddrX;
        rs.texBaseY = m_globalTextAddrY;
        rs.abr = m_globalTextABR;
        rs.drawX = drawX;
        rs.drawY = drawY;
        rs.drawW = drawW;
        rs.drawH = drawH;
        rs.checkMask = m_checkMask;
        rs.setMask16 = m_setMask16;
        rs.setMask32 = m_setMask32;
        rs.drawSemiTrans = m_drawSemiTrans;
        rs.m1 = m_m1;
        rs.m2 = m_m2;
        rs.m3 = m_m3;
        if constexpr (Tex == TexMode::Direct15) {
            rs.clutP = 0;
        } else {
            rs.clutP = (clY << 10) + clX;
        }
        return rs;
    }

    // Unified 3-vertex edge walkers. Four (HasUV, HasRGB) instantiations cover
    // the legacy Flat3 / Shade3 / FlatTextured3 / ShadeTextured3 family. The
    // m_deltaRight{U,V,R,G,B} members below are the X-direction span gradients
    // shared by those triangle walkers.
    template <bool HasUV, bool HasRGB>
    bool setupSections3(const TriInput &in);
    template <bool HasUV, bool HasRGB>
    int leftSection3();
    template <bool HasUV, bool HasRGB>
    int rightSection3();
    template <bool HasUV, bool HasRGB>
    bool nextRow3();

    struct SoftVertex {
        int x, y;
        int u, v;
        int32_t R, G, B;
    };

    SoftVertex m_vtx[4];
    SoftVertex *m_leftArray[4], *m_rightArray[4];
    int m_leftSection, m_rightSection;
    // Per-section row counters. m_*SectionHeight is the down-counter starting
    // at the section's full height; m_*SectionFullHeight is the constant
    // divisor for the per-row recompute formula below.
    int m_leftSectionHeight, m_leftSectionFullHeight;
    int m_rightSectionHeight, m_rightSectionFullHeight;
    // Per-row Y-axis edge state. The section-relative row index is
    // (m_*SectionFullHeight - m_*SectionHeight) after the down-counter has
    // been decremented in nextRow*. The current value is recomputed each row
    // as m_*Start + (int64_t)m_*Diff * row / m_*SectionFullHeight, which is
    // bit-exact against hardware (one truncation per row, no accumulator
    // drift) instead of the legacy +=quotient stepper.
    int m_leftX, m_leftStartX, m_leftDiffX;
    int m_leftU, m_leftStartU, m_leftDiffU;
    int m_leftV, m_leftStartV, m_leftDiffV;
    int m_leftR, m_leftStartR, m_leftDiffR;
    int m_leftG, m_leftStartG, m_leftDiffG;
    int m_leftB, m_leftStartB, m_leftDiffB;
    int m_rightX, m_rightStartX, m_rightDiffX;
    // 3-vert X-direction span gradients: set once by setupSections3 via
    // shl10idiv, read by drawPoly3{T,Gi,TG} as the per-pixel-X stride for
    // texture coordinates and gouraud channels.
    int m_deltaRightU, m_deltaRightV;
    int m_deltaRightR, m_deltaRightG, m_deltaRightB;

    static constexpr inline int shl10idiv(int x, int y) {
        int64_t bi = x;
        bi <<= 10;
        return bi / y;
    }
};

}  // namespace SoftGPU

}  // namespace PCSX
