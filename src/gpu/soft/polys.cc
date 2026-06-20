/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

PCSX::SoftGPU::SoftRenderer::SoftRenderer() { resetRenderer(); }

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

template <bool useCachedDither>
void PCSX::SoftGPU::SoftRenderer::applyShadeDither(uint16_t *pdest, int32_t m1, int32_t m2, int32_t m3, bool semiTrans,
                                                   uint16_t sM) {
    int32_t r, g, b;

    if (semiTrans) {
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
        applyDitherCached(pdest, m_vram16, r, b, g, sM);
    } else {
        applyDither(pdest, m_vram16, r, b, g, sM);
    }
}

template <bool useCachedDither>
void PCSX::SoftGPU::SoftRenderer::getShadeTransColDither(uint16_t *pdest, int32_t m1, int32_t m2, int32_t m3) {
    if (m_checkMask && *pdest & 0x8000) return;

    applyShadeDither<useCachedDither>(pdest, m1, m2, m3, m_drawSemiTrans, m_setMask16);
}

template <bool useCachedDither>
void PCSX::SoftGPU::SoftRenderer::getTextureTransColShadeDither(uint16_t *pdest, uint16_t color, int32_t m1, int32_t m2,
                                                                int32_t m3) {
    if (color == 0) return;

    if (m_checkMask && *pdest & 0x8000) return;

    m1 = (((Channel555::R::extractRightAligned(color))) * m1) >> 4;
    m2 = (((Channel555::B::extractRightAligned(color))) * m2) >> 4;
    m3 = (((Channel555::G::extractRightAligned(color))) * m3) >> 4;

    applyShadeDither<useCachedDither>(pdest, m1, m2, m3, m_drawSemiTrans && (color & 0x8000),
                                      m_setMask16 | (color & 0x8000));
}

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
            // Hardware's edge walker accumulates a TRUNCATED 16.16 per-row
            // step (phase-20 verified): m_leftV(row) = m_leftStartV + row *
            // floor(m_leftDiffV / height), not floor(m_leftDiffV * row /
            // height). The two agree when m_leftDiffV/height divides
            // cleanly, but diverge by up to one LSB-per-row otherwise.
            // For strides like 0.1 / 0.3 / 0.8 / 1.6 (none exactly
            // representable in 16.16), the truncation under-estimates the
            // accumulator at deep rows by enough to round v_sampled DOWN
            // where the exact-arithmetic version rounds it up.
            m_leftU = m_leftStartU + (int64_t)row * (m_leftDiffU / height);
            m_leftV = m_leftStartV + (int64_t)row * (m_leftDiffV / height);
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

template <bool HasUV, PCSX::GPU::Shading Shading, PCSX::SoftGPU::TexMode Tex, bool useCachedDither>
void PCSX::SoftGPU::SoftRenderer::drawPoly3Raster(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3,
                                                  int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2,
                                                  int16_t tx3, int16_t ty3, int16_t clX, int16_t clY, int32_t rgb1,
                                                  int32_t rgb2, int32_t rgb3) {
    static constexpr bool HasRGB = Shading == GPU::Shading::Gouraud;

    int i, j, xmin, xmax, ymin, ymax;
    int32_t cR1 = 0, cG1 = 0, cB1 = 0;
    int32_t difR = 0, difG = 0, difB = 0;
    int32_t difX = 0, difY = 0;
    int32_t posX = 0, posY = 0;

    const auto drawX = m_drawX;
    const auto drawY = m_drawY;
    const auto drawH = m_drawH;
    const auto drawW = m_drawW;

    const int16_t rejXs[3] = {x1, x2, x3};
    const int16_t rejYs[3] = {y1, y2, y3};
    if (primitiveOutsideDrawArea(rejXs, rejYs)) return;

    if (!setupSections3<HasUV, HasRGB>(
            TriInput{{x1, x2, x3}, {y1, y2, y3}, {tx1, tx2, tx3}, {ty1, ty2, ty3}, {rgb1, rgb2, rgb3}}))
        return;

    ymax = m_yMax;

    for (ymin = m_yMin; ymin < drawY; ymin++) {
        if (nextRow3<HasUV, HasRGB>()) return;
    }

    RasterState rs = [&]() {
        if constexpr (HasUV) {
            return makeTexturedRasterState<Tex>(drawX, drawY, drawW, drawH, clX, clY);
        } else {
            return makeBaseRasterState();
        }
    }();
    const int32_t yAdj = [&]() {
        if constexpr (HasUV) {
            return Sampler<Tex>::yAdjust(rs);
        } else {
            return 0;
        }
    }();
    const auto vram16 = rs.vram16;

    uint16_t color = 0;
    uint32_t lcolor = 0;
    if constexpr (Shading == GPU::Shading::Flat) {
        color = PCSX::SoftGPU::Channel555::fromCommandColor(rgb1);
        lcolor = m_setMask32 | (((uint32_t)(color)) << 16) | color;
    } else {
        difR = m_deltaRightR;
        difG = m_deltaRightG;
        difB = m_deltaRightB;
    }

    if constexpr (HasUV) {
        difX = m_deltaRightU;
        difY = m_deltaRightV;
    }

    // One scanline-span seed shared by every linearly-interpolated channel:
    // the affine-UV coordinates and, when gouraud, the R/G/B color channels.
    // At the integer pixel xmin the value is the channel at the row's
    // (possibly fractional) left-edge X, stepped up to xmin and rounded with
    // the constant +0x8000 half-LSB bias:
    //
    //   seed = leftVal + (((xmin << 16) - m_leftX) * dif >> 16) + 0x8000
    //
    // Both corrections are hardware-verified and identical for UV and color:
    //   - The ((xmin << 16) - m_leftX) step covers the sub-pixel gap between
    //     the row's fractional left edge and the first integer pixel. It is
    //     ~0 on an axis-aligned (vertical) left edge - hence invisible to the
    //     axis-aligned phase-1/7 suites - but a 1-LSB deficit on a slanted
    //     edge if dropped (HW_VERIFIED: affine UV phase-17..20, slanted
    //     gouraud phase-22).
    //   - The +0x8000 rounds to nearest: the texture-center bias for UV, the
    //     8-bit-accumulator round for color. phase-7 cannot constrain the
    //     color case because its readback truncates 8-bit -> 5-bit (>>3),
    //     absorbing the 8-bit +/-1 except at a multiple of 8; the dense
    //     slanted phase-22 probes pin it on.
    //
    // Coalescing UV and color through this one seed is deliberate: the
    // slanted-gouraud 1-LSB bug fixed just before this refactor was the color
    // seed having lost this exact correction while the UV seed kept it.
    // Sharing the seed makes that divergence impossible.
    const auto seedSpan = [&](int32_t leftVal, int32_t dif) -> int32_t {
        return leftVal + (int32_t)((((int64_t)((int32_t)xmin << 16) - m_leftX) * dif) >> 16) + 0x8000;
    };

    const auto beginSpan = [&]() {
        if constexpr (HasUV) {
            posX = seedSpan(m_leftU, difX);
            posY = seedSpan(m_leftV, difY);
        }
        if constexpr (Shading == GPU::Shading::Gouraud) {
            cR1 = seedSpan(m_leftR, difR);
            cG1 = seedSpan(m_leftG, difG);
            cB1 = seedSpan(m_leftB, difB);
        }
    };

    // Advance every active span channel by `pixels`: the affine-UV
    // coordinates and, when gouraud, the R/G/B color. Used both to skip the
    // left-clipped pixels and to step the per-pixel scanline walk - pixels=1
    // for the 1-wide body, pixels=2 for the 2-wide unrolled body (2 * dif
    // folds to dif << 1, the same arithmetic the old difX2/difR2 precompute
    // did).
    const auto advanceSpan = [&](int pixels) {
        if constexpr (HasUV) {
            posX += pixels * difX;
            posY += pixels * difY;
        }
        if constexpr (Shading == GPU::Shading::Gouraud) {
            cR1 += pixels * difR;
            cG1 += pixels * difG;
            cB1 += pixels * difB;
        }
    };

    if (!m_checkMask && !m_drawSemiTrans && (Shading == GPU::Shading::Flat || !m_ditherMode)) {
        for (i = ymin; i <= ymax; i++) {
            xmin = (m_leftX + 0xffff) >> 16;
            xmax = (m_rightX - 1) >> 16;
            if (drawW < xmax) xmax = drawW;

            if (xmax >= xmin) {
                beginSpan();

                if (xmin < drawX) {
                    j = drawX - xmin;
                    xmin = drawX;
                    advanceSpan(j);
                }

                for (j = xmin; j < xmax; j += 2) {
                    if constexpr (HasUV) {
                        const uint32_t sampled = Sampler<Tex>::packed(rs, yAdj, posX, posY, difX, difY);
                        if constexpr (Shading == GPU::Shading::Flat) {
                            PixelWriter<true, GPU::Shading::Flat, WriteMode::Solid>::packed(rs, j, i, sampled);
                        } else {
                            PixelWriter<true, GPU::Shading::Gouraud, WriteMode::Solid>::packed(
                                rs, j, i, sampled, (cB1 >> 16) | ((cB1 + difB) & 0xff0000),
                                (cG1 >> 16) | ((cG1 + difG) & 0xff0000), (cR1 >> 16) | ((cR1 + difR) & 0xff0000));
                        }
                    } else if constexpr (Shading == GPU::Shading::Flat) {
                        PixelWriter<false, GPU::Shading::Flat, WriteMode::Solid>::packed(rs, j, i, lcolor);
                    } else {
                        const uint32_t packedColor =
                            PCSX::SoftGPU::Channel555::fromHighAlignedRGBPair(cR1, cG1, cB1, difR, difG, difB);
                        PixelWriter<false, GPU::Shading::Gouraud, WriteMode::Solid>::packed(rs, j, i, packedColor);
                    }
                    advanceSpan(2);
                }
                if (j == xmax) {
                    if constexpr (HasUV) {
                        const uint16_t sampled = Sampler<Tex>::scalar(rs, yAdj, posX, posY);
                        if constexpr (Shading == GPU::Shading::Flat) {
                            PixelWriter<true, GPU::Shading::Flat, WriteMode::Solid>::scalar(rs, j, i, sampled);
                        } else {
                            PixelWriter<true, GPU::Shading::Gouraud, WriteMode::Solid>::scalar(
                                rs, j, i, sampled, (cB1 >> 16), (cG1 >> 16), (cR1 >> 16));
                        }
                    } else if constexpr (Shading == GPU::Shading::Flat) {
                        PixelWriter<false, GPU::Shading::Flat, WriteMode::Solid>::scalar(rs, j, i, color);
                    } else {
                        const uint16_t scalarColor = PCSX::SoftGPU::Channel555::fromHighAlignedRGB(cR1, cG1, cB1);
                        PixelWriter<false, GPU::Shading::Gouraud, WriteMode::Solid>::scalar(rs, j, i, scalarColor);
                    }
                }
            }
            if (nextRow3<HasUV, HasRGB>()) return;
        }
        return;
    }

    for (i = ymin; i <= ymax; i++) {
        xmin = (m_leftX + 0xffff) >> 16;
        xmax = (m_rightX - 1) >> 16;
        if (drawW < xmax) xmax = drawW;

        if (xmax >= xmin) {
            beginSpan();

            if (xmin < drawX) {
                j = drawX - xmin;
                xmin = drawX;
                advanceSpan(j);
            }

            if constexpr (Shading == GPU::Shading::Flat) {
                for (j = xmin; j < xmax; j += 2) {
                    if constexpr (HasUV) {
                        const uint32_t sampled = Sampler<Tex>::packed(rs, yAdj, posX, posY, difX, difY);
                        PixelWriter<true, GPU::Shading::Flat, WriteMode::Default>::packed(rs, j, i, sampled);
                    } else {
                        PixelWriter<false, GPU::Shading::Flat, WriteMode::Default>::packed(rs, j, i, lcolor);
                    }
                    advanceSpan(2);
                }
                if (j == xmax) {
                    if constexpr (HasUV) {
                        PixelWriter<true, GPU::Shading::Flat, WriteMode::Default>::scalar(
                            rs, j, i, Sampler<Tex>::scalar(rs, yAdj, posX, posY));
                    } else {
                        PixelWriter<false, GPU::Shading::Flat, WriteMode::Default>::scalar(rs, j, i, color);
                    }
                }
            } else {
                for (j = xmin; j <= xmax; j++) {
                    if constexpr (HasUV) {
                        const uint16_t sampled = Sampler<Tex>::scalar(rs, yAdj, posX, posY);
                        if (m_ditherMode) {
                            getTextureTransColShadeDither<useCachedDither>(&vram16[(i << 10) + j], sampled, (cB1 >> 16),
                                                                           (cG1 >> 16), (cR1 >> 16));
                        } else {
                            PixelWriter<true, GPU::Shading::Gouraud, WriteMode::Default>::scalar(
                                rs, j, i, sampled, (cB1 >> 16), (cG1 >> 16), (cR1 >> 16));
                        }
                    } else {
                        if (m_ditherMode) {
                            getShadeTransColDither<useCachedDither>(&vram16[(i << 10) + j], (cB1 >> 16), (cG1 >> 16),
                                                                    (cR1 >> 16));
                        } else {
                            PixelWriter<false, GPU::Shading::Flat, WriteMode::Default>::scalar(
                                rs, j, i, PCSX::SoftGPU::Channel555::fromHighAlignedRGB(cR1, cG1, cB1));
                        }
                    }
                    advanceSpan(1);
                }
            }
        }
        if (nextRow3<HasUV, HasRGB>()) return;
    }
}

void PCSX::SoftGPU::SoftRenderer::drawPoly3F(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                             int32_t rgb) {
    drawPoly3Raster<false, GPU::Shading::Flat, TexMode::Direct15, false>(x1, y1, x2, y2, x3, y3, 0, 0, 0, 0, 0, 0, 0, 0,
                                                                         rgb, rgb, rgb);
}

void PCSX::SoftGPU::SoftRenderer::drawPoly3G(int16_t x0, int16_t y0, int16_t x1, int16_t y1, int16_t x2, int16_t y2,
                                             int32_t rgb1, int32_t rgb2, int32_t rgb3) {
    if (s_ditherLUT) {
        drawPoly3Raster<false, GPU::Shading::Gouraud, TexMode::Direct15, true>(x0, y0, x1, y1, x2, y2, 0, 0, 0, 0, 0, 0,
                                                                               0, 0, rgb1, rgb2, rgb3);
    } else {
        drawPoly3Raster<false, GPU::Shading::Gouraud, TexMode::Direct15, false>(x0, y0, x1, y1, x2, y2, 0, 0, 0, 0, 0,
                                                                                0, 0, 0, rgb1, rgb2, rgb3);
    }
}

// draw two g-shaded tris for right psx shading emulation

void PCSX::SoftGPU::SoftRenderer::drawPoly4G(int16_t x0, int16_t y0, int16_t x1, int16_t y1, int16_t x2, int16_t y2,
                                             int16_t x3, int16_t y3, int32_t rgb1, int32_t rgb2, int32_t rgb3,
                                             int32_t rgb4) {
    if (s_ditherLUT) {
        drawPoly3Raster<false, GPU::Shading::Gouraud, TexMode::Direct15, true>(x1, y1, x3, y3, x2, y2, 0, 0, 0, 0, 0, 0,
                                                                               0, 0, rgb2, rgb4, rgb3);
        drawPoly3Raster<false, GPU::Shading::Gouraud, TexMode::Direct15, true>(x0, y0, x1, y1, x2, y2, 0, 0, 0, 0, 0, 0,
                                                                               0, 0, rgb1, rgb2, rgb3);
    } else {
        drawPoly3Raster<false, GPU::Shading::Gouraud, TexMode::Direct15, false>(x1, y1, x3, y3, x2, y2, 0, 0, 0, 0, 0,
                                                                                0, 0, 0, rgb2, rgb4, rgb3);
        drawPoly3Raster<false, GPU::Shading::Gouraud, TexMode::Direct15, false>(x0, y0, x1, y1, x2, y2, 0, 0, 0, 0, 0,
                                                                                0, 0, 0, rgb1, rgb2, rgb3);
    }
}

// Unified 3-vertex rasterizer wrappers. The private drawPoly3Raster template
// owns the edge setup, scanline walk, clipping, and fast/slow write split for
// all four 3-vertex polygon quadrants: untextured/textured x flat/gouraud.
template <PCSX::SoftGPU::TexMode Tex>
void PCSX::SoftGPU::SoftRenderer::drawPoly3T(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                             int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                             int16_t ty3, int16_t clX, int16_t clY) {
    drawPoly3Raster<true, GPU::Shading::Flat, Tex, false>(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3, ty3, clX,
                                                          clY, 0, 0, 0);
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

template <PCSX::SoftGPU::TexMode Tex, bool useCachedDither>
void PCSX::SoftGPU::SoftRenderer::drawPoly3TGi(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3,
                                               int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3,
                                               int16_t ty3, int16_t clX, int16_t clY, int32_t col1, int32_t col2,
                                               int32_t col3) {
    drawPoly3Raster<true, GPU::Shading::Gouraud, Tex, useCachedDither>(x1, y1, x2, y2, x3, y3, tx1, ty1, tx2, ty2, tx3,
                                                                       ty3, clX, clY, col1, col2, col3);
}

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
