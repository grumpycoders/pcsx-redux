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

#pragma once

#include <stdint.h>

#include "core/gpu.h"

namespace PCSX {

namespace SoftGPU {

// PS1 VRAM geometry. The framebuffer is a fixed 1024x512 halfword grid,
// addressed by `vram16[(y << VRAM_WIDTH_SHIFT) + x]`. The mask constants
// are useful when wrap-mode addressing is needed (uploads, blits) or
// when the address arithmetic carries through a wider type.
//
// CHKMAX_X / CHKMAX_Y in soft.cc are edge-length-limit constants for
// triangle setup; they happen to share these numeric values but are
// semantically distinct - keep them separate.
static constexpr int VRAM_WIDTH = 1024;
static constexpr int VRAM_HEIGHT = 512;
static constexpr int VRAM_WIDTH_SHIFT = 10;
static constexpr uint32_t VRAM_X_MASK = 0x3ff;
static constexpr uint32_t VRAM_Y_MASK = 0x1ff;
// Two 16-bit pixels per 32-bit word; the packed-pair pixel writers
// process this many per inner-loop iteration.
static constexpr int PACKED_PIXELS_PER_WORD = 2;

// 16.16 fixed-point parameters. The soft rasterizer carries edge X
// values and per-row gradients in this format throughout the inner
// loops. FIXED_HALF is the pixel-centre bias hardware uses to decide
// which side of an edge a pixel sits on.
static constexpr int FIXED_SHIFT = 16;
static constexpr int32_t FIXED_ONE = 1 << FIXED_SHIFT;
static constexpr int32_t FIXED_HALF = 1 << (FIXED_SHIFT - 1);
static constexpr int32_t FIXED_MASK = FIXED_ONE - 1;

// Compile-time texture sampling mode for the software rasterizer. Picks the
// per-texel address arithmetic and CLUT lookup form. Selected at primitive
// dispatch after texturePage() resolves the runtime m_globalTextTP value,
// then threaded into the inner loop as a template parameter.
enum class TexMode { None, Clut4, Clut8, Direct15 };

// Per-vertex input for the unified 3-vertex edge-walker setup. The caller
// populates only the fields its template instantiation reads:
//   x[3], y[3] : always required
//   u[3], v[3] : required when HasUV
//   rgb[3]     : required when HasRGB (packed BGR as the GP0 stream provides)
// Unmentioned fields are value-initialized (zero) and never read by the body.
struct TriInput {
    int16_t x[3];
    int16_t y[3];
    int16_t u[3];
    int16_t v[3];
    int32_t rgb[3];
};

// Snapshot of the GP0-derived renderer state that stays stable for the
// duration of a primitive draw. Captured once at primitive entry so the
// inner loops can read from a single value type instead of repeatedly
// dereferencing renderer members. The per-primitive edge state
// (m_leftX, m_deltaLeftX, m_leftU, m_leftV, etc.) is NOT in here; it
// lives on the SoftRenderer instance and is mutated by setupSections*()
// / nextRow*() across the scanline walk.
//
// clutP is only meaningful when the texture mode is Clut4 or Clut8.
struct RasterState {
    uint8_t *vram;        // byte-addressed view of VRAM
    uint16_t *vram16;     // halfword-addressed view of VRAM
    int16_t texWindowX0;  // pre-masked offset bits, `(off_x * 8) & maskX`
    int16_t texWindowY0;  // pre-masked offset bits, `(off_y * 8) & maskY`
    uint16_t maskX;       // mask_x * 8 (which bits of U the window overwrites)
    uint16_t maskY;       // mask_y * 8 (which bits of V the window overwrites)
    int32_t texBaseX;     // m_globalTextAddrX after texturePage()
    int32_t texBaseY;     // m_globalTextAddrY after texturePage()
    GPU::BlendFunction abr;
    int drawX, drawY, drawW, drawH;
    bool checkMask;
    uint16_t setMask16;
    uint32_t setMask32;
    bool drawSemiTrans;
    int16_t m1, m2, m3;
    int32_t clutP;  // (clutY << 10) + clutX; valid for Clut4/Clut8 only

    inline uint16_t *pixel16(int x, int y) const { return &vram16[(y << VRAM_WIDTH_SHIFT) + x]; }
    inline uint32_t *pixelPair32(int x, int y) const { return reinterpret_cast<uint32_t *>(pixel16(x, y)); }
};

// Texture sampler policies, keyed by TexMode. Each specialization exposes
// the same three entry points:
//   yAdjust(rs)             : per-primitive Y-base for the address hoist
//   scalar(rs, yAdj, x, y)  : sample one texel, return final 16-bit pixel
//   packed(rs, yAdj, x, y, dx, dy)
//                           : sample (x,y) and (x+dx, y+dy), pack as 32-bit
//
// The packed pair encoding follows the existing soft GPU convention: the
// first texel sits in the low halfword, the second in the high halfword.
template <TexMode Mode>
struct Sampler;

// Hardware texture-window formula (verified on SCPH-5501 via
// gpu-raster-phase15): `filtered = (raw & ~mask_bits) | offset_bits`,
// where mask_bits = mask_field * 8 and offset_bits is the offset field
// projected through that same mask. Sampler<TexMode> applies the
// substitution before reading VRAM, so the texture-page base is the
// only contribution to the per-primitive yAdjust hoist.
template <>
struct Sampler<TexMode::Clut4> {
    static inline int32_t yAdjust(const RasterState &rs) { return (rs.texBaseY << 11) + (rs.texBaseX << 1); }
    static inline uint16_t scalar(const RasterState &rs, int32_t yAdj, int32_t posX, int32_t posY) {
        const int32_t filteredX = ((posX >> 16) & ~static_cast<int32_t>(rs.maskX)) | rs.texWindowX0;
        const int32_t filteredY = ((posY >> 16) & ~static_cast<int32_t>(rs.maskY)) | rs.texWindowY0;
        const uint8_t raw = rs.vram[(filteredY << 11) + yAdj + (filteredX >> 1)];
        const uint16_t idx = (raw >> ((filteredX & 1) << 2)) & 0xf;
        return rs.vram16[rs.clutP + idx];
    }
    static inline uint32_t packed(const RasterState &rs, int32_t yAdj, int32_t posX, int32_t posY, int32_t difX,
                                  int32_t difY) {
        const uint16_t c1 = scalar(rs, yAdj, posX, posY);
        const uint16_t c2 = scalar(rs, yAdj, posX + difX, posY + difY);
        return static_cast<uint32_t>(c1) | (static_cast<uint32_t>(c2) << 16);
    }
};

template <>
struct Sampler<TexMode::Clut8> {
    static inline int32_t yAdjust(const RasterState &rs) { return (rs.texBaseY << 11) + (rs.texBaseX << 1); }
    static inline uint16_t scalar(const RasterState &rs, int32_t yAdj, int32_t posX, int32_t posY) {
        const int32_t filteredX = ((posX >> 16) & ~static_cast<int32_t>(rs.maskX)) | rs.texWindowX0;
        const int32_t filteredY = ((posY >> 16) & ~static_cast<int32_t>(rs.maskY)) | rs.texWindowY0;
        const uint8_t idx = rs.vram[(filteredY << 11) + yAdj + filteredX];
        return rs.vram16[rs.clutP + idx];
    }
    static inline uint32_t packed(const RasterState &rs, int32_t yAdj, int32_t posX, int32_t posY, int32_t difX,
                                  int32_t difY) {
        const uint16_t c1 = scalar(rs, yAdj, posX, posY);
        const uint16_t c2 = scalar(rs, yAdj, posX + difX, posY + difY);
        return static_cast<uint32_t>(c1) | (static_cast<uint32_t>(c2) << 16);
    }
};

template <>
struct Sampler<TexMode::Direct15> {
    // Direct 15-bit does not use a YAdjust hoist; the per-row address
    // arithmetic folds the texture-page base in inside scalar().
    // Kept for API symmetry with the CLUT specializations.
    static inline int32_t yAdjust(const RasterState &) { return 0; }
    static inline uint16_t scalar(const RasterState &rs, int32_t /*yAdj*/, int32_t posX, int32_t posY) {
        const int32_t filteredX = ((posX >> 16) & ~static_cast<int32_t>(rs.maskX)) | rs.texWindowX0;
        const int32_t filteredY = ((posY >> 16) & ~static_cast<int32_t>(rs.maskY)) | rs.texWindowY0;
        return rs.vram16[(filteredX + rs.texBaseX) + ((filteredY + rs.texBaseY) << 10)];
    }
    static inline uint32_t packed(const RasterState &rs, int32_t yAdj, int32_t posX, int32_t posY, int32_t difX,
                                  int32_t difY) {
        const uint16_t c1 = scalar(rs, yAdj, posX, posY);
        const uint16_t c2 = scalar(rs, yAdj, posX + difX, posY + difY);
        return static_cast<uint32_t>(c1) | (static_cast<uint32_t>(c2) << 16);
    }
};

}  // namespace SoftGPU

}  // namespace PCSX
