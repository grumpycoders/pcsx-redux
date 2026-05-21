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
#include "gpu/soft/raster-state.h"

namespace PCSX {

namespace SoftGPU {

// Compile-time write mode for the per-pixel writer policy. Picks which
// branches of the existing pixel-helper family the writer collapses to.
//
//  - Solid:   guaranteed !checkMask && !drawSemiTrans. The fast path
//             writes through with mask/blend disabled. Zero-texel halves
//             of a packed pair preserve the existing destination bits;
//             the source's mask bit gets ORed into the result. Matches
//             the legacy `getTextureTransCol*Solid` helpers.
//  - Default: handles checkMask and drawSemiTrans at runtime by reading
//             RasterState. Matches the legacy `getTextureTransCol*`
//             helpers without the Solid suffix.
//  - Semi:    drawSemiTrans known true at compile time. Matches
//             `getTextureTransColShadeSemi` / `getTextureTransColG32Semi`.
enum class WriteMode { Solid, Default, Semi };

// Saturating helper for packed-pair 5-bit channels.
//
// The packed writers represent one color channel as an int32_t whose two
// 16-bit halfwords each carry a 5-bit value in bits 0..4. The value
// arrives there post-modulate, typically as
//
//     int32_t r = (((color & 0x001f001f) * factor) & 0xff80ff80) >> 7;
//
// which leaves each halfword in 0..0x3f. saturate5Pair clamps each
// halfword to 31: if any of bits 5..14 of a halfword are set, that
// halfword's low five bits become 0x1f. The opposite halfword is
// preserved bit-for-bit. The two halves are tested independently so a
// single helper covers both lanes; the carry behaviour is identical to
// the open-coded six-line pattern this replaces.
struct PackedPair555 {
    static inline int32_t saturate5Pair(int32_t c) {
        if (c & 0x7fe00000) c = 0x1f0000 | (c & 0xffff);
        if (c & 0x7fe0) c = 0x1f | (c & 0xffff0000);
        return c;
    }

    // Compose the final BGR555 packed pair from three right-aligned
    // channels. Each input is a 32-bit value carrying one 5-bit channel
    // value in each halfword (bits 0..4). The output is two consecutive
    // BGR555 pixels: R in bits 0..4, B in bits 5..9, G in bits 10..14.
    static inline uint32_t packBGR(uint32_t r, uint32_t b, uint32_t g) { return (g << 10) | (b << 5) | r; }

    // Lane preservation: "preserveLowHalf(dest, val)" returns the
    // composition that keeps `dest`'s low halfword and takes `val`'s
    // high halfword. preserveHighHalf is the mirror. Used at the end of
    // the packed pixel writers, where a zero source halfword (transparent
    // texel) or a set destination mask bit means the corresponding
    // destination halfword survives unchanged.
    static inline uint32_t preserveLowHalf(uint32_t dest, uint32_t val) { return (dest & 0xffff) | (val & 0xffff0000); }
    static inline uint32_t preserveHighHalf(uint32_t dest, uint32_t val) {
        return (val & 0xffff) | (dest & 0xffff0000);
    }

    // Right-aligned channel extraction from a packed pair. Each helper
    // returns a value whose two halfwords each carry the corresponding
    // channel in bits 0..4. Replaces the legacy X32COL1/2/3 macros.
    static inline uint32_t extractR(uint32_t c) { return c & 0x001f001f; }
    static inline uint32_t extractB(uint32_t c) { return (c >> 5) & 0x001f001f; }
    static inline uint32_t extractG(uint32_t c) { return (c >> 10) & 0x001f001f; }

    // Right-aligned channel extract with bits 0..1 cleared per halfword.
    // The HalfBackAndQuarter blend computes `(F >> 2)`; clearing the
    // low two bits up front keeps the shift lossless. Replaces the
    // legacy X32BCOL1/2/3 macros.
    static inline uint32_t extractRForQuarter(uint32_t c) { return c & 0x001c001c; }
    static inline uint32_t extractBForQuarter(uint32_t c) { return (c >> 5) & 0x001c001c; }
    static inline uint32_t extractGForQuarter(uint32_t c) { return (c >> 10) & 0x001c001c; }

    // Pre-aligned native-position channel for the HalfBackAndHalfFront
    // carry-preserving blend reformulation. Each channel is shifted so
    // the result lands at bits 7..11 of each halfword - the common
    // position where the modulated source can be added in without
    // losing the bit-0 carry that the historical `(B|F) & 0x7bde`
    // shortcut dropped. Replaces the legacy X32TCOL1/2/3 macros.
    static inline uint32_t alignRForHalfBlend(uint32_t c) { return (c & 0x001f001f) << 7; }
    static inline uint32_t alignBForHalfBlend(uint32_t c) { return (c & 0x03e003e0) << 2; }
    static inline uint32_t alignGForHalfBlend(uint32_t c) { return (c & 0x7c007c00) >> 3; }
};

// Native-position channel traits for the BGR555 layout.
//
// The PSX 16-bit pixel layout keeps each colour channel in a fixed
// position: R in bits 0..4, B in bits 5..9, G in bits 10..14, mask in
// bit 15. The scalar pixel writers do per-channel math entirely at
// native position - extract via `color & Mask`, multiply by a 0..255
// modulation factor, shift right by 7, then saturate. The saturate is
// the same shape across all three channels: probe whether any bit
// above the channel's native top is set, and clamp to the channel's
// max value if so.
//
// Channel555::R / B / G expose `mask` (native-position extract /
// max-value) and `saturateNative(c)` (post-multiply clamp). Use the
// channel type for both the extract and the saturate so the two halves
// of the round-trip stay consistent.
namespace Channel555 {

template <uint32_t Mask, uint32_t Overflow, int Shift>
struct Trait {
    static constexpr uint32_t mask = Mask;
    static constexpr uint32_t overflowMask = Overflow;
    static constexpr int shift = Shift;
    static inline int32_t saturateNative(int32_t c) {
        if (c & Overflow) c = Mask;
        return c;
    }
    // Native-position extract: returns the channel still at its source
    // bit range (R: bits 0..4, B: 5..9, G: 10..14). Replaces legacy
    // XCOL1/2/3.
    static inline int32_t extractNative(uint32_t c) { return c & Mask; }
    // Right-aligned extract: shifts the channel down to bits 0..4 so
    // the result is in 0..0x1f regardless of which channel. Replaces
    // legacy XCOL1D/2D/3D.
    static inline int32_t extractRightAligned(uint32_t c) { return (c >> Shift) & 0x1f; }
};

using R = Trait<0x1f, 0x7fffffe0, 0>;
using B = Trait<0x3e0, 0x7ffffc00, 5>;
using G = Trait<0x7c00, 0x7fff8000, 10>;

// Pack three native-position channels into a BGR555 scalar pixel,
// masking each to its own range. Replaces the legacy XPSXCOL macro.
// Argument order matches PackedPair555::packBGR (r, b, g) - the macro
// took (r, g, b), so migrations swap the last two arguments.
inline uint16_t packBGRMasked(int32_t r, int32_t b, int32_t g) {
    return static_cast<uint16_t>((g & 0x7c00) | (b & 0x3e0) | (r & 0x1f));
}

// Convert a GP0 command color word to the software renderer's 15-bit pixel
// layout. The high/middle/low command bytes land in the high/middle/low 5-bit
// pixel fields, matching the legacy soft GPU packing convention.
inline constexpr uint16_t fromCommandColor(uint32_t rgb) {
    return static_cast<uint16_t>(((rgb & 0x00f80000) >> 9) | ((rgb & 0x0000f800) >> 6) | ((rgb & 0x000000f8) >> 3));
}

// Pack high-aligned interpolated channels used by the polygon/line edge
// walkers. R/G/B are kept in the historical 8.16-ish positions so the shifts
// below are part of the rasterizer's bit-exact contract.
inline constexpr uint16_t fromHighAlignedRGB(int32_t r, int32_t g, int32_t b) {
    return static_cast<uint16_t>(((r >> 9) & 0x7c00) | ((g >> 14) & 0x03e0) | ((b >> 19) & 0x001f));
}

inline constexpr uint32_t fromHighAlignedRGBPair(int32_t r, int32_t g, int32_t b, int32_t dr, int32_t dg, int32_t db) {
    return static_cast<uint32_t>(fromHighAlignedRGB(r, g, b)) |
           (static_cast<uint32_t>(fromHighAlignedRGB(r + dr, g + dg, b + db)) << 16);
}

}  // namespace Channel555

// Per-channel hardware blend operations for the four PSX ABR modes.
//
// Each helper expresses one of the GPU's semi-transparent blend
// functions for a single colour channel; the writer call-sites stamp
// the same expression out across R, B, G with channel-specific masks
// and shifts. Modulation is the caller's job (the F argument should
// already be modulated when the source path is textured), so this
// layer doesn't need to know whether the modulation came from
// rs.m1/m2/m3 or per-call m1/m2/m3 or wasn't applied at all.
//
// Two representations are in use:
//   - "right-aligned": both B and F are 5-bit values sitting in bits
//     0..4 of an int32_t. F may carry one or two extra bits from the
//     modulation product (post `>> 7`, peak around 62 for native or
//     124 for the sum of a paired channel). The helper result stays
//     at the same alignment and the caller shifts it back to its
//     native position.
//   - "native-position": B and F sit at the channel's own bit range
//     (R: 0..4, B: 5..9, G: 10..14). The helper result stays at the
//     same range and the caller follows with `Channel555::*::
//     saturateNative` for the overflow clamp.
//
// The runtime dispatch on rs.abr stays inside the writer specialisations;
// these helpers consolidate the blend math without templating the ABR
// axis. Templating ABR at primitive entry is plausible (the rasterizer
// stamps thousands of pixels under a single rs.abr value) but expands
// the code-size matrix to ABR x TexMode x WriteMode x Shading, which
// is a separate architectural decision left for later.
namespace BlendOp {

// HalfBackAndHalfFront: (B + F) / 2 per channel, with the bit-0 carry
// preserved. The historical ((B|F) & 0x7bde) >> 1 shortcut dropped
// that carry; hardware keeps it (SCPH-5501 via gpu-raster-phase12
// abr0_tri_b31_f31). Both inputs right-aligned in bits 0..6; result
// right-aligned in bits 0..5 (caller shifts to native).
inline int32_t halfBackHalfFront(int32_t B, int32_t F) { return (B + F) >> 1; }

// FullBackAndFullFront: B + F per channel; saturates at the channel
// max via the caller's Channel555 trait. Both inputs at native
// position; result lives at the same position and may overflow into
// the channel's overflow region.
inline int32_t fullBackFullFront(int32_t B, int32_t F) { return B + F; }

// FullBackSubFullFront: B - F per channel, clamped to zero on
// underflow. Both inputs at native position; result stays at native
// position with the sign-flip clamp folded in.
inline int32_t fullBackSubFullFront(int32_t B, int32_t F) {
    int32_t v = B - F;
    if (v & 0x80000000) v = 0;
    return v;
}

// HalfBackAndQuarter: B + F/4 per channel. The caller pre-shifts F
// (either as a >> 2 of the raw channel or as a modulation against
// the bits-0..1-cleared extract from PackedPair555::extract*ForQuarter)
// so this layer is a plain addition. Both inputs at native position;
// shares the saturation contract with fullBackFullFront.
inline int32_t halfBackQuarter(int32_t B, int32_t Fquarter) { return B + Fquarter; }

// Packed-pair variant of fullBackSubFullFront. B_pair carries one
// channel's destination value in each halfword at its native bit
// range (e.g. R as `*pdest & 0x001f001f`). F_pair carries the same
// channel post-modulation with the per-halfword overflow bits 5..6
// still set (e.g. the `& 0xff80ff80) >> 7` output for R). The two
// halves are subtracted independently and each clamped to zero on
// underflow; result is the merged pair ready for the next channel
// or the BGR pack. Used in the textured packed semi-transparent
// path where the post-modulation F has both halves populated.
inline int32_t packedFullBackSubFullFront(int32_t B_pair, int32_t F_pair) {
    int32_t hi = (B_pair & 0x001f0000) - (F_pair & 0x003f0000);
    if (hi & 0x80000000) hi = 0;
    int32_t lo = (B_pair & 0x0000001f) - (F_pair & 0x0000003f);
    if (lo & 0x80000000) lo = 0;
    return lo | hi;
}

}  // namespace BlendOp

// Per-pixel writer policy. Each specialization owns both a scalar (one
// 16-bit pixel) and a packed (a 32-bit pair, low halfword first) entry
// point. The packed entry must produce bit-equivalent output to two
// successive scalar entries against the same destination, modulo the
// existing fast-path optimizations the legacy code already encodes.
//
// Specializations exist only for the (Textured, Shading, WriteMode)
// triples that the rasterizer currently exercises. Adding a new one is
// the migration path for the next legacy helper.
template <bool Textured, GPU::Shading Shading, WriteMode WM>
struct PixelWriter;

// Textured, flat-shaded, Solid (!checkMask && !drawSemiTrans).
//
// Matches the legacy `getTextureTransColShadeSolid` (scalar) and
// `getTextureTransColShade32Solid` (pair) member helpers bit for bit.
// Modulation::Off folds in via the neutral 128 coefficients in
// RasterState.m1/m2/m3 (same multiply path as Modulation::On).
template <>
struct PixelWriter<true, GPU::Shading::Flat, WriteMode::Solid> {
    static inline void scalar(const RasterState &rs, int x, int y, uint16_t color) {
        if (color == 0) return;
        uint16_t *pdest = rs.pixel16(x, y);
        const uint16_t l = rs.setMask16 | (color & 0x8000);
        int32_t r = ((color & 0x1f) * rs.m1) >> 7;
        int32_t b = ((color & 0x3e0) * rs.m2) >> 7;
        int32_t g = ((color & 0x7c00) * rs.m3) >> 7;
        r = Channel555::R::saturateNative(r);
        b = Channel555::B::saturateNative(b);
        g = Channel555::G::saturateNative(g);
        *pdest = Channel555::packBGRMasked(r, b, g) | l;
    }

    static inline void packed(const RasterState &rs, int x, int y, uint32_t color) {
        if (color == 0) return;
        uint32_t *pdest = rs.pixelPair32(x, y);
        // Channels are extracted in packed-pair form: bits 0..4 of each
        // halfword for red, 5..9 for blue, 10..14 for green. Multiplying
        // by m1/m2/m3 (0..255) keeps both halves of the int32 valid as
        // long as we mask post-multiply with 0xff80ff80 before the >> 7
        // (otherwise the high half's overflow would bleed into the low
        // half's saturation check).
        int32_t r = (((color & 0x001f001f) * rs.m1) & 0xff80ff80) >> 7;
        int32_t b = ((((color >> 5) & 0x001f001f) * rs.m2) & 0xff80ff80) >> 7;
        int32_t g = ((((color >> 10) & 0x001f001f) * rs.m3) & 0xff80ff80) >> 7;
        r = PackedPair555::saturate5Pair(r);
        b = PackedPair555::saturate5Pair(b);
        g = PackedPair555::saturate5Pair(g);
        const uint32_t flags = rs.setMask32 | (color & 0x80008000);
        const uint32_t packed_rgb = PackedPair555::packBGR(r, b, g);
        // Zero-texel-half preservation: an entirely-zero halfword of the
        // source color means "transparent texel", and the destination
        // halfword keeps its prior value.
        if ((color & 0xffff) == 0) {
            *pdest = PackedPair555::preserveLowHalf(*pdest, packed_rgb | flags);
            return;
        }
        if ((color & 0xffff0000) == 0) {
            *pdest = PackedPair555::preserveHighHalf(*pdest, packed_rgb | flags);
            return;
        }
        *pdest = packed_rgb | flags;
    }
};

// Textured, flat-shaded, Default (runtime checkMask + drawSemiTrans).
//
// Matches the legacy `getTextureTransColShade` (scalar) and
// `getTextureTransColShade32` (pair) member helpers bit for bit.
// Reads checkMask, drawSemiTrans, and abr from RasterState at runtime;
// handles all four BlendFunction cases (HalfBackAndHalfFront,
// FullBackAndFullFront, FullBackSubFullFront, HalfBackAndQuarter).
//
// Semantic differences vs Solid:
//   - scalar honors checkMask via an early return when the destination
//     mask bit is already set
//   - both entry points blend with the destination color when the
//     source mask bit is set and drawSemiTrans is true
//   - packed handles checkMask after the math, with per-halfword
//     destination preservation when the destination's mask bit is set
//     or the corresponding source halfword is zero
template <>
struct PixelWriter<true, GPU::Shading::Flat, WriteMode::Default> {
    static inline void scalar(const RasterState &rs, int x, int y, uint16_t color) {
        if (color == 0) return;
        uint16_t *pdest = rs.pixel16(x, y);
        if (rs.checkMask && *pdest & 0x8000) return;
        const uint16_t l = rs.setMask16 | (color & 0x8000);
        int32_t r, g, b;
        if (rs.drawSemiTrans && (color & 0x8000)) {
            if (rs.abr == GPU::BlendFunction::HalfBackAndHalfFront) {
                const int32_t Br = *pdest & 0x1f;
                const int32_t Bb = (*pdest >> 5) & 0x1f;
                const int32_t Bg = (*pdest >> 10) & 0x1f;
                const int32_t Fr = ((color & 0x1f) * rs.m1) >> 7;
                const int32_t Fb = (((color >> 5) & 0x1f) * rs.m2) >> 7;
                const int32_t Fg = (((color >> 10) & 0x1f) * rs.m3) >> 7;
                r = BlendOp::halfBackHalfFront(Br, Fr);
                b = BlendOp::halfBackHalfFront(Bb, Fb) << 5;
                g = BlendOp::halfBackHalfFront(Bg, Fg) << 10;
            } else if (rs.abr == GPU::BlendFunction::FullBackAndFullFront) {
                r = BlendOp::fullBackFullFront(*pdest & 0x1f, ((color & 0x1f) * rs.m1) >> 7);
                b = BlendOp::fullBackFullFront(*pdest & 0x3e0, ((color & 0x3e0) * rs.m2) >> 7);
                g = BlendOp::fullBackFullFront(*pdest & 0x7c00, ((color & 0x7c00) * rs.m3) >> 7);
            } else if (rs.abr == GPU::BlendFunction::FullBackSubFullFront) {
                r = BlendOp::fullBackSubFullFront(*pdest & 0x1f, ((color & 0x1f) * rs.m1) >> 7);
                b = BlendOp::fullBackSubFullFront(*pdest & 0x3e0, ((color & 0x3e0) * rs.m2) >> 7);
                g = BlendOp::fullBackSubFullFront(*pdest & 0x7c00, ((color & 0x7c00) * rs.m3) >> 7);
            } else {
                r = BlendOp::halfBackQuarter(*pdest & 0x1f, (((color & 0x1f) >> 2) * rs.m1) >> 7);
                b = BlendOp::halfBackQuarter(*pdest & 0x3e0, (((color & 0x3e0) >> 2) * rs.m2) >> 7);
                g = BlendOp::halfBackQuarter(*pdest & 0x7c00, (((color & 0x7c00) >> 2) * rs.m3) >> 7);
            }
        } else {
            r = ((color & 0x1f) * rs.m1) >> 7;
            b = ((color & 0x3e0) * rs.m2) >> 7;
            g = ((color & 0x7c00) * rs.m3) >> 7;
        }
        r = Channel555::R::saturateNative(r);
        b = Channel555::B::saturateNative(b);
        g = Channel555::G::saturateNative(g);
        *pdest = Channel555::packBGRMasked(r, b, g) | l;
    }

    static inline void packed(const RasterState &rs, int x, int y, uint32_t color) {
        if (color == 0) return;
        uint32_t *pdest = rs.pixelPair32(x, y);
        const uint32_t l = rs.setMask32 | (color & 0x80008000);
        int32_t r, g, b;
        if (rs.drawSemiTrans && (color & 0x80008000)) {
            if (rs.abr == GPU::BlendFunction::HalfBackAndHalfFront) {
                // Each channel's destination contribution gets shifted to
                // bits 7..11 of each halfword via alignXForHalfBlend so the
                // modulated source's bit-7 carry survives the post-mask.
                r = ((PackedPair555::alignRForHalfBlend(*pdest) + ((color & 0x001f001f) * rs.m1)) & 0xff00ff00) >> 8;
                b = ((PackedPair555::alignBForHalfBlend(*pdest) + (((color >> 5) & 0x001f001f) * rs.m2)) &
                     0xff00ff00) >>
                    8;
                g = ((PackedPair555::alignGForHalfBlend(*pdest) + (((color >> 10) & 0x001f001f) * rs.m3)) &
                     0xff00ff00) >>
                    8;
            } else if (rs.abr == GPU::BlendFunction::FullBackAndFullFront) {
                r = (*pdest & 0x001f001f) + ((((color & 0x001f001f) * rs.m1) & 0xff80ff80) >> 7);
                b = ((*pdest >> 5) & 0x001f001f) + (((((color >> 5) & 0x001f001f) * rs.m2) & 0xff80ff80) >> 7);
                g = ((*pdest >> 10) & 0x001f001f) + (((((color >> 10) & 0x001f001f) * rs.m3) & 0xff80ff80) >> 7);
            } else if (rs.abr == GPU::BlendFunction::FullBackSubFullFront) {
                r = BlendOp::packedFullBackSubFullFront(*pdest & 0x001f001f,
                                                        (((color & 0x001f001f) * rs.m1) & 0xff80ff80) >> 7);
                b = BlendOp::packedFullBackSubFullFront((*pdest >> 5) & 0x001f001f,
                                                        ((((color >> 5) & 0x001f001f) * rs.m2) & 0xff80ff80) >> 7);
                g = BlendOp::packedFullBackSubFullFront((*pdest >> 10) & 0x001f001f,
                                                        ((((color >> 10) & 0x001f001f) * rs.m3) & 0xff80ff80) >> 7);
            } else {
                // HalfBackAndQuarter: X32BCOL1(color) is color & 0x001c001c
                // (drops bits 0-1 so >> 2 stays lossless).
                r = (*pdest & 0x001f001f) + (((((color & 0x001c001c) >> 2) * rs.m1) & 0xff80ff80) >> 7);
                b = ((*pdest >> 5) & 0x001f001f) + (((((color >> 5) & 0x001c001c) >> 2) * rs.m2) & 0xff80ff80) >> 7;
                g = ((*pdest >> 10) & 0x001f001f) + (((((color >> 10) & 0x001c001c) >> 2) * rs.m3) & 0xff80ff80) >> 7;
            }

            // If only one half of the source has its mask bit set, the other
            // half still needs to be multiplied as if it were a non-blended
            // texel. Patch the corresponding halfword of r/b/g afterwards.
            if (!(color & 0x8000)) {
                r = (r & 0xffff0000) | ((((color & 0x001f001f) * rs.m1) & 0x0000ff80) >> 7);
                b = (b & 0xffff0000) | (((((color >> 5) & 0x001f001f) * rs.m2) & 0x0000ff80) >> 7);
                g = (g & 0xffff0000) | (((((color >> 10) & 0x001f001f) * rs.m3) & 0x0000ff80) >> 7);
            }
            if (!(color & 0x80000000)) {
                r = (r & 0xffff) | ((((color & 0x001f001f) * rs.m1) & 0xFF800000) >> 7);
                b = (b & 0xffff) | (((((color >> 5) & 0x001f001f) * rs.m2) & 0xFF800000) >> 7);
                g = (g & 0xffff) | (((((color >> 10) & 0x001f001f) * rs.m3) & 0xFF800000) >> 7);
            }
        } else {
            r = (((color & 0x001f001f) * rs.m1) & 0xff80ff80) >> 7;
            b = ((((color >> 5) & 0x001f001f) * rs.m2) & 0xff80ff80) >> 7;
            g = ((((color >> 10) & 0x001f001f) * rs.m3) & 0xff80ff80) >> 7;
        }

        r = PackedPair555::saturate5Pair(r);
        b = PackedPair555::saturate5Pair(b);
        g = PackedPair555::saturate5Pair(g);

        const uint32_t packed_rgb = PackedPair555::packBGR(r, b, g);
        if (rs.checkMask) {
            const uint32_t ma = *pdest;
            *pdest = packed_rgb | l;
            if ((color & 0xffff) == 0) *pdest = PackedPair555::preserveHighHalf(*pdest, ma);
            if ((color & 0xffff0000) == 0) *pdest = PackedPair555::preserveLowHalf(*pdest, ma);
            if (ma & 0x80000000) *pdest = PackedPair555::preserveLowHalf(*pdest, ma);
            if (ma & 0x00008000) *pdest = PackedPair555::preserveHighHalf(*pdest, ma);
            return;
        }
        if ((color & 0xffff) == 0) {
            *pdest = PackedPair555::preserveLowHalf(*pdest, packed_rgb | l);
            return;
        }
        if ((color & 0xffff0000) == 0) {
            *pdest = PackedPair555::preserveHighHalf(*pdest, packed_rgb | l);
            return;
        }
        *pdest = packed_rgb | l;
    }
};

// Textured, gouraud-shaded, Solid (!checkMask && !drawSemiTrans && !ditherMode).
//
// Matches the legacy `getTextureTransColShadeXSolid` (scalar) and
// `getTextureTransColShadeX32Solid` (pair) member helpers bit for bit.
// The "X" suffix in the legacy names is the family marker for "modulation
// passed per-call as int16_t m1/m2/m3 args" rather than from
// RasterState.m1/m2/m3 - that's what makes this the Gouraud specialization.
//
// The packed entry takes m1/m2/m3 as int16_t parameters; callers pack the
// gouraud-interpolated integer parts of two consecutive pixels via
// `(c >> 16) | ((c + dif) & 0xff0000)`. Sign-extension during the int16_t
// promotion drops the high half, so both pixels of a packed pair end up
// using the first pixel's modulation - a documented PS1-emulation
// approximation also present in the legacy helpers.
template <>
struct PixelWriter<true, GPU::Shading::Gouraud, WriteMode::Solid> {
    static inline void scalar(const RasterState &rs, int x, int y, uint16_t color, int16_t m1, int16_t m2, int16_t m3) {
        if (color == 0) return;
        uint16_t *pdest = rs.pixel16(x, y);
        int32_t r = ((color & 0x1f) * m1) >> 7;
        int32_t b = ((color & 0x3e0) * m2) >> 7;
        int32_t g = ((color & 0x7c00) * m3) >> 7;
        r = Channel555::R::saturateNative(r);
        b = Channel555::B::saturateNative(b);
        g = Channel555::G::saturateNative(g);
        *pdest = Channel555::packBGRMasked(r, b, g) | rs.setMask16 | (color & 0x8000);
    }

    static inline void packed(const RasterState &rs, int x, int y, uint32_t color, int16_t m1, int16_t m2, int16_t m3) {
        if (color == 0) return;
        uint32_t *pdest = rs.pixelPair32(x, y);
        int32_t r = (((color & 0x001f001f) * m1) & 0xff80ff80) >> 7;
        int32_t b = ((((color >> 5) & 0x001f001f) * m2) & 0xff80ff80) >> 7;
        int32_t g = ((((color >> 10) & 0x001f001f) * m3) & 0xff80ff80) >> 7;
        r = PackedPair555::saturate5Pair(r);
        b = PackedPair555::saturate5Pair(b);
        g = PackedPair555::saturate5Pair(g);
        const uint32_t flags = rs.setMask32 | (color & 0x80008000);
        const uint32_t packed_rgb = PackedPair555::packBGR(r, b, g);
        if ((color & 0xffff) == 0) {
            *pdest = PackedPair555::preserveLowHalf(*pdest, packed_rgb | flags);
            return;
        }
        if ((color & 0xffff0000) == 0) {
            *pdest = PackedPair555::preserveHighHalf(*pdest, packed_rgb | flags);
            return;
        }
        *pdest = packed_rgb | flags;
    }
};

// Textured, gouraud-shaded, Default (runtime checkMask + drawSemiTrans, no
// dither). Matches the legacy `getTextureTransColShadeX` (scalar) member
// helper bit for bit. Only a scalar entry point is provided because the
// gouraud slow path iterates one pixel at a time (color interpolation
// changes per pixel, the packed-pair fast path is unavailable for it).
//
// The dithered variant (matching `getTextureTransColShadeXDither`) lives in
// a separate Dither specialization because it operates on a different
// channel representation (right-aligned 8-bit channels via XCOL1D/2D/3D vs
// the native-position channels here) and dispatches through
// applyDither/applyDitherCached for the final write.
template <>
struct PixelWriter<true, GPU::Shading::Gouraud, WriteMode::Default> {
    static inline void scalar(const RasterState &rs, int x, int y, uint16_t color, int16_t m1, int16_t m2, int16_t m3) {
        if (color == 0) return;
        uint16_t *pdest = rs.pixel16(x, y);
        if (rs.checkMask && *pdest & 0x8000) return;
        const uint16_t l = rs.setMask16 | (color & 0x8000);
        int32_t r, g, b;
        if (rs.drawSemiTrans && (color & 0x8000)) {
            if (rs.abr == GPU::BlendFunction::HalfBackAndHalfFront) {
                const int32_t Br = *pdest & 0x1f;
                const int32_t Bb = (*pdest >> 5) & 0x1f;
                const int32_t Bg = (*pdest >> 10) & 0x1f;
                const int32_t Fr = ((color & 0x1f) * m1) >> 7;
                const int32_t Fb = (((color >> 5) & 0x1f) * m2) >> 7;
                const int32_t Fg = (((color >> 10) & 0x1f) * m3) >> 7;
                r = BlendOp::halfBackHalfFront(Br, Fr);
                b = BlendOp::halfBackHalfFront(Bb, Fb) << 5;
                g = BlendOp::halfBackHalfFront(Bg, Fg) << 10;
            } else if (rs.abr == GPU::BlendFunction::FullBackAndFullFront) {
                r = BlendOp::fullBackFullFront(*pdest & 0x1f, ((color & 0x1f) * m1) >> 7);
                b = BlendOp::fullBackFullFront(*pdest & 0x3e0, ((color & 0x3e0) * m2) >> 7);
                g = BlendOp::fullBackFullFront(*pdest & 0x7c00, ((color & 0x7c00) * m3) >> 7);
            } else if (rs.abr == GPU::BlendFunction::FullBackSubFullFront) {
                r = BlendOp::fullBackSubFullFront(*pdest & 0x1f, ((color & 0x1f) * m1) >> 7);
                b = BlendOp::fullBackSubFullFront(*pdest & 0x3e0, ((color & 0x3e0) * m2) >> 7);
                g = BlendOp::fullBackSubFullFront(*pdest & 0x7c00, ((color & 0x7c00) * m3) >> 7);
            } else {
                r = BlendOp::halfBackQuarter(*pdest & 0x1f, (((color & 0x1f) >> 2) * m1) >> 7);
                b = BlendOp::halfBackQuarter(*pdest & 0x3e0, (((color & 0x3e0) >> 2) * m2) >> 7);
                g = BlendOp::halfBackQuarter(*pdest & 0x7c00, (((color & 0x7c00) >> 2) * m3) >> 7);
            }
        } else {
            r = ((color & 0x1f) * m1) >> 7;
            b = ((color & 0x3e0) * m2) >> 7;
            g = ((color & 0x7c00) * m3) >> 7;
        }
        r = Channel555::R::saturateNative(r);
        b = Channel555::B::saturateNative(b);
        g = Channel555::G::saturateNative(g);
        *pdest = Channel555::packBGRMasked(r, b, g) | l;
    }
};

// Untextured, Solid (!checkMask && !drawSemiTrans).
//
// The untextured fast paths already compute final BGR555 colors before
// calling the writer: flat primitives pass the primitive color, and gouraud
// primitives pass the interpolated color. Solid mode only ORs in the mask
// write bit and stores the scalar or packed pair.
template <GPU::Shading Shading>
struct PixelWriter<false, Shading, WriteMode::Solid> {
    static inline void scalar(const RasterState &rs, int x, int y, uint16_t color) {
        *rs.pixel16(x, y) = color | rs.setMask16;
    }

    static inline void packed(const RasterState &rs, int x, int y, uint32_t color) {
        *rs.pixelPair32(x, y) = color | rs.setMask32;
    }
};

// Untextured, flat-shaded, Default (runtime checkMask + drawSemiTrans).
//
// Matches the legacy `getShadeTransCol` (scalar) and `getShadeTransCol32`
// (pair) member helpers bit for bit. Used by the untextured paths -
// drawPoly3F (flat triangle, slow path) and the line / fill / sprite
// helpers - where there is no texture sampler and `color` is the
// primitive's solid color, optionally blended with the destination on
// drawSemiTrans.
//
// No Modulation here: untextured writes the color through unchanged
// (modulation::On for an untextured primitive in the legacy code path
// is a no-op; the primitive's color word IS the final color). No
// modulation factors are consulted; the channel multiplies that the
// textured writers do are absent.
template <>
struct PixelWriter<false, GPU::Shading::Flat, WriteMode::Default> {
    static inline void scalar(const RasterState &rs, int x, int y, uint16_t color) {
        uint16_t *pdest = rs.pixel16(x, y);
        if (rs.checkMask && *pdest & 0x8000) return;
        if (rs.drawSemiTrans) {
            int32_t r, g, b;
            if (rs.abr == GPU::BlendFunction::HalfBackAndHalfFront) {
                const int32_t Br = *pdest & 0x1f;
                const int32_t Bb = (*pdest >> 5) & 0x1f;
                const int32_t Bg = (*pdest >> 10) & 0x1f;
                const int32_t Fr = color & 0x1f;
                const int32_t Fb = (color >> 5) & 0x1f;
                const int32_t Fg = (color >> 10) & 0x1f;
                r = BlendOp::halfBackHalfFront(Br, Fr);
                b = BlendOp::halfBackHalfFront(Bb, Fb) << 5;
                g = BlendOp::halfBackHalfFront(Bg, Fg) << 10;
            } else if (rs.abr == GPU::BlendFunction::FullBackAndFullFront) {
                r = BlendOp::fullBackFullFront(*pdest & 0x1f, color & 0x1f);
                b = BlendOp::fullBackFullFront(*pdest & 0x3e0, color & 0x3e0);
                g = BlendOp::fullBackFullFront(*pdest & 0x7c00, color & 0x7c00);
            } else if (rs.abr == GPU::BlendFunction::FullBackSubFullFront) {
                r = BlendOp::fullBackSubFullFront(*pdest & 0x1f, color & 0x1f);
                b = BlendOp::fullBackSubFullFront(*pdest & 0x3e0, color & 0x3e0);
                g = BlendOp::fullBackSubFullFront(*pdest & 0x7c00, color & 0x7c00);
            } else {
                r = BlendOp::halfBackQuarter(*pdest & 0x1f, (color & 0x1f) >> 2);
                b = BlendOp::halfBackQuarter(*pdest & 0x3e0, (color & 0x3e0) >> 2);
                g = BlendOp::halfBackQuarter(*pdest & 0x7c00, (color & 0x7c00) >> 2);
            }
            r = Channel555::R::saturateNative(r);
            b = Channel555::B::saturateNative(b);
            g = Channel555::G::saturateNative(g);
            *pdest = Channel555::packBGRMasked(r, b, g) | rs.setMask16;
        } else {
            *pdest = color | rs.setMask16;
        }
    }

    static inline void packed(const RasterState &rs, int x, int y, uint32_t color) {
        uint32_t *pdest = rs.pixelPair32(x, y);
        if (rs.drawSemiTrans) {
            int32_t r, g, b;
            if (rs.abr == GPU::BlendFunction::HalfBackAndHalfFront) {
                // Per-channel (B + F) / 2 across the two packed pixels.
                // Replaces the legacy `((p|color) & 0x7bde7bde) >> 1`
                // shortcut, which dropped each channel's bit-0 carry.
                // Hardware preserves it (phase-12 abr0_tri_b31_f31).
                const uint32_t Br = *pdest & 0x001f001f;
                const uint32_t Bb = (*pdest >> 5) & 0x001f001f;
                const uint32_t Bg = (*pdest >> 10) & 0x001f001f;
                const uint32_t Fr = color & 0x001f001f;
                const uint32_t Fb = (color >> 5) & 0x001f001f;
                const uint32_t Fg = (color >> 10) & 0x001f001f;
                if (!rs.checkMask) {
                    const uint32_t hr = ((Br + Fr) >> 1) & 0x001f001f;
                    const uint32_t hb = ((Bb + Fb) >> 1) & 0x001f001f;
                    const uint32_t hg = ((Bg + Fg) >> 1) & 0x001f001f;
                    *pdest = (hg << 10) | (hb << 5) | hr | rs.setMask32;
                    return;
                }
                r = ((Br + Fr) >> 1) & 0x001f001f;
                b = ((Bb + Fb) >> 1) & 0x001f001f;
                g = ((Bg + Fg) >> 1) & 0x001f001f;
            } else if (rs.abr == GPU::BlendFunction::FullBackAndFullFront) {
                r = (*pdest & 0x001f001f) + (color & 0x001f001f);
                b = ((*pdest >> 5) & 0x001f001f) + ((color >> 5) & 0x001f001f);
                g = ((*pdest >> 10) & 0x001f001f) + ((color >> 10) & 0x001f001f);
            } else if (rs.abr == GPU::BlendFunction::FullBackSubFullFront) {
                int32_t sr, sb, sg, src, sbc, sgc, c;
                src = color & 0x1f;
                sbc = color & 0x3e0;
                sgc = color & 0x7c00;
                c = (*pdest) >> 16;
                sr = (c & 0x1f) - src;
                if (sr & 0x8000) sr = 0;
                sb = (c & 0x3e0) - sbc;
                if (sb & 0x8000) sb = 0;
                sg = (c & 0x7c00) - sgc;
                if (sg & 0x8000) sg = 0;
                r = ((int32_t)sr) << 16;
                b = ((int32_t)sb) << 11;
                g = ((int32_t)sg) << 6;
                c = (*pdest) & 0xffff;
                sr = (c & 0x1f) - src;
                if (sr & 0x8000) sr = 0;
                sb = (c & 0x3e0) - sbc;
                if (sb & 0x8000) sb = 0;
                sg = (c & 0x7c00) - sgc;
                if (sg & 0x8000) sg = 0;
                r |= sr;
                b |= sb >> 5;
                g |= sg >> 10;
            } else {
                // HalfBackAndQuarter: X32BCOL1 = (x & 0x001c001c). Drops bits 0-1 so >> 2 stays lossless.
                r = (*pdest & 0x001f001f) + ((color & 0x001c001c) >> 2);
                b = ((*pdest >> 5) & 0x001f001f) + (((color >> 5) & 0x001c001c) >> 2);
                g = ((*pdest >> 10) & 0x001f001f) + (((color >> 10) & 0x001c001c) >> 2);
            }
            r = PackedPair555::saturate5Pair(r);
            b = PackedPair555::saturate5Pair(b);
            g = PackedPair555::saturate5Pair(g);
            const uint32_t packed_rgb = PackedPair555::packBGR(r, b, g);
            if (rs.checkMask) {
                const uint32_t ma = *pdest;
                *pdest = packed_rgb | rs.setMask32;
                if (ma & 0x80000000) *pdest = PackedPair555::preserveLowHalf(*pdest, ma);
                if (ma & 0x00008000) *pdest = PackedPair555::preserveHighHalf(*pdest, ma);
                return;
            }
            *pdest = packed_rgb | rs.setMask32;
        } else {
            if (rs.checkMask) {
                const uint32_t ma = *pdest;
                *pdest = color | rs.setMask32;
                if (ma & 0x80000000) *pdest = PackedPair555::preserveLowHalf(*pdest, ma);
                if (ma & 0x00008000) *pdest = PackedPair555::preserveHighHalf(*pdest, ma);
                return;
            }
            *pdest = color | rs.setMask32;
        }
    }
};

}  // namespace SoftGPU

}  // namespace PCSX
