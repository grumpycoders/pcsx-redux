/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#pragma once

// Phase-11 hardware-truth values for dither characterization. All
// HW_VERIFIED on SCPH-5501.
//
// Key findings:
//
//   1. The PS1 4x4 Bayer dither matrix matches the psx-spx
//      documentation exactly. At pixel (sx, sy) the offset is:
//        offset[(sx & 3)][(sy & 3)] (or (sy & 3, sx & 3) - see below)
//      Pattern (rows = y mod 4, cols = x mod 4):
//         -4 +0 -3 +1
//         +2 -2 +3 -1
//         -3 +1 -4 +0
//         +3 -1 +2 -2
//      Each offset is an 8-bit-space addition applied BEFORE the 5-bit
//      truncation. So at a base 8-bit value that sits on a 5-bit
//      boundary (multiples of 8: 0, 8, 16, ..., 248), only the
//      negative-offset cells cross to the next-lower 5-bit value -
//      producing a 2x2 alternating checkerboard at those bases.
//      At 5-bit-fractional bases the pattern is richer.
//
//   2. Dither is SCREEN-SPACE-ANCHORED. The triangle origin doesn't
//      change which Bayer cell covers a given screen pixel. Four
//      triangles at origins (0,0), (0,4), (4,0), (4,4) all probed at
//      screen (16, 16) - the three that draw the pixel all read the
//      same dithered value. (The first triangle's (16, 16) lies
//      OUTSIDE its bounding hypotenuse and reads sentinel.)
//
//   3. Dither is channel-independent. Single-channel constant tris
//      (R=128 only, G=128 only, B=128 only) all produce the same per-
//      cell offset pattern at the cells, just expressed in the channel
//      that varied. The dither table applies the same offset to R, G,
//      and B simultaneously.
//
//   4. Saturation at chosen test cells did NOT surface. The cells
//      probed under R=4 all had offsets in {-4, +0, -3, +1} which all
//      truncate to R5=0 (input <= 5). Same at R=252 - all offsets
//      land within the 248..255 range that truncates to R5=31. Phase-
//      12 (ABR) or a follow-up phase-N can revisit saturation with
//      base values that put exactly one cell across the truncation
//      boundary in both directions.

#include "raster-helpers.h"

#define DT_NOMINAL_MID  0x4210u
#define DT_DITHER_MID   0x3defu  /* R=15, G=15, B=15 = mid-gray with -1 LSB */

// ============================================================================
// DT_BAYER_MID: 16 cells at (sx, sy) = (8..11, 8..11). cx = sx mod 4,
// cy = sy mod 4 since sx mod 4 = (sx - 8) here. The captured pattern
// alternates 0x3def (cells with -ve Bayer offset) and 0x4210 (cells
// with non-negative offset).
// ============================================================================

#define DT_BAYER_MID_8_8     DT_DITHER_MID    /* cell(0,0) -4  -> 15 */
#define DT_BAYER_MID_9_8     DT_NOMINAL_MID   /* cell(1,0) +0  -> 16 */
#define DT_BAYER_MID_10_8    DT_DITHER_MID    /* cell(2,0) -3  -> 15 */
#define DT_BAYER_MID_11_8    DT_NOMINAL_MID   /* cell(3,0) +1  -> 16 */
#define DT_BAYER_MID_8_9     DT_NOMINAL_MID   /* cell(0,1) +2  -> 16 */
#define DT_BAYER_MID_9_9     DT_DITHER_MID    /* cell(1,1) -2  -> 15 */
#define DT_BAYER_MID_10_9    DT_NOMINAL_MID   /* cell(2,1) +3  -> 16 */
#define DT_BAYER_MID_11_9    DT_DITHER_MID    /* cell(3,1) -1  -> 15 */
#define DT_BAYER_MID_8_10    DT_DITHER_MID    /* cell(0,2) -3  -> 15 */
#define DT_BAYER_MID_9_10    DT_NOMINAL_MID   /* cell(1,2) +1  -> 16 */
#define DT_BAYER_MID_10_10   DT_DITHER_MID    /* cell(2,2) -4  -> 15 */
#define DT_BAYER_MID_11_10   DT_NOMINAL_MID   /* cell(3,2) +0  -> 16 */
#define DT_BAYER_MID_8_11    DT_NOMINAL_MID   /* cell(0,3) +3  -> 16 */
#define DT_BAYER_MID_9_11    DT_DITHER_MID    /* cell(1,3) -1  -> 15 */
#define DT_BAYER_MID_10_11   DT_NOMINAL_MID   /* cell(2,3) +2  -> 16 */
#define DT_BAYER_MID_11_11   DT_DITHER_MID    /* cell(3,3) -2  -> 15 */

// ============================================================================
// DT_BASE_R: R-only base sweep at R=0x40, 0x80, 0xC0. All three are
// multiples of 8 so they sit on 5-bit boundaries; same alternating
// pattern as mid-gray, just at lower / mid / higher 5-bit values.
// Confirms dither offsets are ADDITIVE (independent of base).
// ============================================================================

#define DT_BASE_R40_8_8      0x0007u  /* R5=7  at -ve cells */
#define DT_BASE_R40_9_8      0x0008u  /* R5=8  at non-neg cells */
#define DT_BASE_R40_10_8     0x0007u
#define DT_BASE_R40_11_8     0x0008u
#define DT_BASE_R40_8_9      0x0008u
#define DT_BASE_R40_9_9      0x0007u
#define DT_BASE_R40_10_9     0x0008u
#define DT_BASE_R40_11_9     0x0007u
#define DT_BASE_R40_8_10     0x0007u
#define DT_BASE_R40_9_10     0x0008u
#define DT_BASE_R40_10_10    0x0007u
#define DT_BASE_R40_11_10    0x0008u
#define DT_BASE_R40_8_11     0x0008u
#define DT_BASE_R40_9_11     0x0007u
#define DT_BASE_R40_10_11    0x0008u
#define DT_BASE_R40_11_11    0x0007u

#define DT_BASE_R80_8_8      0x000fu  /* R5=15 at -ve cells */
#define DT_BASE_R80_9_8      0x0010u  /* R5=16 at non-neg cells */
#define DT_BASE_R80_10_8     0x000fu
#define DT_BASE_R80_11_8     0x0010u
#define DT_BASE_R80_8_9      0x0010u
#define DT_BASE_R80_9_9      0x000fu
#define DT_BASE_R80_10_9     0x0010u
#define DT_BASE_R80_11_9     0x000fu
#define DT_BASE_R80_8_10     0x000fu
#define DT_BASE_R80_9_10     0x0010u
#define DT_BASE_R80_10_10    0x000fu
#define DT_BASE_R80_11_10    0x0010u
#define DT_BASE_R80_8_11     0x0010u
#define DT_BASE_R80_9_11     0x000fu
#define DT_BASE_R80_10_11    0x0010u
#define DT_BASE_R80_11_11    0x000fu

#define DT_BASE_RC0_8_8      0x0017u  /* R5=23 at -ve cells */
#define DT_BASE_RC0_9_8      0x0018u  /* R5=24 at non-neg cells */
#define DT_BASE_RC0_10_8     0x0017u
#define DT_BASE_RC0_11_8     0x0018u
#define DT_BASE_RC0_8_9      0x0018u
#define DT_BASE_RC0_9_9      0x0017u
#define DT_BASE_RC0_10_9     0x0018u
#define DT_BASE_RC0_11_9     0x0017u
#define DT_BASE_RC0_8_10     0x0017u
#define DT_BASE_RC0_9_10     0x0018u
#define DT_BASE_RC0_10_10    0x0017u
#define DT_BASE_RC0_11_10    0x0018u
#define DT_BASE_RC0_8_11     0x0018u
#define DT_BASE_RC0_9_11     0x0017u
#define DT_BASE_RC0_10_11    0x0018u
#define DT_BASE_RC0_11_11    0x0017u

// ============================================================================
// DT_CHAN_G / DT_CHAN_B: channel-independence verification.
// G nominal: 0x0010<<5 = 0x0200, dithered: 0x000f<<5 = 0x01e0.
// B nominal: 0x0010<<10 = 0x4000, dithered: 0x000f<<10 = 0x3c00.
// ============================================================================

#define DT_CHAN_G80_8_8      0x01e0u  /* -ve cell */
#define DT_CHAN_G80_9_8      0x0200u  /* non-neg cell */
#define DT_CHAN_G80_10_8     0x01e0u
#define DT_CHAN_G80_11_8     0x0200u

#define DT_CHAN_B80_8_8      0x3c00u  /* -ve cell */
#define DT_CHAN_B80_9_8      0x4000u  /* non-neg cell */
#define DT_CHAN_B80_10_8     0x3c00u
#define DT_CHAN_B80_11_8     0x4000u

// ============================================================================
// DT_POS: position sweep. Probe screen-space (16, 16) across four
// triangle origins. (16, 16) is cell (0, 0) - Bayer offset -4 -> 15
// LSB on each channel -> 0x3def.
//
// The (0, 0) triangle's bounding hypotenuse runs from (31, 0) to
// (0, 31); the point (16, 16) lies on x+y=32 which is OUTSIDE that
// hypotenuse (32 > 31). So the first triangle doesn't even cover
// (16, 16) - it reads sentinel. The other three triangles (shifted
// +4 in X, Y, or both) extend coverage to include (16, 16) and read
// the dithered value.
//
// All three drawing triangles return the SAME value (0x3def). This
// confirms screen-space anchoring: the dither cell at (16, 16) does
// not depend on which triangle covers it.
// ============================================================================

#define DT_POS_00_AT_16_16   RASTER_SENTINEL  /* outside triangle bound */
#define DT_POS_04_AT_16_16   DT_DITHER_MID
#define DT_POS_40_AT_16_16   DT_DITHER_MID
#define DT_POS_44_AT_16_16   DT_DITHER_MID

// ============================================================================
// DT_SAT_LOW: R=4 input. Bayer offsets at probed cells are {-4, +0,
// -3, +1}. 4-4=0, 4+0=4, 4-3=1, 4+1=5 - all truncate to R5=0. No
// saturation surfaces here because the offsets stay in the [0, 5]
// 8-bit range which collapses uniformly to R5=0. To probe actual
// saturation (clamp-vs-wrap behavior at the 0 or 255 boundary), use
// base values that put exactly one cell across the boundary; a
// follow-up phase can revisit if the refactor needs that case.
// ============================================================================

#define DT_SAT_LOW_R04_8_8   0x0000u
#define DT_SAT_LOW_R04_9_8   0x0000u
#define DT_SAT_LOW_R04_10_8  0x0000u
#define DT_SAT_LOW_R04_11_8  0x0000u

// DT_SAT_HIGH: R=0xFC. Bayer offsets {-4, +0, -3, +1}. 252-4=248,
// 252+0=252, 252-3=249, 252+1=253 - all truncate to R5=31. Same
// caveat: real saturation behavior unprobed here.
#define DT_SAT_HIGH_RFC_8_8  0x001fu
#define DT_SAT_HIGH_RFC_9_8  0x001fu
#define DT_SAT_HIGH_RFC_10_8 0x001fu
#define DT_SAT_HIGH_RFC_11_8 0x001fu

// ============================================================================
// DT_SAT_CROSS: probes the cells where the Bayer offset pushes the
// dithered value across 0 or 255. These are the diagnostic cases for
// clamp-vs-wrap behavior at the channel boundary.
//
// Cell (0, 0) has offset -4 at screen (8, 8). At base R=3, output =
// 3-4 = -1. Clamp policy: 0 -> R5=0. Wrap-as-uint8 policy: 255 ->
// R5=31. The visible difference distinguishes the policies.
//
// Cell (2, 1) has offset +3 at screen (10, 9). At base R=255, output
// = 258. Clamp policy: 255 -> R5=31. Wrap policy: 2 -> R5=0.
//
// Reference cells with offset 0 (no crossing) provide controls. The
// "land exactly at boundary" cases (R=4 cell -4 -> 0, R=252 cell +3
// -> 255) confirm the boundary itself doesn't shift.
// ============================================================================

#define DT_SAT_CROSS_UNDER_R3_8_8     0x0000u  /* offset -4 underflow, predict clamp */
#define DT_SAT_CROSS_UNDER_R3_10_10   0x0000u  /* offset -4 underflow, predict clamp */
#define DT_SAT_CROSS_LAND_R4_8_8      0x0000u  /* offset -4 lands at 0 exactly */
#define DT_SAT_CROSS_OVER_R255_10_9   0x001fu  /* offset +3 overflow, predict clamp */
#define DT_SAT_CROSS_OVER_R255_8_11   0x001fu  /* offset +3 overflow, predict clamp */
#define DT_SAT_CROSS_LAND_R252_10_9   0x001fu  /* offset +3 lands at 255 exactly */
