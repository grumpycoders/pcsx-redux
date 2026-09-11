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

// Phase-17 expected hardware-truth values for affine UV-mapping
// characterization on SCPH-5501 silicon.
//
// HARDWARE FINDING (refined across rounds, 2026-05-19):
// The 3-vertex textured-triangle sampler uses 16.16 fixed-point edge
// accumulation with a +0x8000 (half-LSB) bias applied before the
// shift-right to integer texel coordinates. This is functionally
// pixel-center sampling: U/V at the row's pixel position equal
// floor((m_leftV + delta * step + 0x8000) >> 16). T2 AR_COMPRESS
// at (10, 7) returning V=1 (not the 0 a pure-truncate-of-0.6 would
// give) is the cleanest probe of this rule: dV/dY = 3/10 per row,
// V_accum at Y=7 in 16.16 is 39320, +0x8000 = 72088, >>16 = 1.
//
// This means phase-8's 4-vert finding ("hardware applies pixel-center
// bias, Redux misses it") wasn't 3-vert-vs-4-vert hardware asymmetry.
// The 3-vert sampler in soft.cc already had the bias; the 4-vert
// sweep was missing it. Both paths converge on the same hardware
// model after the phase-8 fix (commit b89abc47).
//
// Implication for the retire-4-vert-sweep proposal: routing quads
// through (1,3,2)+(0,1,2) triangle decomposition (as untextured +
// gouraud-textured quad paths already do) inherits the 3-vert
// sampler which is already hardware-correct. The 4-vert sweep path
// is structurally redundant with two 3-vert calls - decomposition is
// the simpler form, no special bias mechanics needed. Hardware
// itself decomposes quads to triangles internally, so decomposition
// is also the more silicon-faithful form. This is the data Pixel
// asked for: retiring the 4-vert sweep simplifies code and preserves
// hardware-matching output.
//
// Workflow (since cester's malloc'd error queue caps detailed FAIL
// output around 24 entries, the patch lands in batches):
//   1. Run hardware. Capture first 24 EvaluationError lines.
//   2. Patch HW_TODO -> HW_VERIFIED with captured values.
//   3. Re-run. Now those 24 pass; cester emits details for next 24.
//   4. Repeat until all macros are HW_VERIFIED.
//
// Shape battery (see affine-triangles.c / affine-quads.c):
//
//   Triangles (8):
//     T1 AR_AXIS_BASE       axis-aligned 1:1 sanity
//     T2 AR_COMPRESS        UV span < screen span
//     T3 AR_STRETCH         UV span > screen span
//     T4 AR_TWIST_90        UV axes swapped
//     T5 AR_TWIST_45        UV rotated 45 degrees
//     T6 AR_NATURAL         arbitrary triangle + UV
//     T7 AR_NARROW_TALL     cross-span step dominates  (Round 2 capture)
//     T8 AR_FLAT_WIDE       row edge step dominates    (Round 2 capture)
//
//   Quads (5) - decomposition validation:               (Round 2/3 capture)
//     Q1 AQ_AXIS_BASE       axis-aligned 1:1
//     Q2 AQ_TWIST_90        90 degree UV rotation
//     Q3 AQ_TRAPEZOID       non-parallelogram
//     Q4 AQ_SKEW_NP         skewed (seam-class probe)
//     Q5 AQ_COMPRESS_UV     compressed UV on large quad

#include "raster-helpers.h"
#include "texture-fixture-phase17.h"

#define HW_TODO  0xCAFEu

// --------------------------------------------------------------------------
// T1 AR_AXIS_BASE: A=(5,5)/(0,0)  B=(25,5)/(20,0)  C=(5,15)/(0,10)
// 1:1 UV-to-screen mapping. Sampler at integer pixel = UV(x-5, y-5).
// --------------------------------------------------------------------------

#define EXPECT_AR_AXIS_BASE_10_8    0x2465u  /* HW_VERIFIED: UV(5, 3)  naive  */
#define EXPECT_AR_AXIS_BASE_20_6    0x442Fu  /* HW_VERIFIED: UV(15, 1) naive  */
#define EXPECT_AR_AXIS_BASE_8_12    0x2CE3u  /* HW_VERIFIED: UV(3, 7)  naive  */
#define EXPECT_AR_AXIS_BASE_24_5    0x4C13u  /* HW_VERIFIED: UV(19, 0) top-edge drawn */
#define EXPECT_AR_AXIS_BASE_25_5    RASTER_SENTINEL  /* HW_VERIFIED: B vertex excluded */

// --------------------------------------------------------------------------
// T2 AR_COMPRESS: A=(5,5)/(0,0)  B=(35,5)/(6,0)  C=(5,15)/(0,3)
// dU/dx=0.2, dV/dy=0.3 sub-unit step. HW samples at integer pixel.
// --------------------------------------------------------------------------

#define EXPECT_AR_COMPRESS_10_7     0x0C21u  /* HW_VERIFIED: UV(1, 1) */
#define EXPECT_AR_COMPRESS_20_8     0x1423u  /* HW_VERIFIED: UV(3, 1) */
#define EXPECT_AR_COMPRESS_15_10    0x0C22u  /* HW_VERIFIED: UV(2, 1) */
#define EXPECT_AR_COMPRESS_30_5     0x1405u  /* HW_VERIFIED: UV(5, 0) */

// --------------------------------------------------------------------------
// T3 AR_STRETCH: A=(5,5)/(0,0)  B=(15,5)/(30,0)  C=(5,10)/(0,20)
// dU/dx=3, dV/dy=4 super-unit step. HW exactly naive (no pixel-center
// bias) - probe (6,6) returns UV(3,4), not the (4,6) a pixel-center
// model would produce. Confirms 3-vert naive-sampler rule.
// --------------------------------------------------------------------------

#define EXPECT_AR_STRETCH_6_6       0x1C83u  /* HW_VERIFIED: UV(3, 4)  */
#define EXPECT_AR_STRETCH_10_7      0x5D0Fu  /* HW_VERIFIED: UV(15, 8) */
#define EXPECT_AR_STRETCH_8_8       0x5589u  /* HW_VERIFIED: UV(9, 12) */
#define EXPECT_AR_STRETCH_5_5       0x0400u  /* HW_VERIFIED: UV(0, 0)  A vertex drawn */

// --------------------------------------------------------------------------
// T4 AR_TWIST_90: A=(4,4)/(0,0)  B=(20,4)/(0,16)  C=(4,20)/(16,0)
// UV axes swapped. UV(x, y) = (y - 4, x - 4) inside triangle. Matched
// mechanical pre-run prediction exactly: probe (10,10) -> 0x34C6.
// --------------------------------------------------------------------------

#define EXPECT_AR_TWIST_90_10_10    0x34C6u  /* HW_VERIFIED: UV(6, 6) - pre-run trace match */
#define EXPECT_AR_TWIST_90_6_10     0x2446u  /* HW_VERIFIED: UV(6, 2) */
#define EXPECT_AR_TWIST_90_10_6     0x24C2u  /* HW_VERIFIED: UV(2, 6) */
#define EXPECT_AR_TWIST_90_4_4      0x0400u  /* HW_VERIFIED: UV(0, 0) A vertex drawn */

// --------------------------------------------------------------------------
// T5 AR_TWIST_45: A=(4,4)/(8,0)  B=(20,4)/(16,8)  C=(4,20)/(0,8)
// UV rotated 45 degrees. UV(x, y) = (8 + 0.5(x-y), 0.5(x+y-8)).
// --------------------------------------------------------------------------

#define EXPECT_AR_TWIST_45_12_4     0x448Cu  /* HW_VERIFIED: UV(12, 4) AB mid */
#define EXPECT_AR_TWIST_45_4_12     0x2484u  /* HW_VERIFIED: UV(4, 4)  AC mid */
#define EXPECT_AR_TWIST_45_8_8      0x3488u  /* HW_VERIFIED: UV(8, 4)  interior */
#define EXPECT_AR_TWIST_45_12_12    RASTER_SENTINEL  /* HW_VERIFIED: (12,12) on hypotenuse BC, excluded (top-left rule on right edge) */

// --------------------------------------------------------------------------
// T6 AR_NATURAL: A=(5,5)/(3,2)  B=(25,9)/(20,5)  C=(8,22)/(8,22)
// Arbitrary triangle, arbitrary UV. Affine via inverse linear map.
// --------------------------------------------------------------------------

#define EXPECT_AR_NATURAL_12_10     0x44E9u  /* HW_VERIFIED: UV(9, 7) */
#define EXPECT_AR_NATURAL_18_15     RASTER_SENTINEL  /* HW_VERIFIED: (18,15) outside tri (right of edge BC) */
#define EXPECT_AR_NATURAL_10_18     0x6E29u  /* HW_VERIFIED: UV(9, 17) */
#define EXPECT_AR_NATURAL_5_5       RASTER_SENTINEL  /* HW_VERIFIED: A vertex excluded (top-left rule for non-axis-aligned A) */

// --------------------------------------------------------------------------
// T7 AR_NARROW_TALL: A=(10,4)/(0,0)  B=(14,4)/(20,0)  C=(12,24)/(10,30)
// Tall+thin triangle (4 wide, 20 tall). Cross-span UV step >> row edge step.
// --------------------------------------------------------------------------

#define EXPECT_AR_NARROW_TALL_11_8  0x2CC5u  /* HW_VERIFIED: UV(5, 6) */
#define EXPECT_AR_NARROW_TALL_12_14 0x65EAu  /* HW_VERIFIED: UV(10, 15) */
#define EXPECT_AR_NARROW_TALL_11_20 RASTER_SENTINEL  /* HW_VERIFIED: pixel (11,20) outside narrow tri (left of left edge) */
#define EXPECT_AR_NARROW_TALL_13_6  0x4C6Fu  /* HW_VERIFIED: UV(15, 3) */

// --------------------------------------------------------------------------
// T8 AR_FLAT_WIDE: A=(4,8)/(0,0)  B=(34,9)/(30,0)  C=(4,11)/(0,4)
// Wide+flat triangle (30 wide, 3 tall). Row edge step >> cross-span step.
// --------------------------------------------------------------------------

#define EXPECT_AR_FLAT_WIDE_8_9     0x1424u  /* HW_VERIFIED: UV(4, 1) */
#define EXPECT_AR_FLAT_WIDE_20_9    0x4430u  /* HW_VERIFIED: UV(16, 1) */
#define EXPECT_AR_FLAT_WIDE_30_9    0x6C1Au  /* HW_VERIFIED: UV(26, 0) */
#define EXPECT_AR_FLAT_WIDE_6_10    0x1462u  /* HW_VERIFIED: UV(2, 3) */

// --------------------------------------------------------------------------
// Q1 AQ_AXIS_BASE: v0=(5,5)/(0,0) v1=(20,5)/(15,0) v2=(5,15)/(0,10) v3=(20,15)/(15,10)
// 4-vert flat-textured quad output matches hardware at axis-aligned 1:1.
// --------------------------------------------------------------------------

#define EXPECT_AQ_AXIS_BASE_8_8     0x1C63u  /* HW_VERIFIED: UV(3, 3) */
#define EXPECT_AQ_AXIS_BASE_15_10   0x3CAAu  /* HW_VERIFIED: UV(10, 5) */
#define EXPECT_AQ_AXIS_BASE_5_14    0x2520u  /* HW_VERIFIED: UV(0, 9) */
#define EXPECT_AQ_AXIS_BASE_20_5    RASTER_SENTINEL  /* HW_VERIFIED: v1 column excluded */

// --------------------------------------------------------------------------
// Q2 AQ_TWIST_90: v0=(5,5)/(0,0) v1=(20,5)/(0,15) v2=(5,18)/(13,0) v3=(20,18)/(13,15)
// 90-degree UV rotation. Decomposition's UV interp through the seam.
// --------------------------------------------------------------------------

#define EXPECT_AQ_TWIST_90_8_10     0x2465u  /* HW_VERIFIED: UV(5, 3) */
#define EXPECT_AQ_TWIST_90_15_13    0x4D48u  /* HW_VERIFIED: UV(8, 10) */
#define EXPECT_AQ_TWIST_90_12_8     0x2CE3u  /* HW_VERIFIED: UV(3, 7) near seam */
#define EXPECT_AQ_TWIST_90_12_11    0x34E6u  /* HW_VERIFIED: UV(6, 7) near seam */

// --------------------------------------------------------------------------
// Q3 AQ_TRAPEZOID: v0=(8,5)/(0,0) v1=(20,5)/(15,0) v2=(5,18)/(0,13) v3=(23,18)/(15,13)
// Non-parallelogram. Per-row pixel-count varies linearly.
// --------------------------------------------------------------------------

#define EXPECT_AQ_TRAPEZOID_12_8    0x2466u  /* HW_VERIFIED: UV(6, 3) */
#define EXPECT_AQ_TRAPEZOID_14_13   0x4508u  /* HW_VERIFIED: UV(8, 8) */
#define EXPECT_AQ_TRAPEZOID_8_15    0x3543u  /* HW_VERIFIED: UV(3, 10) */
#define EXPECT_AQ_TRAPEZOID_20_15   0x5D4Du  /* HW_VERIFIED: UV(13, 10) */

// --------------------------------------------------------------------------
// Q4 AQ_SKEW_NP: v0=(5,5)/(0,0) v1=(20,8)/(12,0) v2=(8,22)/(0,12) v3=(25,18)/(12,12)
// Skewed non-parallelogram. Every edge non-axis-aligned. Diagonal seam.
// --------------------------------------------------------------------------

#define EXPECT_AQ_SKEW_NP_12_10     0x2465u  /* HW_VERIFIED: UV(5, 3) */
#define EXPECT_AQ_SKEW_NP_15_14     0x34A7u  /* HW_VERIFIED: UV(7, 5) */
#define EXPECT_AQ_SKEW_NP_10_15     0x2CE3u  /* HW_VERIFIED: UV(3, 7) */
#define EXPECT_AQ_SKEW_NP_18_12     0x3489u  /* HW_VERIFIED: UV(9, 4) along diagonal seam */

// --------------------------------------------------------------------------
// Q5 AQ_COMPRESS_UV: v0=(5,5)/(0,0) v1=(30,5)/(8,0) v2=(5,22)/(0,5) v3=(30,22)/(8,5)
// 25x17 screen -> 8x5 UV. Texture stretched. (Round-3 capture for 3 remain.)
// --------------------------------------------------------------------------

#define EXPECT_AQ_COMPRESS_UV_10_8  0x0C22u  /* HW_VERIFIED: UV(2, 1) */
#define EXPECT_AQ_COMPRESS_UV_20_15 0x2465u  /* HW_VERIFIED: UV(5, 3) */
#define EXPECT_AQ_COMPRESS_UV_15_10 0x1423u  /* HW_VERIFIED: UV(3, 1) */
#define EXPECT_AQ_COMPRESS_UV_29_21 0x34A8u  /* HW_VERIFIED: UV(8, 5) near corner */
