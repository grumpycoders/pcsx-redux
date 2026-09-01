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

// Phase-7 expected hardware-truth values for gouraud color precision.
//
// All values HW_VERIFIED on real SCPH-5501 by running the binary via
// Unirom + psxup.py and grepping ^OBS lines from the captured serial
// log. Mismatches that surface when the soft renderer runs against
// this oracle are the deliverable - they enumerate the punch list for
// the delta-precision refactor.
//
// Naming: GC = Gouraud Canonical (size 1/2/3 = 8/32/128).
//         GV = Gouraud Vertical R-only sweep.
//         GH = Gouraud Horizontal R-only sweep.
//         GS = Gouraud Saturation / vertex-exactness probes.
//         GD = Gouraud Dither.
//         GO = Gouraud Orientation (vertex-order permutations).
//
// Color encoding: VRAM 5:5:5 with R at bits 4:0, G at bits 9:5, B at
// bits 14:10, mask at bit 15. The GP0(0x30) command word packs vertex
// colors as 8:8:8 with R at bits 7:0, G at bits 15:8, B at bits 23:16
// (rasterCmdColor() shifts 5-bit channel values up by 3 to land in
// command form). Values below are VRAM-side as read back via GP0(0xC0).
//
// Notable HW findings (verified 2026-05-15):
//
//   1. Vertex-exactness: apex pixels of every gouraud triangle land at
//      exactly the apex vertex color. No accumulator-init drift at the
//      origin row.
//
//   2. Vertex-order independence: All six permutations of GC1's three
//      vertices produce identical interior pixel values. The PS1
//      gouraud rasterizer is handedness-free.
//
//   3. Symmetric vertical / horizontal interpolation: identical R-only
//      gradient triangles probed along the left edge (GV) and the top
//      edge (GH) produce identical per-row / per-pixel values for the
//      same N. The two truncating delta paths share their arithmetic.
//
//   4. Large-triangle apex precision: GC3 (128x128) reads (1,1) at
//      R=30 instead of R=31. Tiny offset from apex already shows
//      cross-axis interpolation drift at the 5-bit boundary.
//
//   5. Sub-LSB triangles: a triangle with apex R=1 and base R=0 holds
//      R=1 only at the apex row. By y=2 the per-row 8-bit delta has
//      dropped the accumulator below the 5-bit truncation threshold
//      and all subsequent rows read R=0.
//
//   6. Dither overlay: same canonical 32x32 RGB triangle reads back
//      different per-pixel values under E1[9] = 1, with adjacent
//      pixels' 5-bit channels differing by single LSBs in a stable
//      4-pixel-periodic pattern.

#include "raster-helpers.h"

// --------------------------------------------------------------------------
// GC: Canonical RGB-vertex triangle at three sizes
// --------------------------------------------------------------------------
//
// Layout (size N):
//   v0 = (0, 0)   RASTER_CMD_RED   -> 5:5:5 R=31 G=0  B=0
//   v1 = (N, 0)   RASTER_CMD_GREEN -> 5:5:5 R=0  G=31 B=0
//   v2 = (0, N)   RASTER_CMD_BLUE  -> 5:5:5 R=0  G=0  B=31

// -- GC1: 8x8 -- HW_VERIFIED
#define GC1_V0_R                0x001fu  /* apex (0,0) = pure R */
#define GC1_TOP_X4              0x022du  /* (4,0) R=13 G=17 B=0 - 4/7 along R->G */
#define GC1_LEFT_Y4             0x440du  /* (0,4) R=13 G=0 B=17 - 4/7 along R->B */
#define GC1_INTERIOR_1_1        0x1096u  /* (1,1) interior near apex */
#define GC1_INTERIOR_2_2        0x210du  /* (2,2) interior */
#define GC1_INTERIOR_3_3        0x35a4u  /* (3,3) interior */
#define GC1_INTERIOR_1_3        0x348du  /* (1,3) more B than G */
#define GC1_INTERIOR_3_1        0x11adu  /* (3,1) more G than B */

// -- GC2: 32x32 -- HW_VERIFIED
#define GC2_V0_R                0x001fu  /* apex pure R */
#define GC2_TOP_X16             0x020fu  /* (16,0) midpoint of R->G top edge */
#define GC2_LEFT_Y16            0x400fu  /* (0,16) midpoint of R->B left edge */
#define GC2_INTERIOR_8_8        0x210fu  /* (8,8) interior */
#define GC2_INTERIOR_16_8       0x2207u  /* (16,8) right-of-centroid */
#define GC2_INTERIOR_8_16       0x4107u  /* (8,16) below-centroid */
#define GC2_INTERIOR_1_1        0x043du  /* (1,1) near apex */
#define GC2_INTERIOR_30_0       0x03c1u  /* (30,0) near G vertex */

// -- GC3: 128x128 -- HW_VERIFIED
#define GC3_V0_R                0x001fu  /* apex pure R */
#define GC3_TOP_X64             0x01efu  /* (64,0) ~midpoint R->G */
#define GC3_LEFT_Y64            0x3c0fu  /* (0,64) ~midpoint R->B */
#define GC3_INTERIOR_32_32      0x1cefu  /* (32,32) interior */
#define GC3_INTERIOR_1_1        0x001eu  /* (1,1) - apex drift! R=30 not 31 */
#define GC3_INTERIOR_64_32      0x1de7u  /* (64,32) */
#define GC3_INTERIOR_32_64      0x3ce7u  /* (32,64) */
#define GC3_INTERIOR_96_16      0x0ee3u  /* (96,16) far-right interior */

// --------------------------------------------------------------------------
// GV: Vertical R-only gradient (probes left-edge color accumulator)
// --------------------------------------------------------------------------
//
// Layout: v0=(0,0) R=31, v1=(N,0) R=0, v2=(0,N) R=0. Left edge carries
// R going from 31 -> 0 across N rows. Probe column x=0.

// -- GV3: H=W=3 -- HW_VERIFIED
#define GV3_X0_Y0               0x001fu  /* apex R=31 */
#define GV3_X0_Y1               0x0014u  /* R=20 */
#define GV3_X0_Y2               0x000au  /* R=10 */

// -- GV5: H=W=5 -- HW_VERIFIED
#define GV5_X0_Y0               0x001fu
#define GV5_X0_Y1               0x0018u  /* R=24 */
#define GV5_X0_Y2               0x0012u  /* R=18 */
#define GV5_X0_Y3               0x000cu  /* R=12 */
#define GV5_X0_Y4               0x0006u  /* R=6 */

// -- GV7: H=W=7 -- HW_VERIFIED
// Per-row 8-bit delta truncated; accumulator drift visible vs naive
// (31, 27, 23, 19, 15, 11, 7) - hardware actually steps:
// 31, 26, 22, 17, 13, 8, 4. Floor((R<<3)+accum)/8 at each row.
#define GV7_X0_Y0               0x001fu  /* R=31 */
#define GV7_X0_Y1               0x001au  /* R=26 */
#define GV7_X0_Y2               0x0016u  /* R=22 */
#define GV7_X0_Y3               0x0011u  /* R=17 */
#define GV7_X0_Y4               0x000du  /* R=13 */
#define GV7_X0_Y5               0x0008u  /* R=8 */
#define GV7_X0_Y6               0x0004u  /* R=4 */

// -- GV11: H=W=11 -- HW_VERIFIED
#define GV11_X0_Y0              0x001fu  /* R=31 */
#define GV11_X0_Y2              0x0019u  /* R=25 */
#define GV11_X0_Y4              0x0013u  /* R=19 */
#define GV11_X0_Y6              0x000eu  /* R=14 */
#define GV11_X0_Y8              0x0008u  /* R=8 */
#define GV11_X0_Y10             0x0002u  /* R=2 */

// --------------------------------------------------------------------------
// GH: Horizontal R-only gradient (probes per-pixel-X color delta)
// --------------------------------------------------------------------------
//
// Layout: v0=(0,0) R=31, v1=(N,0) R=0, v2=(0,N) R=31. Left edge stays
// at R=31; top edge interpolates R 31->0 across N columns. Probe row
// y=0. Hardware confirms GV / GH symmetry - identical values per N.

// -- GH3 -- HW_VERIFIED
#define GH3_Y0_X0               0x001fu
#define GH3_Y0_X1               0x0014u
#define GH3_Y0_X2               0x000au

// -- GH5 -- HW_VERIFIED
#define GH5_Y0_X0               0x001fu
#define GH5_Y0_X1               0x0018u
#define GH5_Y0_X2               0x0012u
#define GH5_Y0_X3               0x000cu
#define GH5_Y0_X4               0x0006u

// -- GH7 -- HW_VERIFIED
#define GH7_Y0_X0               0x001fu
#define GH7_Y0_X1               0x001au
#define GH7_Y0_X2               0x0016u
#define GH7_Y0_X3               0x0011u
#define GH7_Y0_X4               0x000du
#define GH7_Y0_X5               0x0008u
#define GH7_Y0_X6               0x0004u

// -- GH11 -- HW_VERIFIED
#define GH11_Y0_X0              0x001fu
#define GH11_Y0_X2              0x0019u
#define GH11_Y0_X4              0x0013u
#define GH11_Y0_X6              0x000eu
#define GH11_Y0_X8              0x0008u
#define GH11_Y0_X10             0x0002u

// --------------------------------------------------------------------------
// GS: Saturation / vertex-exactness probes -- HW_VERIFIED
// --------------------------------------------------------------------------
//
// GS_NEAR_MAX: apex R=31, base R=30. Apex pixel reads exactly R=31;
//   deep interior reads R=30 (the base color). No overshoot.
//
// GS_NEAR_MIN: apex R=0, base R=1. Apex reads R=0; deep interior reads
//   R=0 too - the 5-bit value R=1 lives at 8-bit R=8, but the
//   interpolated 8-bit value never crosses 8 at the probed interior
//   position (4,8). So a 1-LSB-in-5-bit triangle gets quantized away
//   for most of its area.
//
// GS_HALF_OF_LSB: apex R=1, base R=0. R=1 holds only at the apex pixel.
//   By y=2 (and below) the accumulator is below 5-bit threshold and
//   reads R=0. The per-row 8-bit delta is small enough that the 5-bit
//   truncation collapses the gradient to a single bright pixel.

#define GS_NEAR_MAX_APEX        0x001fu
#define GS_NEAR_MAX_INTERIOR    0x001eu
#define GS_NEAR_MIN_APEX        0x0000u
#define GS_NEAR_MIN_INTERIOR    0x0000u
#define GS_HALF_OF_LSB_APEX     0x0001u
#define GS_HALF_OF_LSB_Y2       0x0000u
#define GS_HALF_OF_LSB_Y4       0x0000u
#define GS_HALF_OF_LSB_Y6       0x0000u

// --------------------------------------------------------------------------
// GD: Dither overlay (E1[9] = 1) on the canonical 32x32 RGB triangle.
//     4x4 OBS grid at (8..11, 8..11). -- HW_VERIFIED
// --------------------------------------------------------------------------
//
// The dither table modulates per-pixel rounding direction in a 4-pixel
// repeating pattern. Notice how adjacent pixels' R / G / B channels
// flip by 1-2 LSBs in a stable spatial pattern - the Bayer-style
// signature on real silicon.

#define GD_8_8                  0x1ceeu
#define GD_9_8                  0x212eu
#define GD_10_8                 0x1d2cu
#define GD_11_8                 0x216cu
#define GD_8_9                  0x250eu
#define GD_9_9                  0x210cu
#define GD_10_9                 0x254cu
#define GD_11_9                 0x214au
#define GD_8_10                 0x24ecu
#define GD_9_10                 0x292cu
#define GD_10_10                0x252au
#define GD_11_10                0x296au
#define GD_8_11                 0x2d0cu
#define GD_9_11                 0x290au
#define GD_10_11                0x2d4au
#define GD_11_11                0x2948u

// --------------------------------------------------------------------------
// GO: Vertex-order permutations of GC1. -- HW_VERIFIED
// All six orderings produce identical interior pixels: the PS1
// gouraud rasterizer is order-independent. Aliases inherit GC1 truth.
// --------------------------------------------------------------------------

#define GO_PERM_INTERIOR_2_2    GC1_INTERIOR_2_2
#define GO_PERM_INTERIOR_1_3    GC1_INTERIOR_1_3
