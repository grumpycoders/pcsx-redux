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

// Phase-20 expected hardware-truth values for the affine UV
// row-walk drift sweep.
//
// Five triangles T_LONG_K (K in {1, 3, 5, 8, 16}), identical 10x20
// screen footprint:
//   A=(5, 5)/(0, 0)  B=(15, 5)/(K, 0)  C=(5, 25)/(0, 2K)
// per-axis stride dU/dx = dV/dy = K/10 (same as phase-18). Probes
// at x=7 (column under the vertical AC edge, row-start X always
// integer) and y in {5, 8, 11, 14, 17, 20}. Y=20 is 15 rows below
// the top edge - five rows deeper than the deepest probe in
// phases 17-19.
//
// Predictions under phases-17/18/19 confirmed model
//   u_sampled = floor(u_real + 0.5),  v_sampled = floor(v_real + 0.5)
// with u_real = (K/10) * (x - 5), v_real = (K/10) * (y - 5).
// If hardware's edge walker drifts over long Y traversal, deep
// probes (y=14, 17, 20) surface the deviation.
//
// Texture: phase-17 TEX17. Probe decoding:
//   vram(u, v) = u | (v << 5) | (((u + v) & 31) | 1) << 10
//
// Status markers:
//   HW_VERIFIED    confirmed on SCPH-5501 hardware.
//   HW_TODO        sentinel; this probe is uncaptured.

#include "raster-helpers.h"
#include "texture-fixture-phase17.h"

#define HW_TODO 0xCAFEu

// --------------------------------------------------------------------------
// K=01 (dU/dx = dV/dy = 0.1)
//   u_real(7, *) = 0.2  -> u_sampled = 0
//   v_real(7, y) = 0.1*(y-5): 0.0, 0.3, 0.6, 0.9, 1.2, 1.5 at y=5,8,11,14,17,20
//   v_sampled = floor(v_real + 0.5): 0, 0, 1, 1, 1, 2
// --------------------------------------------------------------------------

#define EXPECT_LONG_K01_Y05 0x0400u /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_LONG_K01_Y08 0x0400u /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_LONG_K01_Y11 0x0420u /* HW_VERIFIED: UV(0, 1) */
#define EXPECT_LONG_K01_Y14 0x0420u /* HW_VERIFIED: UV(0, 1) */
#define EXPECT_LONG_K01_Y17 0x0420u /* HW_VERIFIED: UV(0, 1) */
#define EXPECT_LONG_K01_Y20                                                                                    \
    0x0420u /* HW_VERIFIED: UV(0, 1) - row-walk drift: stride 0.1 truncates to 6553/0x10000 in 16.16, 15 steps \
               under-estimates v_real to 1.4999 (< 1.5), floor(1.9999) = 1 instead of the ideal model's 2 */

// --------------------------------------------------------------------------
// K=03 (dU/dx = dV/dy = 0.3)
//   u_real(7, *) = 0.6  -> u_sampled = 1
//   v_real(7, y) = 0.3*(y-5): 0, 0.9, 1.8, 2.7, 3.6, 4.5
//   v_sampled: 0, 1, 2, 3, 4, 5
// --------------------------------------------------------------------------

#define EXPECT_LONG_K03_Y05 0x0401u /* HW_VERIFIED: UV(1, 0) */
#define EXPECT_LONG_K03_Y08 0x0C21u /* HW_VERIFIED: UV(1, 1) */
#define EXPECT_LONG_K03_Y11 0x0C41u /* HW_VERIFIED: UV(1, 2) */
#define EXPECT_LONG_K03_Y14 0x1461u /* HW_VERIFIED: UV(1, 3) */
#define EXPECT_LONG_K03_Y17 0x1481u /* HW_VERIFIED: UV(1, 4) */
#define EXPECT_LONG_K03_Y20                                                                                            \
    0x1481u /* HW_VERIFIED: UV(1, 4) - row-walk drift: stride 0.3 truncates to 19660/0x10000, 15 steps under-estimates \
               v_real to 4.4997 (< 4.5), floor(4.9997) = 4 instead of the ideal model's 5 */

// --------------------------------------------------------------------------
// K=05 (dU/dx = dV/dy = 0.5)
//   u_real(7, *) = 1.0  -> u_sampled = 1
//   v_real(7, y) = 0.5*(y-5): 0, 1.5, 3.0, 4.5, 6.0, 7.5
//   v_sampled: 0, 2, 3, 5, 6, 8
// --------------------------------------------------------------------------

#define EXPECT_LONG_K05_Y05 0x0401u /* HW_VERIFIED: UV(1, 0) */
#define EXPECT_LONG_K05_Y08 0x0C41u /* HW_VERIFIED: UV(1, 2) */
#define EXPECT_LONG_K05_Y11 0x1461u /* HW_VERIFIED: UV(1, 3) */
#define EXPECT_LONG_K05_Y14 0x1CA1u /* HW_VERIFIED: UV(1, 5) */
#define EXPECT_LONG_K05_Y17 0x1CC1u /* HW_VERIFIED: UV(1, 6) */
#define EXPECT_LONG_K05_Y20 0x2501u /* HW_VERIFIED: UV(1, 8) */

// --------------------------------------------------------------------------
// K=08 (dU/dx = dV/dy = 0.8)
//   u_real(7, *) = 1.6  -> u_sampled = 2
//   v_real(7, y) = 0.8*(y-5): 0, 2.4, 4.8, 7.2, 9.6, 12.0
//   v_sampled: 0, 2, 5, 7, 10, 12
// --------------------------------------------------------------------------

#define EXPECT_LONG_K08_Y05 0x0C02u /* HW_VERIFIED: UV(2, 0) */
#define EXPECT_LONG_K08_Y08 0x1442u /* HW_VERIFIED: UV(2, 2) */
#define EXPECT_LONG_K08_Y11 0x1CA2u /* HW_VERIFIED: UV(2, 5) */
#define EXPECT_LONG_K08_Y14 0x24E2u /* HW_VERIFIED: UV(2, 7) */
#define EXPECT_LONG_K08_Y17 0x3542u /* HW_VERIFIED: UV(2, 10) */
#define EXPECT_LONG_K08_Y20 0x3D82u /* HW_VERIFIED: UV(2, 12) */

// --------------------------------------------------------------------------
// K=16 (dU/dx = dV/dy = 1.6)
//   u_real(7, *) = 3.2  -> u_sampled = 3
//   v_real(7, y) = 1.6*(y-5): 0, 4.8, 9.6, 14.4, 19.2, 24.0
//   v_sampled: 0, 5, 10, 14, 19, 24
// --------------------------------------------------------------------------

#define EXPECT_LONG_K16_Y05 0x0C03u /* HW_VERIFIED: UV(3, 0) */
#define EXPECT_LONG_K16_Y08 0x24A3u /* HW_VERIFIED: UV(3, 5) */
#define EXPECT_LONG_K16_Y11 0x3543u /* HW_VERIFIED: UV(3, 10) */
#define EXPECT_LONG_K16_Y14 0x45C3u /* HW_VERIFIED: UV(3, 14) */
#define EXPECT_LONG_K16_Y17 0x5E63u /* HW_VERIFIED: UV(3, 19) */
#define EXPECT_LONG_K16_Y20 0x6F03u /* HW_VERIFIED: UV(3, 24) */
