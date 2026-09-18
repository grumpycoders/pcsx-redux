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

// Phase-19 expected hardware-truth values for the affine UV
// stride-sign + cross-axis sweep.
//
// Six triangles, identical 10x10 screen footprint to phase-18, varying
// in stride sign and per-axis stride direction:
//
//   T_NEG_U_K05    dU/dx = -0.5            (mirrored U, mild)
//   T_NEG_V_K05    dV/dy = -0.5            (mirrored V, mild)
//   T_NEG_BOTH_K05 dU/dx = -0.5, dV/dy = -0.5
//   T_NEG_U_K16    dU/dx = -1.6            (mirrored U, stretched)
//   T_CROSS_45_K05 45-deg UV rotation      (dU/dx = dU/dy = +/-0.5)
//   T_CROSS_90_K16 90-deg UV rotation, stretched
//                                          (dU/dy = dV/dx = 1.6)
//
// Probes are the same five screen positions as phase-18:
//   P_VERTEX     (5,  5)
//   P_TOP_NEAR   (6,  5)
//   P_LEFT_NEAR  (5,  6)
//   P_INTERIOR   (8,  8)
//   P_TOP_FAR    (12, 5)
//
// Predictions seeded under phase-17/18 model:
//   per-axis u_sampled = floor(u_real(x, y) + 0.5)
//   per-axis v_sampled = floor(v_real(x, y) + 0.5)
// with u_real and v_real evaluated from the affine map. The model
// is direction-symmetric (works for negative stride) and per-axis
// independent (works for cross-axis stride). Phase-19 tests both
// assumptions against silicon.
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
// T_NEG_U_K05: A=(5,5)/(5,0) B=(15,5)/(0,0) C=(5,15)/(5,5)
//   u(x,y) = 7.5 - 0.5*x      v(x,y) = 0.5*y - 2.5
//   P_VERTEX     (5,5)   u=5.0  v=0.0   -> (5, 0)
//   P_TOP_NEAR   (6,5)   u=4.5  v=0.0   -> (5, 0)
//   P_LEFT_NEAR  (5,6)   u=5.0  v=0.5   -> (5, 1)
//   P_INTERIOR   (8,8)   u=3.5  v=1.5   -> (4, 2)
//   P_TOP_FAR    (12,5)  u=1.5  v=0.0   -> (2, 0)
// --------------------------------------------------------------------------

#define EXPECT_NEG_U_K05_VERTEX 0x1405u    /* HW_VERIFIED: UV(5, 0) */
#define EXPECT_NEG_U_K05_TOP_NEAR 0x1405u  /* HW_VERIFIED: UV(5, 0) */
#define EXPECT_NEG_U_K05_LEFT_NEAR 0x1C25u /* HW_VERIFIED: UV(5, 1) */
#define EXPECT_NEG_U_K05_INTERIOR 0x1C44u  /* HW_VERIFIED: UV(4, 2) */
#define EXPECT_NEG_U_K05_TOP_FAR 0x0C02u   /* HW_VERIFIED: UV(2, 0) */

// --------------------------------------------------------------------------
// T_NEG_V_K05: A=(5,5)/(0,5) B=(15,5)/(5,5) C=(5,15)/(0,0)
//   u(x,y) = 0.5*x - 2.5      v(x,y) = 7.5 - 0.5*y
//   P_VERTEX     (5,5)   u=0.0  v=5.0   -> (0, 5)
//   P_TOP_NEAR   (6,5)   u=0.5  v=5.0   -> (1, 5)
//   P_LEFT_NEAR  (5,6)   u=0.0  v=4.5   -> (0, 5)
//   P_INTERIOR   (8,8)   u=1.5  v=3.5   -> (2, 4)
//   P_TOP_FAR    (12,5)  u=3.5  v=5.0   -> (4, 5)
// --------------------------------------------------------------------------

#define EXPECT_NEG_V_K05_VERTEX 0x14A0u    /* HW_VERIFIED: UV(0, 5) */
#define EXPECT_NEG_V_K05_TOP_NEAR 0x1CA1u  /* HW_VERIFIED: UV(1, 5) */
#define EXPECT_NEG_V_K05_LEFT_NEAR 0x14A0u /* HW_VERIFIED: UV(0, 5) */
#define EXPECT_NEG_V_K05_INTERIOR 0x1C82u  /* HW_VERIFIED: UV(2, 4) */
#define EXPECT_NEG_V_K05_TOP_FAR 0x24A4u   /* HW_VERIFIED: UV(4, 5) */

// --------------------------------------------------------------------------
// T_NEG_BOTH_K05: A=(5,5)/(5,5) B=(15,5)/(0,5) C=(5,15)/(5,0)
//   u(x,y) = 7.5 - 0.5*x      v(x,y) = 7.5 - 0.5*y
//   P_VERTEX     (5,5)   u=5.0  v=5.0   -> (5, 5)
//   P_TOP_NEAR   (6,5)   u=4.5  v=5.0   -> (5, 5)
//   P_LEFT_NEAR  (5,6)   u=5.0  v=4.5   -> (5, 5)
//   P_INTERIOR   (8,8)   u=3.5  v=3.5   -> (4, 4)
//   P_TOP_FAR    (12,5)  u=1.5  v=5.0   -> (2, 5)
// --------------------------------------------------------------------------

#define EXPECT_NEG_BOTH_K05_VERTEX 0x2CA5u    /* HW_VERIFIED: UV(5, 5) */
#define EXPECT_NEG_BOTH_K05_TOP_NEAR 0x2CA5u  /* HW_VERIFIED: UV(5, 5) */
#define EXPECT_NEG_BOTH_K05_LEFT_NEAR 0x2CA5u /* HW_VERIFIED: UV(5, 5) */
#define EXPECT_NEG_BOTH_K05_INTERIOR 0x2484u  /* HW_VERIFIED: UV(4, 4) */
#define EXPECT_NEG_BOTH_K05_TOP_FAR 0x1CA2u   /* HW_VERIFIED: UV(2, 5) */

// --------------------------------------------------------------------------
// T_NEG_U_K16: A=(5,5)/(16,0) B=(15,5)/(0,0) C=(5,15)/(16,16)
//   u(x,y) = 24 - 1.6*x       v(x,y) = 1.6*y - 8
//   P_VERTEX     (5,5)   u=16.0   v=0.0    -> (16, 0)
//   P_TOP_NEAR   (6,5)   u=14.4   v=0.0    -> (14, 0)
//   P_LEFT_NEAR  (5,6)   u=16.0   v=1.6    -> (16, 2)
//   P_INTERIOR   (8,8)   u=11.2   v=4.8    -> (11, 5)
//   P_TOP_FAR    (12,5)  u=4.8    v=0.0    -> (5, 0)
// --------------------------------------------------------------------------

#define EXPECT_NEG_U_K16_VERTEX 0x4410u    /* HW_VERIFIED: UV(16, 0) */
#define EXPECT_NEG_U_K16_TOP_NEAR 0x3C0Eu  /* HW_VERIFIED: UV(14, 0) */
#define EXPECT_NEG_U_K16_LEFT_NEAR 0x4C50u /* HW_VERIFIED: UV(16, 2) */
#define EXPECT_NEG_U_K16_INTERIOR 0x44ABu  /* HW_VERIFIED: UV(11, 5) */
#define EXPECT_NEG_U_K16_TOP_FAR 0x1405u   /* HW_VERIFIED: UV(5, 0) */

// --------------------------------------------------------------------------
// T_CROSS_45_K05: A=(5,5)/(5,0) B=(15,5)/(10,5) C=(5,15)/(0,5)
//   u(x,y) = 0.5*x - 0.5*y + 5    v(x,y) = 0.5*x + 0.5*y - 5
//   P_VERTEX     (5,5)   u=5.0  v=0.0   -> (5, 0)
//   P_TOP_NEAR   (6,5)   u=5.5  v=0.5   -> (6, 1)
//   P_LEFT_NEAR  (5,6)   u=4.5  v=0.5   -> (5, 1)
//   P_INTERIOR   (8,8)   u=5.0  v=3.0   -> (5, 3)
//   P_TOP_FAR    (12,5)  u=8.5  v=3.5   -> (9, 4)
// --------------------------------------------------------------------------

#define EXPECT_CROSS_45_K05_VERTEX 0x1405u    /* HW_VERIFIED: UV(5, 0) */
#define EXPECT_CROSS_45_K05_TOP_NEAR 0x1C26u  /* HW_VERIFIED: UV(6, 1) */
#define EXPECT_CROSS_45_K05_LEFT_NEAR 0x1C25u /* HW_VERIFIED: UV(5, 1) */
#define EXPECT_CROSS_45_K05_INTERIOR 0x2465u  /* HW_VERIFIED: UV(5, 3) */
#define EXPECT_CROSS_45_K05_TOP_FAR 0x3489u   /* HW_VERIFIED: UV(9, 4) */

// --------------------------------------------------------------------------
// T_CROSS_90_K16: A=(5,5)/(0,0) B=(15,5)/(0,16) C=(5,15)/(16,0)
//   u(x,y) = 1.6*y - 8        v(x,y) = 1.6*x - 8
//   P_VERTEX     (5,5)   u=0.0    v=0.0     -> (0, 0)
//   P_TOP_NEAR   (6,5)   u=0.0    v=1.6     -> (0, 2)
//   P_LEFT_NEAR  (5,6)   u=1.6    v=0.0     -> (2, 0)
//   P_INTERIOR   (8,8)   u=4.8    v=4.8     -> (5, 5)
//   P_TOP_FAR    (12,5)  u=0.0    v=11.2    -> (0, 11)
// --------------------------------------------------------------------------

#define EXPECT_CROSS_90_K16_VERTEX 0x0400u    /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_CROSS_90_K16_TOP_NEAR 0x0C40u  /* HW_VERIFIED: UV(0, 2) */
#define EXPECT_CROSS_90_K16_LEFT_NEAR 0x0C02u /* HW_VERIFIED: UV(2, 0) */
#define EXPECT_CROSS_90_K16_INTERIOR 0x2CA5u  /* HW_VERIFIED: UV(5, 5) */
#define EXPECT_CROSS_90_K16_TOP_FAR 0x2D60u   /* HW_VERIFIED: UV(0, 11) */
