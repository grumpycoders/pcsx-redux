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

// Phase-18 expected hardware-truth values for the affine UV
// stride-magnitude sweep.
//
// Triangle T_AXIS_K is A=(5, 5)/(0, 0)  B=(15, 5)/(K, 0)  C=(5, 15)/(0, K).
// Per-axis stride dU/dx = dV/dy = K/10. Probes are five fixed screen
// positions shared across all K:
//
//   P_VERTEX     (5,  5)   u_real = 0,      v_real = 0
//   P_TOP_NEAR   (6,  5)   u_real = K/10,   v_real = 0
//   P_LEFT_NEAR  (5,  6)   u_real = 0,      v_real = K/10
//   P_INTERIOR   (8,  8)   u_real = 3K/10,  v_real = 3K/10
//   P_TOP_FAR    (12, 5)   u_real = 7K/10,  v_real = 0
//
// Bias model (phase-17 HARDWARE FINDING, phase-18 confirmed):
//   u_sampled = ((u_real << 16) + 0x8000) >> 16 = floor(u_real + 0.5)
// i.e. constant +0.5 LSB bias before truncate-to-int, independent of
// dU/dx magnitude. Phase-17 confirmed this at AR_COMPRESS (dV/dy=0.3)
// and AR_STRETCH (dU/dx=3). Phase-18 widens the K sweep to
// K in {1, 2, 3, 5, 8, 16}; SCPH-5501 returned 30/30 matching the
// model's predictions, so the bias is uniform across per-axis
// stride magnitudes covering 0.1 .. 1.6 texels-per-screen-pixel.
//
// Texture: phase-17 TEX17 32x32 signature texture, texel(u, v) =
// vram555(u, v, ((u+v)&31)|1). So expected VRAM at sampled (u, v):
//   vram(u, v) = u | (v << 5) | (((u+v)&31)|1) << 10
// Sample table (u, v) -> vram:
//   (0, 0) -> 0x0400
//   (1, 0) -> 0x0401
//   (0, 1) -> 0x0420
//   (1, 1) -> 0x0C21
//   (2, 0) -> 0x0C02
//   (0, 2) -> 0x0C40
//   (2, 2) -> 0x1442
//   (4, 0) -> 0x1404
//   (5, 5) -> 0x2CA5
//   (6, 0) -> 0x1C06
//   (11, 0) -> 0x2C0B
//
// Status markers:
//   HW_VERIFIED    confirmed on SCPH-5501 hardware.
//   HW_TODO        sentinel; this probe is uncaptured.

#include "raster-helpers.h"
#include "texture-fixture-phase17.h"

#define HW_TODO 0xCAFEu

// --------------------------------------------------------------------------
// K=1   (stride 0.1)
//   P_VERTEX     u_real=0.0  v_real=0.0  -> (0, 0)
//   P_TOP_NEAR   u_real=0.1  v_real=0.0  -> (0, 0)
//   P_LEFT_NEAR  u_real=0.0  v_real=0.1  -> (0, 0)
//   P_INTERIOR   u_real=0.3  v_real=0.3  -> (0, 0)
//   P_TOP_FAR    u_real=0.7  v_real=0.0  -> (1, 0)
// --------------------------------------------------------------------------

#define EXPECT_K01_VERTEX 0x0400u    /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_K01_TOP_NEAR 0x0400u  /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_K01_LEFT_NEAR 0x0400u /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_K01_INTERIOR 0x0400u  /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_K01_TOP_FAR 0x0401u   /* HW_VERIFIED: UV(1, 0) */

// --------------------------------------------------------------------------
// K=2   (stride 0.2)
//   P_VERTEX     u_real=0.0  v_real=0.0  -> (0, 0)
//   P_TOP_NEAR   u_real=0.2  v_real=0.0  -> (0, 0)
//   P_LEFT_NEAR  u_real=0.0  v_real=0.2  -> (0, 0)
//   P_INTERIOR   u_real=0.6  v_real=0.6  -> (1, 1)
//   P_TOP_FAR    u_real=1.4  v_real=0.0  -> (1, 0)
// --------------------------------------------------------------------------

#define EXPECT_K02_VERTEX 0x0400u    /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_K02_TOP_NEAR 0x0400u  /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_K02_LEFT_NEAR 0x0400u /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_K02_INTERIOR 0x0C21u  /* HW_VERIFIED: UV(1, 1) */
#define EXPECT_K02_TOP_FAR 0x0401u   /* HW_VERIFIED: UV(1, 0) */

// --------------------------------------------------------------------------
// K=3   (stride 0.3)
//   P_VERTEX     u_real=0.0  v_real=0.0  -> (0, 0)
//   P_TOP_NEAR   u_real=0.3  v_real=0.0  -> (0, 0)
//   P_LEFT_NEAR  u_real=0.0  v_real=0.3  -> (0, 0)
//   P_INTERIOR   u_real=0.9  v_real=0.9  -> (1, 1)
//   P_TOP_FAR    u_real=2.1  v_real=0.0  -> (2, 0)
// --------------------------------------------------------------------------

#define EXPECT_K03_VERTEX 0x0400u    /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_K03_TOP_NEAR 0x0400u  /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_K03_LEFT_NEAR 0x0400u /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_K03_INTERIOR 0x0C21u  /* HW_VERIFIED: UV(1, 1) */
#define EXPECT_K03_TOP_FAR 0x0C02u   /* HW_VERIFIED: UV(2, 0) */

// --------------------------------------------------------------------------
// K=5   (stride 0.5 - right at the half-step boundary)
//   P_VERTEX     u_real=0.0  v_real=0.0  -> (0, 0)
//   P_TOP_NEAR   u_real=0.5  v_real=0.0  -> (1, 0)
//   P_LEFT_NEAR  u_real=0.0  v_real=0.5  -> (0, 1)
//   P_INTERIOR   u_real=1.5  v_real=1.5  -> (2, 2)
//   P_TOP_FAR    u_real=3.5  v_real=0.0  -> (4, 0)
// --------------------------------------------------------------------------

#define EXPECT_K05_VERTEX 0x0400u    /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_K05_TOP_NEAR 0x0401u  /* HW_VERIFIED: UV(1, 0) */
#define EXPECT_K05_LEFT_NEAR 0x0420u /* HW_VERIFIED: UV(0, 1) */
#define EXPECT_K05_INTERIOR 0x1442u  /* HW_VERIFIED: UV(2, 2) */
#define EXPECT_K05_TOP_FAR 0x1404u   /* HW_VERIFIED: UV(4, 0) */

// --------------------------------------------------------------------------
// K=8   (stride 0.8 - near 1:1)
//   P_VERTEX     u_real=0.0  v_real=0.0  -> (0, 0)
//   P_TOP_NEAR   u_real=0.8  v_real=0.0  -> (1, 0)
//   P_LEFT_NEAR  u_real=0.0  v_real=0.8  -> (0, 1)
//   P_INTERIOR   u_real=2.4  v_real=2.4  -> (2, 2)
//   P_TOP_FAR    u_real=5.6  v_real=0.0  -> (6, 0)
// --------------------------------------------------------------------------

#define EXPECT_K08_VERTEX 0x0400u    /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_K08_TOP_NEAR 0x0401u  /* HW_VERIFIED: UV(1, 0) */
#define EXPECT_K08_LEFT_NEAR 0x0420u /* HW_VERIFIED: UV(0, 1) */
#define EXPECT_K08_INTERIOR 0x1442u  /* HW_VERIFIED: UV(2, 2) */
#define EXPECT_K08_TOP_FAR 0x1C06u   /* HW_VERIFIED: UV(6, 0) */

// --------------------------------------------------------------------------
// K=16  (stride 1.6 - stretched)
//   P_VERTEX     u_real=0.0   v_real=0.0   -> (0, 0)
//   P_TOP_NEAR   u_real=1.6   v_real=0.0   -> (2, 0)
//   P_LEFT_NEAR  u_real=0.0   v_real=1.6   -> (0, 2)
//   P_INTERIOR   u_real=4.8   v_real=4.8   -> (5, 5)
//   P_TOP_FAR    u_real=11.2  v_real=0.0   -> (11, 0)
// --------------------------------------------------------------------------

#define EXPECT_K16_VERTEX 0x0400u    /* HW_VERIFIED: UV(0, 0) */
#define EXPECT_K16_TOP_NEAR 0x0C02u  /* HW_VERIFIED: UV(2, 0) */
#define EXPECT_K16_LEFT_NEAR 0x0C40u /* HW_VERIFIED: UV(0, 2) */
#define EXPECT_K16_INTERIOR 0x2CA5u  /* HW_VERIFIED: UV(5, 5) */
#define EXPECT_K16_TOP_FAR 0x2C0Bu   /* HW_VERIFIED: UV(11, 0) */
