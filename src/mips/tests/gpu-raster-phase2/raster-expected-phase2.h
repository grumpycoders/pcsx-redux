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

// Phase-2 expected hardware-truth values.
//
// Same workflow as phase-1's raster-expected.h: best-guess placeholders
// tagged HW_TODO. Run on hardware via Unirom + psxup.py, grep `^OBS` on
// the captured log for ground truth, patch these macros, commit. Redux
// runs then produce the soft-renderer punch list as cester FAIL lines.

#include "raster-helpers.h"

// --------------------------------------------------------------------------
// Line endpoints suite
// --------------------------------------------------------------------------
//
// Best-guess model: PS1 GP0(40) line draws Bresenham with endpoint
// INCLUSIVE (both start and end pixels). This is the conventional choice
// for raster lines on early-90s silicon.

// Horizontal 1-pixel line: vertices (5, 10), (10, 10). Expect pixels
// (5,10), (6,10), (7,10), (8,10), (9,10), (10,10) drawn (6 pixels).
#define EXPECT_LINE_H_PIXEL_4_10   RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 before start */
#define EXPECT_LINE_H_PIXEL_5_10   RASTER_VRAM_GREEN /* HW_VERIFIED 2026-05-15 start point */
#define EXPECT_LINE_H_PIXEL_7_10   RASTER_VRAM_GREEN /* HW_VERIFIED 2026-05-15 interior */
#define EXPECT_LINE_H_PIXEL_10_10  RASTER_VRAM_GREEN /* HW_VERIFIED 2026-05-15 end point (inclusive?) */
#define EXPECT_LINE_H_PIXEL_11_10  RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 past end */
#define EXPECT_LINE_H_PIXEL_5_11   RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 below line */

// Vertical line: vertices (10, 5), (10, 10).
#define EXPECT_LINE_V_PIXEL_10_4   RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_LINE_V_PIXEL_10_5   RASTER_VRAM_RED   /* HW_VERIFIED 2026-05-15 start */
#define EXPECT_LINE_V_PIXEL_10_7   RASTER_VRAM_RED   /* HW_VERIFIED 2026-05-15 interior */
#define EXPECT_LINE_V_PIXEL_10_10  RASTER_VRAM_RED   /* HW_VERIFIED 2026-05-15 end (inclusive?) */
#define EXPECT_LINE_V_PIXEL_10_11  RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 past end */

// Diagonal +45 deg (slope 1): (5, 5), (10, 10). Bresenham steps both
// axes one per step; expect (5,5),(6,6),(7,7),(8,8),(9,9),(10,10).
#define EXPECT_LINE_D45_PIXEL_5_5    RASTER_VRAM_BLUE  /* HW_VERIFIED 2026-05-15 start */
#define EXPECT_LINE_D45_PIXEL_7_7    RASTER_VRAM_BLUE  /* HW_VERIFIED 2026-05-15 interior */
#define EXPECT_LINE_D45_PIXEL_10_10  RASTER_VRAM_BLUE  /* HW_VERIFIED 2026-05-15 end */
#define EXPECT_LINE_D45_PIXEL_5_6    RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 off-diagonal */
#define EXPECT_LINE_D45_PIXEL_6_5    RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 off-diagonal */

// Diagonal -45 deg (slope -1): (5, 10), (10, 5).
#define EXPECT_LINE_DN45_PIXEL_5_10  RASTER_VRAM_WHITE /* HW_VERIFIED 2026-05-15 start */
#define EXPECT_LINE_DN45_PIXEL_7_8   RASTER_VRAM_WHITE /* HW_VERIFIED 2026-05-15 interior */
#define EXPECT_LINE_DN45_PIXEL_10_5  RASTER_VRAM_WHITE /* HW_VERIFIED 2026-05-15 end */

// Zero-length line: start == end. Best-guess: hardware draws the single
// start pixel.
#define EXPECT_LINE_ZERO_PIXEL_20_20  RASTER_VRAM_RED  /* HW_VERIFIED 2026-05-15 */
#define EXPECT_LINE_ZERO_PIXEL_21_20  RASTER_SENTINEL  /* HW_VERIFIED 2026-05-15 */

// Shallow line (more horizontal than vertical): (0, 0), (10, 3). Major
// axis is X; Bresenham steps X each iter, Y on accumulator overflow.
// Best-guess pixel set under standard Bresenham:
//   (0,0)(1,0)(2,1)(3,1)(4,1)(5,2)(6,2)(7,2)(8,2)(9,3)(10,3)
//   - 11 pixels (endpoint inclusive on both ends).
#define EXPECT_LINE_SHALLOW_PIXEL_0_0    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 start */
#define EXPECT_LINE_SHALLOW_PIXEL_5_2    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 midpoint */
#define EXPECT_LINE_SHALLOW_PIXEL_10_3   RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 end */
#define EXPECT_LINE_SHALLOW_PIXEL_2_0    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 Bresenham picks y=1 here */

// --------------------------------------------------------------------------
// Mask-bit suite
// --------------------------------------------------------------------------
//
// GP0(E6) sets two state bits: set-mask (every pixel drawn gets bit 15
// set in VRAM) and check-mask (skip pixels with bit 15 already set).
// Best-guess: hardware writes 0x801F for "RED + mask bit set" rather
// than 0x001F.

// Set-mask only: triangle drawn at (0,0)(4,0)(0,4) RED with E6 = 0x01.
// Each drawn pixel should be 0x801F (RED with mask bit).
#define EXPECT_MASK_SET_PIXEL_0_0  0x801fu  /* HW_VERIFIED 2026-05-15 RED OR mask bit */
#define EXPECT_MASK_SET_PIXEL_2_1  0x801fu  /* HW_VERIFIED 2026-05-15 */
#define EXPECT_MASK_SET_PIXEL_4_0  RASTER_SENTINEL  /* HW_VERIFIED 2026-05-15 right edge excluded */

// Check-mask after set-mask: overlay a second triangle with E6 = 0x02
// (check only). Pixels already drawn (with bit 15 set) should be
// preserved; pixels not yet drawn should fill normally.
//
// Setup: first draw RED tri A (sets mask bits via E6=0x01), then second
// draw GREEN at OVERLAPPING geometry with E6=0x02 (check only, no set).
// Pixel (1, 0) is in both triangles - was 0x801f (mask-set RED), should
// stay 0x801f after the GREEN attempt is rejected. Pixel (5, 0) is only
// in GREEN tri - was sentinel, should become VRAM_GREEN (0x03E0).
#define EXPECT_MASK_CHECK_PIXEL_1_0_preserved  0x801fu      /* HW_VERIFIED 2026-05-15 */
#define EXPECT_MASK_CHECK_PIXEL_5_0_filled     RASTER_VRAM_GREEN /* HW_VERIFIED 2026-05-15 */

// --------------------------------------------------------------------------
// Texture window suite
// --------------------------------------------------------------------------
//
// Pure characterization at first - textured primitives need a texpage
// + CLUT setup, and the test surface (which TIM gets uploaded, where in
// VRAM the texture lives, etc.) is its own design problem. Phase 2.5
// or beyond. Placeholders left empty here; suite file may stay as
// scaffolding initially.
