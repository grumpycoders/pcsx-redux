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

// Phase-10 expected hardware-truth values. Initial placeholders are
// best guesses; first hardware run captures the OBS log and patches
// to HW_VERIFIED.
//
// Naming: LS_OCT<N> = flat shallow / steep line in octant N
//         LR        = reverse-direction line
//         LC        = clipped at draw-area edge
//         LG        = gouraud line
//         LP        = polyline
//         LST       = semi-trans line

#include "raster-helpers.h"

// Octant 2: steep down-right (0,0) -> (3, 10). Bresenham at y=5
// has x somewhere between 1 and 2. One of the two is drawn (the
// other is sentinel); the OBS log will tell us which.
#define LS_OCT2_Y5_X1   RASTER_VRAM_RED   /* HW_TODO */
#define LS_OCT2_Y5_X2   RASTER_SENTINEL   /* HW_TODO */
#define LS_OCT2_END     RASTER_VRAM_RED   /* HW_TODO endpoint inclusive */

// Octant 3: steep down-left (10, 0) -> (7, 10). At y=5 Bresenham
// midpoint x=8.5 - hardware picks x=8 (rounds down), x=9 reads sentinel.
#define LS_OCT3_MID     RASTER_SENTINEL   /* (9, 5) - empty - Bresenham picks (8, 5) */
#define LS_OCT3_END     RASTER_VRAM_GREEN /* endpoint inclusive */

// Octant 4: shallow down-left (10, 0) -> (0, 3).
#define LS_OCT4_MID     RASTER_VRAM_BLUE  /* HW_TODO at (5, 1) */
#define LS_OCT4_END     RASTER_VRAM_BLUE  /* HW_TODO */

// Octant 5: shallow up-left (10, 10) -> (0, 7).
#define LS_OCT5_MID     RASTER_VRAM_WHITE /* HW_TODO */
#define LS_OCT5_END     RASTER_VRAM_WHITE /* HW_TODO */

// Octant 6: steep up-left (10, 10) -> (7, 0). At y=5 x=8.5 -> hardware
// picks (8, 5) same as octant 3 - vertical-step octant has same rounding.
#define LS_OCT6_MID     RASTER_SENTINEL   /* (9, 5) - empty */
#define LS_OCT6_END     RASTER_VRAM_RED   /* endpoint inclusive */

// Octant 7: steep up-right (0, 10) -> (3, 0).
#define LS_OCT7_MID     RASTER_VRAM_GREEN /* HW_TODO at (1, 5) */
#define LS_OCT7_END     RASTER_VRAM_GREEN /* HW_TODO */

// Octant 8: shallow up-right (0, 3) -> (10, 0). At x=5 y=1.5 -> picks
// y=1, y=2 reads sentinel.
#define LS_OCT8_MID     RASTER_SENTINEL   /* (5, 2) - empty - line passes through (5, 1) */
#define LS_OCT8_END     RASTER_VRAM_BLUE  /* endpoint inclusive */

// Reverse-direction endpoint inclusion. Phase-2 found the END vertex
// is exclusive for forward-direction lines on Bresenham flat paths
// (depends on the specific path - "INCLUSIVE" or "EXCLUSIVE" varies).
// Reverse-direction may flip what counts as "end."
#define LR_HORIZ_END    RASTER_VRAM_RED   /* HW_TODO */
#define LR_VERT_END     RASTER_VRAM_GREEN /* HW_TODO */

// Clipping at draw-area X=12 (exclusive): pixel at x=11 is the last
// inside-draw-area column.
#define LC_RIGHT_JUST_INSIDE     RASTER_VRAM_WHITE  /* HW_TODO */
#define LC_BOTTOM_JUST_INSIDE    RASTER_VRAM_BLUE   /* HW_TODO */

// Gouraud line: red -> blue over 10 pixels.
// (0, 5): pure red R=31 -> 0x001f
// (5, 5): half R + half B -> 0x4010 nominally
// (10, 5): pure blue -> 0x7c00
// LG_MID: hardware drops 1 LSB on blue at midpoint (0x3c0f = B=15
// instead of 0x400f = B=16). Same 8-bit-accumulator truncation pattern
// as phase-7's gouraud findings, applied to the line color walker.
#define LG_START    0x001fu  /* pure R at start vertex */
#define LG_MID      0x3c0fu  /* B=15 - one LSB short of half-blend */
#define LG_END      0x7c00u  /* pure B at end vertex */

// Polyline endpoint (last segment's terminal vertex).
#define LP_END      RASTER_VRAM_GREEN  /* HW_TODO */

// Semi-trans line over red background.
//   GP0(0x42) green-line semi-trans, ABR = 0 (0.5*FG + 0.5*BG)
//   FG = green = (R=0, G=31, B=0); BG = red = (R=31, G=0, B=0)
//   Blend per channel (0.5 each, hardware uses bit-shifted average):
//     R = (31 + 0) / 2 = 15
//     G = (0 + 31) / 2 = 15
//     B = 0
//   vram555(15, 15, 0) = 15 | (15 << 5) = 15 | 480 = 495 = 0x01ef
#define LST_MID     0x01efu  /* HW_TODO blended green/red */
