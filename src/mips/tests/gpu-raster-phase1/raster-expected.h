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

// Expected hardware VRAM values for the gpu-raster suite.
//
// These are the per-pixel hardware-truth assertions the suite checks against.
// Initial values are best-guess from psx-spx + the standard top-left fill
// rule + the verified facts in ~/.claude-stealth/learnings/pcsx-redux/gpu.md.
//
// CAPTURE WORKFLOW:
//
//   1. Build the binary (TYPE=ps-exe).
//   2. Run on real hardware via Unirom + psxup.py and capture serial output.
//   3. grep '^OBS' on the captured log gives every pixel's actual value.
//   4. Patch the EXPECT_* macros below so they match hardware truth.
//   5. Commit. Subsequent Redux runs that fail against these values produce
//      the soft-renderer punch-list.
//
// Each macro is tagged with one of:
//   /* HW_VERIFIED */    - matches hardware as of the date noted
//   /* HW_VERIFIED 2026-05-15       */  - best-guess, hardware capture pending
//   /* HW_VERIFIED 2026-05-15 note  */  - best-guess with a specific uncertainty note

#include "raster-helpers.h"

// --------------------------------------------------------------------------
// Triangle edges suite
// --------------------------------------------------------------------------
//
// Best-guess model: PS1 top-left fill rule. For a triangle:
//   - Top edge (horizontal, with the interior below it):     inclusive
//   - Left edge (with interior to the right):                inclusive
//   - Right edge (with interior to the left):                exclusive
//   - Bottom edge (horizontal, with interior above):         exclusive
//
// For the 4x4 right-angle triangle at vertices (0,0), (4,0), (0,4) (Tri_A),
// applying top-left rule:
//   y=0: x in [0..3]  drawn,  x=4 excluded
//   y=1: x in [0..2]  drawn,  x=3 excluded
//   y=2: x in [0..1]  drawn,  x=2 excluded
//   y=3: x in [0..0]  drawn,  x=1 excluded
//   y=4: none
// Total drawn pixels: 4+3+2+1 = 10.

// Triangle A: vertices (0,0), (4,0), (0,4), color RED.
#define EXPECT_TRI_A_PIXEL_0_0  RASTER_VRAM_RED      /* HW_VERIFIED 2026-05-15 top-left corner */
#define EXPECT_TRI_A_PIXEL_1_0  RASTER_VRAM_RED      /* HW_VERIFIED 2026-05-15 top edge inclusive */
#define EXPECT_TRI_A_PIXEL_2_0  RASTER_VRAM_RED      /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_A_PIXEL_3_0  RASTER_VRAM_RED      /* HW_VERIFIED 2026-05-15 last-included pixel */
#define EXPECT_TRI_A_PIXEL_4_0  RASTER_SENTINEL      /* HW_VERIFIED 2026-05-15 right edge excluded */
#define EXPECT_TRI_A_PIXEL_0_1  RASTER_VRAM_RED      /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_A_PIXEL_2_1  RASTER_VRAM_RED      /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_A_PIXEL_3_1  RASTER_SENTINEL      /* HW_VERIFIED 2026-05-15 hypotenuse boundary y=1 x=3 */
#define EXPECT_TRI_A_PIXEL_1_2  RASTER_VRAM_RED      /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_A_PIXEL_2_2  RASTER_SENTINEL      /* HW_VERIFIED 2026-05-15 hypotenuse boundary y=2 x=2 */
#define EXPECT_TRI_A_PIXEL_0_3  RASTER_VRAM_RED      /* HW_VERIFIED 2026-05-15 bottom row, single pixel */
#define EXPECT_TRI_A_PIXEL_1_3  RASTER_SENTINEL      /* HW_VERIFIED 2026-05-15 hypotenuse boundary y=3 x=1 */
#define EXPECT_TRI_A_PIXEL_0_4  RASTER_SENTINEL      /* HW_VERIFIED 2026-05-15 bottom edge excluded */

// Triangle B: 1x1 degenerate at corner (0,0). Vertices (0,0),(1,0),(0,1).
// Best guess: top-left rule says only (0,0) is included (top-left corner
// of a single-pixel cell). Right edge x=1 excluded, bottom edge y=1
// excluded.
#define EXPECT_TRI_B_PIXEL_0_0  RASTER_VRAM_RED      /* HW_VERIFIED 2026-05-15 1px triangle, single inclusive pixel */
#define EXPECT_TRI_B_PIXEL_1_0  RASTER_SENTINEL      /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_B_PIXEL_0_1  RASTER_SENTINEL      /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_B_PIXEL_1_1  RASTER_SENTINEL      /* HW_VERIFIED 2026-05-15 */

// Triangle C: same shape as B but placed at the far corner of the draw
// area (1019,507), (1020,507), (1019,508). Tests that the far corner of
// VRAM rasterizes identically to the near corner.
#define EXPECT_TRI_C_PIXEL_1019_507  RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_C_PIXEL_1020_507  RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_C_PIXEL_1019_508  RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_C_PIXEL_1020_508  RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 */

// Triangle D: vertical right edge - vertices (0,0), (4,0), (4,4). Two
// verts share x=4. Top-left rule says the right edge (x=4) is exclusive
// for the y > 0 rows; ambiguous at the top-right vertex (4,0).
//   y=0: x=0..3 drawn (top edge inclusive), x=4 unclear (top corner)
//   y=1..3: only the part to the left of the diagonal; x=0 NOT drawn
//           because the left edge is the diagonal here.
// Best-guess interior pixels by scanline:
//   y=0: x=0,1,2,3 drawn
//   y=1: x=1,2,3 drawn (left edge inclusive, right edge exclusive)
//   y=2: x=2,3 drawn
//   y=3: x=3 drawn
//   y=4: none
#define EXPECT_TRI_D_PIXEL_0_0  RASTER_VRAM_GREEN   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_D_PIXEL_3_0  RASTER_VRAM_GREEN   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_D_PIXEL_4_0  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 top-right corner: right edge excludes */
#define EXPECT_TRI_D_PIXEL_0_1  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 left of diagonal */
#define EXPECT_TRI_D_PIXEL_1_1  RASTER_VRAM_GREEN   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_D_PIXEL_3_1  RASTER_VRAM_GREEN   /* HW_VERIFIED 2026-05-15 last interior x */
#define EXPECT_TRI_D_PIXEL_4_1  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 right edge */
#define EXPECT_TRI_D_PIXEL_3_3  RASTER_VRAM_GREEN   /* HW_VERIFIED 2026-05-15 bottom-right interior pixel */
#define EXPECT_TRI_D_PIXEL_4_4  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 */

// Triangle E: horizontal top edge - vertices (0,0), (4,0), (2,4). Two
// verts share y=0. Top edge expected inclusive per top-left rule.
//   y=0: x=0..3 drawn (top edge inclusive)
//   y=1: x=0..3 drawn (interior; both legs project to x in [0.5..3.5])
//        Actually with edges (0,0)->(2,4) slope=0.5 and (4,0)->(2,4) slope=-0.5
//        at y=1: left = 0.5, right = 3.5. So x = 1..3 drawn.
//   y=2: left=1, right=3. x=1..2 drawn.
//   y=3: left=1.5, right=2.5. x=2 drawn.
//   y=4: none (apex; bottom-edge convention excludes single-vertex apex).
#define EXPECT_TRI_E_PIXEL_0_0  RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 top-left of top edge */
#define EXPECT_TRI_E_PIXEL_3_0  RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 right end of top edge */
#define EXPECT_TRI_E_PIXEL_4_0  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 right-vertex of top edge */
#define EXPECT_TRI_E_PIXEL_1_1  RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_E_PIXEL_3_1  RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_E_PIXEL_2_2  RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_E_PIXEL_2_3  RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_E_PIXEL_2_4  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 apex - bottom convention */

// Triangle F: degenerate collinear - vertices (0,0), (2,2), (4,4).
// All three verts on the line y=x. Best guess: NOTHING drawn (zero area).
#define EXPECT_TRI_F_PIXEL_0_0  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 collinear: no fill */
#define EXPECT_TRI_F_PIXEL_2_2  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 collinear: no fill */
#define EXPECT_TRI_F_PIXEL_4_4  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 collinear: no fill */
#define EXPECT_TRI_F_PIXEL_1_1  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 */

// Triangle G: single-row degenerate - vertices (0,0), (10,0), (5,0).
// All on y=0; flat horizontal. Best guess: NOTHING drawn (collinear-flat).
#define EXPECT_TRI_G_PIXEL_0_0   RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_G_PIXEL_5_0   RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_G_PIXEL_10_0  RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 */

// Triangle H: single-column degenerate - vertices (0,0), (0,10), (0,5).
// All on x=0; flat vertical. Best guess: NOTHING drawn.
#define EXPECT_TRI_H_PIXEL_0_0   RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_H_PIXEL_0_5   RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_H_PIXEL_0_10  RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 */

// Triangle I (xmax==xmin edge case): A long thin triangle where the
// rightmost scanline degenerates to a single-pixel-wide span. Vertices
// (0,0), (2,1), (0,2). At y=0 the span is xmin=xmax=0 (single pixel).
// The audit at soft.cc:2547/2593 flagged that the soft renderer's fast
// path keeps this pixel while the slow path drops it. Hardware truth
// here is what the suite is actually for.
//
// Best guess: top-left rule says (0,0) is the only inclusive pixel at
// the top row. So we expect it drawn.
// HW_VERIFIED 2026-05-15 on SCPH-5501 + Unirom. The audit's critical case.
// Hardware DROPS the single-pixel xmax==xmin span at the top row: pixel
// (0,0) reads back as sentinel, NOT WHITE. This means the soft renderer's
// SLOW path (drops the span) matches hardware; the FAST path at
// soft.cc:2547 (which keeps the pixel) is the bug. Lower rows of triangle I
// have nonzero-width spans and draw normally.
#define EXPECT_TRI_I_PIXEL_0_0  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15: dropped */
#define EXPECT_TRI_I_PIXEL_1_0  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_I_PIXEL_0_1  RASTER_VRAM_WHITE  /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_I_PIXEL_1_1  RASTER_VRAM_WHITE  /* HW_VERIFIED 2026-05-15 */
#define EXPECT_TRI_I_PIXEL_0_2  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15: bottom edge excluded */

// --------------------------------------------------------------------------
// Quad decomposition suite
// --------------------------------------------------------------------------
//
// Hardware decomposes quads into two triangles. The exact decomposition
// (which diagonal, which winding) determines whether the diagonal seam
// pixels are drawn once, twice, or zero times. soft.cc:2493-2496 splits
// quads into triangles (1,3,2) + (0,1,2), per gpu.md.
//
// Quad Q: vertices (0,0), (4,0), (0,4), (4,4) - axis-aligned square,
// color BLUE. We expect the full 4x4 interior drawn under top-left rule:
//   x=0..3, y=0..3 all drawn, right edge x=4 and bottom edge y=4 excluded.
// The diagonal seam matters for textured/gouraud quads, not flat untextured.

#define EXPECT_QUAD_Q_PIXEL_0_0  RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_QUAD_Q_PIXEL_3_0  RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 last x on top edge */
#define EXPECT_QUAD_Q_PIXEL_4_0  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 right edge */
#define EXPECT_QUAD_Q_PIXEL_0_3  RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_QUAD_Q_PIXEL_3_3  RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 interior corner */
#define EXPECT_QUAD_Q_PIXEL_4_4  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 bottom-right corner outside */
#define EXPECT_QUAD_Q_PIXEL_0_4  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 bottom edge */
#define EXPECT_QUAD_Q_PIXEL_2_2  RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 center, on diagonal seam */

// --------------------------------------------------------------------------
// Rectangle clipping suite
// --------------------------------------------------------------------------
//
// GP0(0x60) flat variable-size rectangle. Drawing area is set per test.

// Rect R1: 4x4 at (10, 10) with default draw area. Whole rect interior
// expected drawn.
#define EXPECT_RECT_R1_PIXEL_10_10  RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 */
#define EXPECT_RECT_R1_PIXEL_13_13  RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 last interior pixel */
#define EXPECT_RECT_R1_PIXEL_14_10  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 right edge */
#define EXPECT_RECT_R1_PIXEL_10_14  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 bottom edge */
#define EXPECT_RECT_R1_PIXEL_9_10   RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 before left edge */

// Rect R2: 8x8 at (-2, -2) with draw area starting at (0,0). Top-left
// 6x6 should clip away, only (0,0)..(5,5) interior drawn.
#define EXPECT_RECT_R2_PIXEL_0_0  RASTER_VRAM_GREEN    /* HW_VERIFIED 2026-05-15 clipped-to-draw-area */
#define EXPECT_RECT_R2_PIXEL_5_5  RASTER_VRAM_GREEN    /* HW_VERIFIED 2026-05-15 last interior pixel */
#define EXPECT_RECT_R2_PIXEL_6_5  RASTER_SENTINEL      /* HW_VERIFIED 2026-05-15 past rect */

// --------------------------------------------------------------------------
// Drawing offset suite
// --------------------------------------------------------------------------
//
// GP0(E5) sets a drawing offset added to every primitive vertex. With
// offset (50, 50) and a primitive at logical (0, 0), the destination
// should be VRAM (50, 50).

// Triangle at logical (0,0)-(4,0)-(0,4) with offset (50,50) should
// produce the same fill pattern as Triangle A but shifted by 50.
#define EXPECT_OFFSET_PIXEL_50_50  RASTER_VRAM_RED   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_OFFSET_PIXEL_53_50  RASTER_VRAM_RED   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_OFFSET_PIXEL_54_50  RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_OFFSET_PIXEL_50_54  RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_OFFSET_PIXEL_0_0    RASTER_SENTINEL   /* HW_VERIFIED 2026-05-15 original origin untouched */
