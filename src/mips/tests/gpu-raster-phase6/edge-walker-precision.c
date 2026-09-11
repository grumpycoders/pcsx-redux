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

// Edge-walker integer-division precision oracle. PS1 vertices are
// 11-bit integer - there is no fractional-coord input. The question
// this suite probes is what happens INSIDE the rasterizer when its
// per-row right-edge step accumulates 16.16 truncation across rows.
//
// soft.cc's `setupSectionsFlat3` (and family) sets:
//
//   m_deltaRightX = ((v2->x - v1->x) << 16) / height;
//
// at 16.16 fixed-point. When (v2.x - v1.x) doesn't divide height
// cleanly, the division truncates - and the truncation accumulates
// per row. At rows where the *true* rightX is exactly an integer,
// the accumulated truncation determines whether the next-row's edge
// is "just below" or "just at/above" the integer, which decides
// whether pixel x=integer is INSIDE or OUTSIDE the span under
// top-left rule.
//
// This suite probes configurations where the integer-rightX boundary
// hits multiple rows, plus integer-shifted variants of the same
// shape, to characterize hardware's actual rounding behavior. The
// refactor's fix (whether Bresenham-style integer accumulation or
// extended fixed-point) needs this oracle to verify correct
// convergence.
//
// Naming: EWP<n> = Edge-Walker Precision configuration n.

CESTER_BODY(

// EWP1: slope exactly 1/2. (0, 0)-(2, 0)-(0, 4).
//   Right(y): y=0->2.0, y=1->1.5, y=2->1.0, y=3->0.5, y=4->0
//   Slow-path xmax = floor(right) - 1:
//     y=0: xmax=1, span [0,1]
//     y=1: xmax=0 (1.5->floor 1 -> -1=0), span [0,0]
//     y=2: xmax=-1 (1.0->floor 1 -> -1=0... but right is exactly 1)
//     y=3: xmax=-1 (0.5->floor 0 -> -1)
// Hardware truth captured here. Integer-rightX rows: y=0, y=2, y=4.
static void drawEWP1(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 8, 8);
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 2, 0, 0, 4);
    rasterFlushPrimitive();
}

// EWP2: SF1 shape (0, 0)-(3, 0)-(0, 9), already tested in phase-3 but
// re-probed here at MORE rows for edge-walker characterization. Slope
// 1/3. Integer-rightX rows: y=0 (3.0), y=3 (2.0), y=6 (1.0), y=9 (0).
// We expect: at y=2, right=2.333, xmax=1, x=0,1 drawn, x=2 sentinel.
//            at y=3, right=2.0,   xmax=0, x=0 drawn, x=1,2 sentinel.
// (Already confirmed in phase-3 but with no x=2 y=3 boundary probe.)
static void drawEWP2(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 8, 16);
    rasterFlatTri(RASTER_CMD_GREEN, 0, 0, 3, 0, 0, 9);
    rasterFlushPrimitive();
}

// EWP3: position-shift of EWP2. Same shape but origin at (1, 0):
// (1, 0)-(4, 0)-(1, 9). Tests whether the shifted triangle has
// identical relative coverage. Edge-walker math should be position-
// independent for integer offsets (the absolute screen position
// doesn't enter the slope calc), so phase-3's EWP2 rules should
// translate to (1..3, 0..8) here.
static void drawEWP3(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 8, 16);
    rasterFlatTri(RASTER_CMD_GREEN, 1, 0, 4, 0, 1, 9);
    rasterFlushPrimitive();
}

// EWP4: irrational slope 7/9. (0, 0)-(7, 0)-(0, 9). Right(y) at each y:
//   y=0: 7.0       y=5: 3.111
//   y=1: 6.222     y=6: 2.333
//   y=2: 5.444     y=7: 1.556
//   y=3: 4.667     y=8: 0.778
//   y=4: 3.889     y=9: 0
// Slow-path floor-1 rule:
//   y=0: xmax=6, span [0,6]   (boundary: x=6 drawn, x=7 not)
//   y=1: xmax=5, [0..5]
//   y=2: xmax=4
//   y=3: xmax=3
//   y=4: xmax=2
//   y=5: xmax=2
//   y=6: xmax=1
//   y=7: xmax=0
//   y=8: xmax=-1 (right=0.778->floor 0 -> -1)
// Hardware should KEEP narrow rows post-apex per phase-3 finding.
static void drawEWP4(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 12, 12);
    rasterFlatTri(RASTER_CMD_BLUE, 0, 0, 7, 0, 0, 9);
    rasterFlushPrimitive();
}

// EWP5: slope 2/5. (0, 0)-(2, 0)-(0, 5). Slow path:
//   y=0: right=2.0,   xmax=0 (floor 2 -> -1=1... actually slow is
//                              right>>16 - 1, so right=2 -> 2 - 1 = 1)
//   Hmm wait let me recompute. right at y=0 is 2.0, encoded as
//   2<<16 = 0x20000. right>>16 = 2. xmax = 2 - 1 = 1. Span [0, 1].
//   y=1: right=1.6, encoded 0x19999. right>>16=1, xmax=0. Span [0, 0].
//   y=2: right=1.2, right>>16=1, xmax=0. Span [0, 0].
//   y=3: right=0.8, right>>16=0, xmax=-1. Empty?
//   y=4: right=0.4, similar empty.
// Per phase-3 hardware truth: narrow rows post-apex are KEPT. So
// y=3, y=4 likely have x=0 drawn anyway.
static void drawEWP5(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 8, 8);
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 2, 0, 0, 5);
    rasterFlushPrimitive();
}

// EWP6: tall + narrow with slope 1/N where N is large. (0, 0)-(1, 0)-
// (0, 15). One-pixel-wide column for the whole height. All 15 rows
// should fill at x=0 per phase-3 SF2 generalization.
static void drawEWP6(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 4, 20);
    rasterFlatTri(RASTER_CMD_WHITE, 0, 0, 1, 0, 0, 15);
    rasterFlushPrimitive();
}

// EWP7: slope that produces same right-edge integer values at
// multiple non-modular rows. (0, 0)-(4, 0)-(0, 16). Slope 1/4.
// Right(y) at every y: 4, 3.75, 3.5, 3.25, 3, 2.75, 2.5, 2.25, 2,
//                      1.75, 1.5, 1.25, 1, 0.75, 0.5, 0.25, 0
// Integer-rightX rows: y=0,4,8,12,16. Many integer-boundary cases.
static void drawEWP7(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 8, 20);
    rasterFlatTri(RASTER_CMD_GREEN, 0, 0, 4, 0, 0, 16);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// EWP1: slope 1/2
// --------------------------------------------------------------------------

CESTER_TEST(ewp1_y0_x0, gpu_raster_phase6,
    drawEWP1();
    /* y=0, right=2.0, expect x=0 drawn. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 0, 0);
)

CESTER_TEST(ewp1_y0_x1, gpu_raster_phase6,
    drawEWP1();
    /* y=0, right=2.0, slow xmax=1, x=1 drawn. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 1, 0);
)

CESTER_TEST(ewp1_y0_x2_right_vertex, gpu_raster_phase6,
    drawEWP1();
    /* y=0 right vertex - right edge excluded per top-left. */
    ASSERT_PIXEL_UNTOUCHED(2, 0);
)

CESTER_TEST(ewp1_y1_x0, gpu_raster_phase6,
    drawEWP1();
    /* y=1, right=1.5, x=0 drawn. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 0, 1);
)

CESTER_TEST(ewp1_y1_x1_boundary, gpu_raster_phase6,
    drawEWP1();
    /* y=1, right=1.5 (fractional). HW_VERIFIED 2026-05-16: hardware
       INCLUDES x=floor(right)=1 when right is fractional. This is
       neither legacy fast-path (which decrements unconditionally if
       xmax>xmin) nor slow-path (which decrements unconditionally).
       The canonical rule appears to be:
         xmax = (rightX - 1) >> 16
       Integer rightX excludes (right-vertex behavior), fractional
       rightX keeps the floor pixel. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 1, 1);
)

CESTER_TEST(ewp1_y2_x0_integer_right, gpu_raster_phase6,
    drawEWP1();
    /* y=2, right=1.0 EXACTLY (integer-rightX row). Top-left rule
       excludes the right edge at integer crossings. x=0 drawn,
       x=1 not. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 0, 2);
)

CESTER_TEST(ewp1_y2_x1_integer_right, gpu_raster_phase6,
    drawEWP1();
    /* y=2, right=1.0 exactly. x=1 IS the integer boundary. */
    ASSERT_PIXEL_UNTOUCHED(1, 2);
)

CESTER_TEST(ewp1_y3_x0_narrow, gpu_raster_phase6,
    drawEWP1();
    /* y=3, right=0.5. Per phase-3 narrow-post-apex rule, x=0 likely
       drawn (kept). */
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 0, 3);
)

CESTER_TEST(ewp1_y4_bottom_excluded, gpu_raster_phase6,
    drawEWP1();
    ASSERT_PIXEL_UNTOUCHED(0, 4);
)

// --------------------------------------------------------------------------
// EWP3: position-shift of SF1 shape (origin (1, 0))
// --------------------------------------------------------------------------

CESTER_TEST(ewp3_shifted_y0_x1, gpu_raster_phase6,
    drawEWP3();
    /* y=0, x=1 = relative (0,0) of shifted triangle. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 1, 0);
)

CESTER_TEST(ewp3_shifted_y0_x3, gpu_raster_phase6,
    drawEWP3();
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 3, 0);
)

CESTER_TEST(ewp3_shifted_y0_x4_right_vertex, gpu_raster_phase6,
    drawEWP3();
    ASSERT_PIXEL_UNTOUCHED(4, 0);
)

CESTER_TEST(ewp3_shifted_y3_x2_integer_right_boundary, gpu_raster_phase6,
    drawEWP3();
    /* y=3 of shifted shape = absolute y=3. Right edge at relative
       x=2, absolute x=3. Integer-rightX row. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 2, 3);
)

CESTER_TEST(ewp3_shifted_y3_x3_excluded, gpu_raster_phase6,
    drawEWP3();
    ASSERT_PIXEL_UNTOUCHED(3, 3);
)

// --------------------------------------------------------------------------
// EWP4: irrational slope 7/9
// --------------------------------------------------------------------------

CESTER_TEST(ewp4_y0_x6, gpu_raster_phase6,
    drawEWP4();
    /* y=0, right=7, span [0..6]. x=6 drawn. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_BLUE, 6, 0);
)

CESTER_TEST(ewp4_y0_x7_right_vertex, gpu_raster_phase6,
    drawEWP4();
    ASSERT_PIXEL_UNTOUCHED(7, 0);
)

CESTER_TEST(ewp4_y4_x2_irrational, gpu_raster_phase6,
    drawEWP4();
    /* y=4, right=3.889. Slow xmax=2, span [0..2]. x=2 drawn. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_BLUE, 2, 4);
)

CESTER_TEST(ewp4_y4_x3_boundary, gpu_raster_phase6,
    drawEWP4();
    /* y=4, right=3.889 (fractional). HW_VERIFIED: x=3 IS drawn
       (same canonical xmax = (rightX-1)>>16 rule as EWP1 y=1). */
    ASSERT_PIXEL_EQ(RASTER_VRAM_BLUE, 3, 4);
)

CESTER_TEST(ewp4_y7_narrow_x0, gpu_raster_phase6,
    drawEWP4();
    /* y=7, right=1.556, narrow row, hardware keeps. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_BLUE, 0, 7);
)

CESTER_TEST(ewp4_y8_narrow_post_apex, gpu_raster_phase6,
    drawEWP4();
    /* y=8, right=0.778. Per phase-3, narrow post-apex is KEPT. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_BLUE, 0, 8);
)

// --------------------------------------------------------------------------
// EWP5: slope 2/5
// --------------------------------------------------------------------------

CESTER_TEST(ewp5_y0_x0, gpu_raster_phase6,
    drawEWP5();
    /* y=0, right=2.0 exact integer. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 0, 0);
)

CESTER_TEST(ewp5_y0_x1, gpu_raster_phase6,
    drawEWP5();
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 1, 0);
)

CESTER_TEST(ewp5_y0_x2_right_vertex, gpu_raster_phase6,
    drawEWP5();
    ASSERT_PIXEL_UNTOUCHED(2, 0);
)

CESTER_TEST(ewp5_y3_narrow_kept, gpu_raster_phase6,
    drawEWP5();
    /* y=3, right=0.8, narrow post-apex KEPT. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 0, 3);
)

CESTER_TEST(ewp5_y4_narrow_kept, gpu_raster_phase6,
    drawEWP5();
    /* y=4, right=0.4, even narrower. Still KEPT per phase-3. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 0, 4);
)

// --------------------------------------------------------------------------
// EWP6: 1-pixel column, height 15
// --------------------------------------------------------------------------

CESTER_TEST(ewp6_y0, gpu_raster_phase6,
    drawEWP6();
    ASSERT_PIXEL_EQ(RASTER_VRAM_WHITE, 0, 0);
)

CESTER_TEST(ewp6_y7_mid, gpu_raster_phase6,
    drawEWP6();
    ASSERT_PIXEL_EQ(RASTER_VRAM_WHITE, 0, 7);
)

CESTER_TEST(ewp6_y14_last_row, gpu_raster_phase6,
    drawEWP6();
    ASSERT_PIXEL_EQ(RASTER_VRAM_WHITE, 0, 14);
)

CESTER_TEST(ewp6_y15_bottom_excluded, gpu_raster_phase6,
    drawEWP6();
    ASSERT_PIXEL_UNTOUCHED(0, 15);
)

CESTER_TEST(ewp6_x1_right_edge_clean, gpu_raster_phase6,
    drawEWP6();
    ASSERT_PIXEL_UNTOUCHED(1, 7);
)

// --------------------------------------------------------------------------
// EWP7: slope 1/4, multiple integer-rightX rows (y=0,4,8,12,16)
// --------------------------------------------------------------------------

CESTER_TEST(ewp7_y0_x3, gpu_raster_phase6,
    drawEWP7();
    /* y=0, right=4.0 exact, span [0..3]. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 3, 0);
)

CESTER_TEST(ewp7_y0_x4_right_vertex, gpu_raster_phase6,
    drawEWP7();
    ASSERT_PIXEL_UNTOUCHED(4, 0);
)

CESTER_TEST(ewp7_y4_x2_integer_right, gpu_raster_phase6,
    drawEWP7();
    /* y=4, right=3.0 EXACT integer. Slow xmax=2. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 2, 4);
)

CESTER_TEST(ewp7_y4_x3_integer_excluded, gpu_raster_phase6,
    drawEWP7();
    /* y=4, right=3.0. x=3 IS the integer boundary - excluded. */
    ASSERT_PIXEL_UNTOUCHED(3, 4);
)

CESTER_TEST(ewp7_y8_x1_integer_right, gpu_raster_phase6,
    drawEWP7();
    /* y=8, right=2.0 exact. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 1, 8);
)

CESTER_TEST(ewp7_y8_x2_excluded, gpu_raster_phase6,
    drawEWP7();
    ASSERT_PIXEL_UNTOUCHED(2, 8);
)

CESTER_TEST(ewp7_y12_x0_integer_right, gpu_raster_phase6,
    drawEWP7();
    /* y=12, right=1.0 exact. xmax=0. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 0, 12);
)

CESTER_TEST(ewp7_y12_x1_excluded, gpu_raster_phase6,
    drawEWP7();
    ASSERT_PIXEL_UNTOUCHED(1, 12);
)

CESTER_TEST(ewp7_y14_narrow_x0_kept, gpu_raster_phase6,
    drawEWP7();
    /* y=14, right=0.5. Narrow post-apex KEPT. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 0, 14);
)

CESTER_TEST(ewp7_y15_narrow_x0_kept, gpu_raster_phase6,
    drawEWP7();
    /* y=15, right=0.25. Even narrower, still KEPT per phase-3. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 0, 15);
)

CESTER_TEST(ewp7_y16_bottom_excluded, gpu_raster_phase6,
    drawEWP7();
    ASSERT_PIXEL_UNTOUCHED(0, 16);
)
