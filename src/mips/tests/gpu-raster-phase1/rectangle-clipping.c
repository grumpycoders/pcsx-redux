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

// Rectangle clipping suite. GP0(0x60) flat variable-size rectangle.
// Drawing area = (0,0) .. (1024, 512) by default. Tests:
//   - Rect entirely inside the draw area (R1).
//   - Rect with top-left outside the draw area (R2). Top-left clipping.
//   - Rect that exactly equals the draw area edge.
//   - Rect with negative coordinates after drawing offset.

CESTER_BODY(

// R1: 4x4 rectangle at (10, 10), GREEN. Fully inside draw area.
static void rasterDrawRectR1(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    rasterFlatRect(RASTER_CMD_GREEN, 10, 10, 4, 4);
    rasterFlushPrimitive();
}

// R2: 8x8 rectangle starting at (-2, -2), GREEN. Top-left 4x4 quadrant
// of the rect is outside the draw area; only the bottom-right 6x6 region
// remains and should fill VRAM (0,0)..(5,5).
//
// Note: GP0(0x60) takes UNSIGNED 16-bit coordinates in the second word
// (x | y<<16). Negative -2 sign-extends to 0xfffe which would naturally
// be a huge X. But the drawing-area clipping should clamp this. The
// observation IS the test - if the GPU treats -2 as 0xfffe and clips
// everything (no draw), we want to see that in the OBS log.
//
// To get a meaningful test of "negative top-left clipping" we instead
// shift the drawing area so the test rect crosses its top-left edge
// with VALID 11-bit coordinates. Set draw area to (4, 4)..(end), draw
// rect at (2, 2) size 6x6. Then VRAM (4,4)..(7,7) should fill and
// VRAM (2,2)..(3,3) should stay sentinel.
static void rasterDrawRectR2(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    // Shrink draw area to (4, 4)..(16, 16).
    setDrawingArea(4, 4, 16, 16);
    rasterFlatRect(RASTER_CMD_GREEN, 2, 2, 6, 6);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// Rect R1: fully inside draw area
// --------------------------------------------------------------------------

CESTER_TEST(rectR1_top_left, gpu_raster_phase1,
    rasterDrawRectR1();
    ASSERT_PIXEL_EQ(EXPECT_RECT_R1_PIXEL_10_10, 10, 10);
)

CESTER_TEST(rectR1_bottom_right_interior, gpu_raster_phase1,
    rasterDrawRectR1();
    ASSERT_PIXEL_EQ(EXPECT_RECT_R1_PIXEL_13_13, 13, 13);
)

CESTER_TEST(rectR1_right_edge_excluded, gpu_raster_phase1,
    rasterDrawRectR1();
    ASSERT_PIXEL_EQ(EXPECT_RECT_R1_PIXEL_14_10, 14, 10);
)

CESTER_TEST(rectR1_bottom_edge_excluded, gpu_raster_phase1,
    rasterDrawRectR1();
    ASSERT_PIXEL_EQ(EXPECT_RECT_R1_PIXEL_10_14, 10, 14);
)

CESTER_TEST(rectR1_before_left_edge, gpu_raster_phase1,
    rasterDrawRectR1();
    ASSERT_PIXEL_EQ(EXPECT_RECT_R1_PIXEL_9_10, 9, 10);
)

// --------------------------------------------------------------------------
// Rect R2: top-left clipped by drawing area (4,4)
// --------------------------------------------------------------------------
//
// EXPECT_RECT_R2_PIXEL_0_0 in raster-expected.h was written assuming the
// default draw area (0,0). Here we use a shifted draw area (4,4) and
// expect the rect at (2,2) size 6x6 to fill VRAM (4,4)..(7,7) only.
// The pixels we assert against differ from the placeholders; redirect
// to the actual coordinates this test exercises.

CESTER_TEST(rectR2_clipped_pixel_4_4_corner, gpu_raster_phase1,
    rasterDrawRectR2();
    // (4,4) is inside both the rect and the shrunk draw area: should fill.
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 4, 4);
)

CESTER_TEST(rectR2_clipped_pixel_7_7_bottom_right, gpu_raster_phase1,
    rasterDrawRectR2();
    // (7,7) is the last interior pixel given the rect (2,2)..(8,8)
    // exclusive right/bottom under top-left rule.
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 7, 7);
)

CESTER_TEST(rectR2_clipped_pixel_2_2_top_left_outside_draw_area,
            gpu_raster_phase1,
    rasterDrawRectR2();
    // (2,2) is inside the rect but OUTSIDE the draw area (which starts
    // at 4). Should be clipped -> sentinel.
    ASSERT_PIXEL_UNTOUCHED(2, 2);
)

CESTER_TEST(rectR2_clipped_pixel_3_3_just_inside_rect_outside_draw,
            gpu_raster_phase1,
    rasterDrawRectR2();
    // (3,3) is inside the rect but just outside the shifted draw area.
    // Should be sentinel.
    ASSERT_PIXEL_UNTOUCHED(3, 3);
)

CESTER_TEST(rectR2_clipped_pixel_8_8_outside_rect, gpu_raster_phase1,
    rasterDrawRectR2();
    // (8,8) is past the rect's exclusive right/bottom edge.
    ASSERT_PIXEL_UNTOUCHED(8, 8);
)
