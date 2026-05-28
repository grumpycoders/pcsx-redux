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

// Drawing-area + drawing-offset interactions. GP0(E3) sets the area
// upper-left, GP0(E4) the area lower-right (inclusive). GP0(E5) sets
// the offset added to every primitive vertex.
//
// Documents:
//   - Offset (50, 50): primitive at logical (0,0) draws at VRAM (50,50).
//   - Offset combined with draw-area clip.
//   - Primitive at negative logical coords after offset.

CESTER_BODY(

// Offset-A: Triangle A geometry (0,0),(4,0),(0,4) with drawing offset
// (50, 50). Expected to fill exactly the same pixel set as Triangle A
// from triangle-edges.c, shifted by (50, 50).
static void rasterDrawOffsetA(void) {
    rasterReset();
    rasterClearTestRegion(48, 48, 16, 16);
    // Also clear the original origin so we can assert it stays sentinel.
    rasterClearTestRegion(0, 0, 8, 8);
    setDrawingOffset(50, 50);
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 4, 0, 0, 4);
    rasterFlushPrimitive();
}

// Offset-B: Drawing offset that pushes geometry partially OFF the draw
// area. Logical (-3, -3), (5, -3), (-3, 5) with offset (3, 3) gives
// destination triangle (0,0), (8,0), (0,8). The drawing-area clip is
// (0, 0)..(1024, 512) so nothing should be cut. This documents that
// offset itself does not introduce clipping when destinations are
// non-negative.
static void rasterDrawOffsetB(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    setDrawingOffset(3, 3);
    rasterFlatTri(RASTER_CMD_GREEN, -3, -3, 5, -3, -3, 5);
    rasterFlushPrimitive();
}

// Offset-C: Drawing offset PLUS shrunk draw area. The primitive lands
// inside VRAM but partially outside the active draw area. Should clip
// to the area, not silently extend past it.
//   Draw area: (10, 10)..(20, 20)
//   Offset: (10, 10)
//   Primitive: triangle (0,0),(8,0),(0,8) -> VRAM (10,10),(18,10),(10,18)
// All of the destination is inside the draw area, so the triangle
// should render fully. This is a sanity check that offset + draw area
// compose additively.
static void rasterDrawOffsetC(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    setDrawingArea(10, 10, 20, 20);
    setDrawingOffset(10, 10);
    rasterFlatTri(RASTER_CMD_BLUE, 0, 0, 8, 0, 0, 8);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// Offset A: triangle shifted by (50, 50)
// --------------------------------------------------------------------------

CESTER_TEST(offsetA_origin_top_left_at_50_50, gpu_raster_phase1,
    rasterDrawOffsetA();
    ASSERT_PIXEL_EQ(EXPECT_OFFSET_PIXEL_50_50, 50, 50);
)

CESTER_TEST(offsetA_origin_top_inner_53_50, gpu_raster_phase1,
    rasterDrawOffsetA();
    ASSERT_PIXEL_EQ(EXPECT_OFFSET_PIXEL_53_50, 53, 50);
)

CESTER_TEST(offsetA_right_edge_54_50_excluded, gpu_raster_phase1,
    rasterDrawOffsetA();
    ASSERT_PIXEL_EQ(EXPECT_OFFSET_PIXEL_54_50, 54, 50);
)

CESTER_TEST(offsetA_bottom_edge_50_54_excluded, gpu_raster_phase1,
    rasterDrawOffsetA();
    ASSERT_PIXEL_EQ(EXPECT_OFFSET_PIXEL_50_54, 50, 54);
)

CESTER_TEST(offsetA_origin_0_0_untouched, gpu_raster_phase1,
    rasterDrawOffsetA();
    // With offset 50,50, the logical (0,0) corner of the triangle should
    // NOT write VRAM (0,0). Sentinel confirms the offset took effect.
    ASSERT_PIXEL_EQ(EXPECT_OFFSET_PIXEL_0_0, 0, 0);
)

// --------------------------------------------------------------------------
// Offset B: negative logical coordinates compensated by positive offset
// --------------------------------------------------------------------------

CESTER_TEST(offsetB_negative_compensated_pixel_0_0, gpu_raster_phase1,
    rasterDrawOffsetB();
    // Logical (-3, -3) + offset (3, 3) = VRAM (0, 0). The triangle
    // (-3,-3)(5,-3)(-3,5) -> (0,0)(8,0)(0,8). Top-left rule says (0,0)
    // is drawn (inclusive corner).
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 0, 0);
)

CESTER_TEST(offsetB_negative_compensated_pixel_7_0, gpu_raster_phase1,
    rasterDrawOffsetB();
    // Last drawn pixel of the top edge under top-left rule.
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 7, 0);
)

CESTER_TEST(offsetB_negative_compensated_pixel_8_0, gpu_raster_phase1,
    rasterDrawOffsetB();
    // Right-vertex corner; top-left rule excludes.
    ASSERT_PIXEL_UNTOUCHED(8, 0);
)

CESTER_TEST(offsetB_negative_compensated_pixel_0_8, gpu_raster_phase1,
    rasterDrawOffsetB();
    // Bottom-vertex; bottom edge excluded.
    ASSERT_PIXEL_UNTOUCHED(0, 8);
)

// --------------------------------------------------------------------------
// Offset C: offset + shifted draw area compose additively
// --------------------------------------------------------------------------

CESTER_TEST(offsetC_compose_pixel_10_10_inside_area, gpu_raster_phase1,
    rasterDrawOffsetC();
    ASSERT_PIXEL_EQ(RASTER_VRAM_BLUE, 10, 10);
)

CESTER_TEST(offsetC_compose_pixel_17_10_top_inner, gpu_raster_phase1,
    rasterDrawOffsetC();
    // Logical (7,0) + offset 10 = VRAM (17,10). Inside draw area (ends
    // at 20). Under top-left rule for triangle (0,0)(8,0)(0,8), pixel
    // x=7 y=0 is the last included on the top edge.
    ASSERT_PIXEL_EQ(RASTER_VRAM_BLUE, 17, 10);
)

CESTER_TEST(offsetC_compose_pixel_18_10_right_vertex, gpu_raster_phase1,
    rasterDrawOffsetC();
    // Right-vertex corner excluded under top-left rule.
    ASSERT_PIXEL_UNTOUCHED(18, 10);
)

CESTER_TEST(offsetC_compose_pixel_9_9_before_draw_area, gpu_raster_phase1,
    rasterDrawOffsetC();
    // Just outside the shifted draw area (which starts at 10).
    ASSERT_PIXEL_UNTOUCHED(9, 9);
)
