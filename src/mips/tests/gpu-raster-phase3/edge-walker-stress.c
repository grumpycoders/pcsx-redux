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

// Edge-walker stress suite: configurations that exercise soft.cc's
// setupSections* / nextRow* family in non-trivial ways. Targets:
//   - Near-vertical degenerate triangles (height >> width).
//   - Near-horizontal degenerate triangles (width >> height).
//   - Longest-edge boundary cases (which edge gets "longest" status).
//   - Slope-fraction sweep (probes 16.16 accumulator behavior via
//     non-power-of-two slope ratios).
//   - 4-vertex quad sweep paths (untextured decompose path).
//
// All flat untextured - no texpage state needed. The Phase 4 refactor
// thread is unifying edge walkers across 3-vert and 4-vert families;
// this suite gives that work a regression surface that was previously
// uncovered.

CESTER_BODY(

// Near-vertical degenerate triangles.

static void drawNV1(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 8, 16);
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 1, 0, 0, 10);
    rasterFlushPrimitive();
}

static void drawNV2(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 8, 16);
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 2, 10, 0, 10);
    rasterFlushPrimitive();
}

static void drawNV3(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 32);
    rasterFlatTri(RASTER_CMD_GREEN, 5, 0, 6, 0, 5, 20);
    rasterFlushPrimitive();
}

// Near-horizontal degenerate triangles.

static void drawNH1(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 4);
    rasterFlatTri(RASTER_CMD_BLUE, 0, 0, 20, 0, 0, 1);
    rasterFlushPrimitive();
}

static void drawNH2(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 4);
    rasterFlatTri(RASTER_CMD_BLUE, 0, 0, 20, 1, 0, 1);
    rasterFlushPrimitive();
}

static void drawNH3(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 48, 4);
    rasterFlatTri(RASTER_CMD_BLUE, 0, 0, 40, 0, 20, 1);
    rasterFlushPrimitive();
}

// Longest-edge boundary cases.

static void drawLE1(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 10, 0, 5, 9);
    rasterFlushPrimitive();
}

static void drawLE2(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 8);
    rasterFlatTri(RASTER_CMD_GREEN, 0, 0, 20, 0, 10, 5);
    rasterFlushPrimitive();
}

static void drawLE3(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 24);
    rasterFlatTri(RASTER_CMD_WHITE, 0, 0, 3, 0, 10, 20);
    rasterFlushPrimitive();
}

// Slope-fraction sweep.

static void drawSF1(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 8, 12);
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 3, 0, 0, 9);
    rasterFlushPrimitive();
}

static void drawSF2(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 4, 8);
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 1, 0, 0, 5);
    rasterFlushPrimitive();
}

static void drawSF3(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 8, 12);
    rasterFlatTri(RASTER_CMD_GREEN, 0, 0, 3, 0, 0, 7);
    rasterFlushPrimitive();
}

// 4-vertex quad sweep paths.

static void drawQS1(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    // Skewed quad: vertices (0,0),(8,0),(1,8),(9,8). Seam runs from
    // vertex 1 (8,0) to vertex 2 (1,8) per (1,3,2)+(0,1,2) decompose.
    rasterFlatQuad(RASTER_CMD_BLUE, 0, 0, 8, 0, 1, 8, 9, 8);
    rasterFlushPrimitive();
}

static void drawQS2(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 20, 16);
    // Parallelogram: vertices (0,0),(10,0),(5,10),(15,10).
    rasterFlatQuad(RASTER_CMD_GREEN, 0, 0, 10, 0, 5, 10, 15, 10);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// Near-vertical degenerate triangles
// --------------------------------------------------------------------------

CESTER_TEST(nv1_top, gpu_raster_phase3,
    drawNV1();
    ASSERT_PIXEL_EQ(EXPECT_NV1_PIXEL_0_0, 0, 0);
)

CESTER_TEST(nv1_mid, gpu_raster_phase3,
    drawNV1();
    ASSERT_PIXEL_EQ(EXPECT_NV1_PIXEL_0_5, 0, 5);
)

CESTER_TEST(nv1_last_row, gpu_raster_phase3,
    drawNV1();
    ASSERT_PIXEL_EQ(EXPECT_NV1_PIXEL_0_9, 0, 9);
)

CESTER_TEST(nv1_bottom_excluded, gpu_raster_phase3,
    drawNV1();
    ASSERT_PIXEL_EQ(EXPECT_NV1_PIXEL_0_10, 0, 10);
)

CESTER_TEST(nv1_right_edge_excluded, gpu_raster_phase3,
    drawNV1();
    ASSERT_PIXEL_EQ(EXPECT_NV1_PIXEL_1_0, 1, 0);
)

CESTER_TEST(nv2_top_xmax_eq_xmin, gpu_raster_phase3,
    drawNV2();
    ASSERT_PIXEL_EQ(EXPECT_NV2_PIXEL_0_0, 0, 0);
)

CESTER_TEST(nv2_narrow_row, gpu_raster_phase3,
    drawNV2();
    ASSERT_PIXEL_EQ(EXPECT_NV2_PIXEL_0_1, 0, 1);
)

CESTER_TEST(nv2_mid, gpu_raster_phase3,
    drawNV2();
    ASSERT_PIXEL_EQ(EXPECT_NV2_PIXEL_0_5, 0, 5);
)

CESTER_TEST(nv2_near_bottom, gpu_raster_phase3,
    drawNV2();
    ASSERT_PIXEL_EQ(EXPECT_NV2_PIXEL_0_9, 0, 9);
)

CESTER_TEST(nv2_widest_x1, gpu_raster_phase3,
    drawNV2();
    ASSERT_PIXEL_EQ(EXPECT_NV2_PIXEL_1_9, 1, 9);
)

CESTER_TEST(nv2_right_edge, gpu_raster_phase3,
    drawNV2();
    ASSERT_PIXEL_EQ(EXPECT_NV2_PIXEL_2_9, 2, 9);
)

CESTER_TEST(nv3_top, gpu_raster_phase3,
    drawNV3();
    ASSERT_PIXEL_EQ(EXPECT_NV3_PIXEL_5_0, 5, 0);
)

CESTER_TEST(nv3_mid, gpu_raster_phase3,
    drawNV3();
    ASSERT_PIXEL_EQ(EXPECT_NV3_PIXEL_5_10, 5, 10);
)

CESTER_TEST(nv3_last_row, gpu_raster_phase3,
    drawNV3();
    ASSERT_PIXEL_EQ(EXPECT_NV3_PIXEL_5_19, 5, 19);
)

CESTER_TEST(nv3_bottom_excluded, gpu_raster_phase3,
    drawNV3();
    ASSERT_PIXEL_EQ(EXPECT_NV3_PIXEL_5_20, 5, 20);
)

CESTER_TEST(nv3_right_edge_x6, gpu_raster_phase3,
    drawNV3();
    ASSERT_PIXEL_EQ(EXPECT_NV3_PIXEL_6_0, 6, 0);
)

CESTER_TEST(nv3_before_left_x4, gpu_raster_phase3,
    drawNV3();
    ASSERT_PIXEL_EQ(EXPECT_NV3_PIXEL_4_0, 4, 0);
)

// --------------------------------------------------------------------------
// Near-horizontal degenerate triangles
// --------------------------------------------------------------------------

CESTER_TEST(nh1_left, gpu_raster_phase3,
    drawNH1();
    ASSERT_PIXEL_EQ(EXPECT_NH1_PIXEL_0_0, 0, 0);
)

CESTER_TEST(nh1_mid, gpu_raster_phase3,
    drawNH1();
    ASSERT_PIXEL_EQ(EXPECT_NH1_PIXEL_10_0, 10, 0);
)

CESTER_TEST(nh1_last_x, gpu_raster_phase3,
    drawNH1();
    ASSERT_PIXEL_EQ(EXPECT_NH1_PIXEL_19_0, 19, 0);
)

CESTER_TEST(nh1_right_edge_x20, gpu_raster_phase3,
    drawNH1();
    ASSERT_PIXEL_EQ(EXPECT_NH1_PIXEL_20_0, 20, 0);
)

CESTER_TEST(nh1_bottom_y1, gpu_raster_phase3,
    drawNH1();
    ASSERT_PIXEL_EQ(EXPECT_NH1_PIXEL_0_1, 0, 1);
)

CESTER_TEST(nh2_apex_top_row, gpu_raster_phase3,
    drawNH2();
    ASSERT_PIXEL_EQ(EXPECT_NH2_PIXEL_0_0, 0, 0);
)

CESTER_TEST(nh2_mid_top_row, gpu_raster_phase3,
    drawNH2();
    ASSERT_PIXEL_EQ(EXPECT_NH2_PIXEL_10_0, 10, 0);
)

CESTER_TEST(nh3_left, gpu_raster_phase3,
    drawNH3();
    ASSERT_PIXEL_EQ(EXPECT_NH3_PIXEL_0_0, 0, 0);
)

CESTER_TEST(nh3_apex_x_top, gpu_raster_phase3,
    drawNH3();
    ASSERT_PIXEL_EQ(EXPECT_NH3_PIXEL_20_0, 20, 0);
)

CESTER_TEST(nh3_last_x, gpu_raster_phase3,
    drawNH3();
    ASSERT_PIXEL_EQ(EXPECT_NH3_PIXEL_39_0, 39, 0);
)

CESTER_TEST(nh3_right_vertex, gpu_raster_phase3,
    drawNH3();
    ASSERT_PIXEL_EQ(EXPECT_NH3_PIXEL_40_0, 40, 0);
)

CESTER_TEST(nh3_bottom_apex, gpu_raster_phase3,
    drawNH3();
    ASSERT_PIXEL_EQ(EXPECT_NH3_PIXEL_20_1, 20, 1);
)

// --------------------------------------------------------------------------
// Longest-edge boundary cases
// --------------------------------------------------------------------------

CESTER_TEST(le1_top_left, gpu_raster_phase3,
    drawLE1();
    ASSERT_PIXEL_EQ(EXPECT_LE1_PIXEL_0_0, 0, 0);
)

CESTER_TEST(le1_interior, gpu_raster_phase3,
    drawLE1();
    ASSERT_PIXEL_EQ(EXPECT_LE1_PIXEL_5_4, 5, 4);
)

CESTER_TEST(le1_top_right_end, gpu_raster_phase3,
    drawLE1();
    ASSERT_PIXEL_EQ(EXPECT_LE1_PIXEL_9_0, 9, 0);
)

CESTER_TEST(le1_top_vertex_right, gpu_raster_phase3,
    drawLE1();
    ASSERT_PIXEL_EQ(EXPECT_LE1_PIXEL_10_0, 10, 0);
)

CESTER_TEST(le1_apex, gpu_raster_phase3,
    drawLE1();
    ASSERT_PIXEL_EQ(EXPECT_LE1_PIXEL_5_9, 5, 9);
)

CESTER_TEST(le2_top_left, gpu_raster_phase3,
    drawLE2();
    ASSERT_PIXEL_EQ(EXPECT_LE2_PIXEL_0_0, 0, 0);
)

CESTER_TEST(le2_top_right_end, gpu_raster_phase3,
    drawLE2();
    ASSERT_PIXEL_EQ(EXPECT_LE2_PIXEL_19_0, 19, 0);
)

CESTER_TEST(le2_near_apex, gpu_raster_phase3,
    drawLE2();
    ASSERT_PIXEL_EQ(EXPECT_LE2_PIXEL_10_4, 10, 4);
)

CESTER_TEST(le2_apex, gpu_raster_phase3,
    drawLE2();
    ASSERT_PIXEL_EQ(EXPECT_LE2_PIXEL_10_5, 10, 5);
)

CESTER_TEST(le3_top_left, gpu_raster_phase3,
    drawLE3();
    ASSERT_PIXEL_EQ(EXPECT_LE3_PIXEL_0_0, 0, 0);
)

CESTER_TEST(le3_top_x2, gpu_raster_phase3,
    drawLE3();
    ASSERT_PIXEL_EQ(EXPECT_LE3_PIXEL_2_0, 2, 0);
)

CESTER_TEST(le3_top_vertex, gpu_raster_phase3,
    drawLE3();
    ASSERT_PIXEL_EQ(EXPECT_LE3_PIXEL_3_0, 3, 0);
)

CESTER_TEST(le3_mid, gpu_raster_phase3,
    drawLE3();
    ASSERT_PIXEL_EQ(EXPECT_LE3_PIXEL_5_10, 5, 10);
)

CESTER_TEST(le3_apex, gpu_raster_phase3,
    drawLE3();
    ASSERT_PIXEL_EQ(EXPECT_LE3_PIXEL_10_20, 10, 20);
)

// --------------------------------------------------------------------------
// Slope-fraction sweep
// --------------------------------------------------------------------------

CESTER_TEST(sf1_top_left, gpu_raster_phase3,
    drawSF1();
    ASSERT_PIXEL_EQ(EXPECT_SF1_PIXEL_0_0, 0, 0);
)

CESTER_TEST(sf1_top_x2, gpu_raster_phase3,
    drawSF1();
    ASSERT_PIXEL_EQ(EXPECT_SF1_PIXEL_2_0, 2, 0);
)

CESTER_TEST(sf1_x2_y1, gpu_raster_phase3,
    drawSF1();
    ASSERT_PIXEL_EQ(EXPECT_SF1_PIXEL_2_1, 2, 1);
)

CESTER_TEST(sf1_x2_y2, gpu_raster_phase3,
    drawSF1();
    ASSERT_PIXEL_EQ(EXPECT_SF1_PIXEL_2_2, 2, 2);
)

CESTER_TEST(sf1_right_eq_2_excluded, gpu_raster_phase3,
    drawSF1();
    ASSERT_PIXEL_EQ(EXPECT_SF1_PIXEL_2_3, 2, 3);
)

CESTER_TEST(sf1_x1_y3, gpu_raster_phase3,
    drawSF1();
    ASSERT_PIXEL_EQ(EXPECT_SF1_PIXEL_1_3, 1, 3);
)

CESTER_TEST(sf1_right_eq_1_excluded, gpu_raster_phase3,
    drawSF1();
    ASSERT_PIXEL_EQ(EXPECT_SF1_PIXEL_1_6, 1, 6);
)

CESTER_TEST(sf1_x0_y6, gpu_raster_phase3,
    drawSF1();
    ASSERT_PIXEL_EQ(EXPECT_SF1_PIXEL_0_6, 0, 6);
)

CESTER_TEST(sf1_narrow_y7_dropped, gpu_raster_phase3,
    drawSF1();
    ASSERT_PIXEL_EQ(EXPECT_SF1_PIXEL_0_7, 0, 7);
)

CESTER_TEST(sf1_narrow_y8_dropped, gpu_raster_phase3,
    drawSF1();
    ASSERT_PIXEL_EQ(EXPECT_SF1_PIXEL_0_8, 0, 8);
)

CESTER_TEST(sf2_y0, gpu_raster_phase3,
    drawSF2();
    ASSERT_PIXEL_EQ(EXPECT_SF2_PIXEL_0_0, 0, 0);
)

CESTER_TEST(sf2_y1, gpu_raster_phase3,
    drawSF2();
    ASSERT_PIXEL_EQ(EXPECT_SF2_PIXEL_0_1, 0, 1);
)

CESTER_TEST(sf2_y4, gpu_raster_phase3,
    drawSF2();
    ASSERT_PIXEL_EQ(EXPECT_SF2_PIXEL_0_4, 0, 4);
)

CESTER_TEST(sf3_top_left, gpu_raster_phase3,
    drawSF3();
    ASSERT_PIXEL_EQ(EXPECT_SF3_PIXEL_0_0, 0, 0);
)

CESTER_TEST(sf3_top_x2, gpu_raster_phase3,
    drawSF3();
    ASSERT_PIXEL_EQ(EXPECT_SF3_PIXEL_2_0, 2, 0);
)

CESTER_TEST(sf3_y1_x2, gpu_raster_phase3,
    drawSF3();
    ASSERT_PIXEL_EQ(EXPECT_SF3_PIXEL_2_1, 2, 1);
)

CESTER_TEST(sf3_y2_x2_uncertain, gpu_raster_phase3,
    drawSF3();
    ASSERT_PIXEL_EQ(EXPECT_SF3_PIXEL_2_2, 2, 2);
)

CESTER_TEST(sf3_y2_x1, gpu_raster_phase3,
    drawSF3();
    ASSERT_PIXEL_EQ(EXPECT_SF3_PIXEL_1_2, 1, 2);
)

CESTER_TEST(sf3_y3_x0, gpu_raster_phase3,
    drawSF3();
    ASSERT_PIXEL_EQ(EXPECT_SF3_PIXEL_0_3, 0, 3);
)

CESTER_TEST(sf3_y3_x1, gpu_raster_phase3,
    drawSF3();
    ASSERT_PIXEL_EQ(EXPECT_SF3_PIXEL_1_3, 1, 3);
)

CESTER_TEST(sf3_y5_dropped, gpu_raster_phase3,
    drawSF3();
    ASSERT_PIXEL_EQ(EXPECT_SF3_PIXEL_0_5, 0, 5);
)

// --------------------------------------------------------------------------
// 4-vertex quad sweep paths
// --------------------------------------------------------------------------

CESTER_TEST(qs1_top_left, gpu_raster_phase3,
    drawQS1();
    ASSERT_PIXEL_EQ(EXPECT_QS1_PIXEL_0_0, 0, 0);
)

CESTER_TEST(qs1_top_right_interior, gpu_raster_phase3,
    drawQS1();
    ASSERT_PIXEL_EQ(EXPECT_QS1_PIXEL_7_0, 7, 0);
)

CESTER_TEST(qs1_vertex1, gpu_raster_phase3,
    drawQS1();
    ASSERT_PIXEL_EQ(EXPECT_QS1_PIXEL_8_0, 8, 0);
)

CESTER_TEST(qs1_seam_mid, gpu_raster_phase3,
    drawQS1();
    ASSERT_PIXEL_EQ(EXPECT_QS1_PIXEL_4_4, 4, 4);
)

CESTER_TEST(qs1_near_vertex2, gpu_raster_phase3,
    drawQS1();
    ASSERT_PIXEL_EQ(EXPECT_QS1_PIXEL_1_7, 1, 7);
)

CESTER_TEST(qs1_bottom_right_interior, gpu_raster_phase3,
    drawQS1();
    ASSERT_PIXEL_EQ(EXPECT_QS1_PIXEL_8_7, 8, 7);
)

CESTER_TEST(qs1_outside_left, gpu_raster_phase3,
    drawQS1();
    ASSERT_PIXEL_EQ(EXPECT_QS1_PIXEL_0_7, 0, 7);
)

CESTER_TEST(qs1_bottom_edge, gpu_raster_phase3,
    drawQS1();
    ASSERT_PIXEL_EQ(EXPECT_QS1_PIXEL_1_8, 1, 8);
)

CESTER_TEST(qs2_top_left, gpu_raster_phase3,
    drawQS2();
    ASSERT_PIXEL_EQ(EXPECT_QS2_PIXEL_0_0, 0, 0);
)

CESTER_TEST(qs2_top_mid, gpu_raster_phase3,
    drawQS2();
    ASSERT_PIXEL_EQ(EXPECT_QS2_PIXEL_5_0, 5, 0);
)

CESTER_TEST(qs2_top_right, gpu_raster_phase3,
    drawQS2();
    ASSERT_PIXEL_EQ(EXPECT_QS2_PIXEL_9_0, 9, 0);
)

CESTER_TEST(qs2_top_vertex, gpu_raster_phase3,
    drawQS2();
    ASSERT_PIXEL_EQ(EXPECT_QS2_PIXEL_10_0, 10, 0);
)

CESTER_TEST(qs2_mid_left_interior, gpu_raster_phase3,
    drawQS2();
    ASSERT_PIXEL_EQ(EXPECT_QS2_PIXEL_2_5, 2, 5);
)

CESTER_TEST(qs2_mid_right_interior, gpu_raster_phase3,
    drawQS2();
    ASSERT_PIXEL_EQ(EXPECT_QS2_PIXEL_12_5, 12, 5);
)

CESTER_TEST(qs2_near_vertex2, gpu_raster_phase3,
    drawQS2();
    ASSERT_PIXEL_EQ(EXPECT_QS2_PIXEL_5_9, 5, 9);
)

CESTER_TEST(qs2_bottom_excluded, gpu_raster_phase3,
    drawQS2();
    ASSERT_PIXEL_EQ(EXPECT_QS2_PIXEL_5_10, 5, 10);
)
