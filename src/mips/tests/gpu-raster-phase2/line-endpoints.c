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

// Line endpoints suite. GP0(0x40) flat untextured line - two vertex
// words after the command. Documents:
//   - Whether start AND end pixels are both drawn (inclusive on both ends).
//   - Bresenham octant symmetry: same shape across +X+Y, -X+Y, etc.
//   - Zero-length lines (start == end): does anything draw?
//   - Shallow vs steep lines (major axis selection).
//   - Diagonal at exactly 45 deg vs slope-0 / slope-infinity edge cases.

CESTER_BODY(

// Horizontal 1px line at y=10 from x=5 to x=10.
static void rasterDrawLineH(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatLine(RASTER_CMD_GREEN, 5, 10, 10, 10);
    rasterFlushPrimitive();
}

// Vertical 1px line at x=10 from y=5 to y=10.
static void rasterDrawLineV(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatLine(RASTER_CMD_RED, 10, 5, 10, 10);
    rasterFlushPrimitive();
}

// Diagonal +45 deg from (5,5) to (10,10).
static void rasterDrawLineD45(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatLine(RASTER_CMD_BLUE, 5, 5, 10, 10);
    rasterFlushPrimitive();
}

// Diagonal -45 deg from (5,10) to (10,5).
static void rasterDrawLineDN45(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatLine(RASTER_CMD_WHITE, 5, 10, 10, 5);
    rasterFlushPrimitive();
}

// Zero-length line: same start and end point.
static void rasterDrawLineZero(void) {
    rasterReset();
    rasterClearTestRegion(16, 16, 16, 8);
    rasterFlatLine(RASTER_CMD_RED, 20, 20, 20, 20);
    rasterFlushPrimitive();
}

// Shallow slope line (more horizontal than vertical): (0,0) to (10,3).
// Major axis is X. Tests Bresenham major-axis selection.
static void rasterDrawLineShallow(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 8);
    rasterFlatLine(RASTER_CMD_GREEN, 0, 0, 10, 3);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// Horizontal line (5,10) - (10,10)
// --------------------------------------------------------------------------

CESTER_TEST(lineH_before_start_pixel_4_10, gpu_raster_phase2,
    rasterDrawLineH();
    ASSERT_PIXEL_EQ(EXPECT_LINE_H_PIXEL_4_10, 4, 10);
)

CESTER_TEST(lineH_start_pixel_5_10, gpu_raster_phase2,
    rasterDrawLineH();
    ASSERT_PIXEL_EQ(EXPECT_LINE_H_PIXEL_5_10, 5, 10);
)

CESTER_TEST(lineH_interior_pixel_7_10, gpu_raster_phase2,
    rasterDrawLineH();
    ASSERT_PIXEL_EQ(EXPECT_LINE_H_PIXEL_7_10, 7, 10);
)

CESTER_TEST(lineH_end_pixel_10_10_inclusive, gpu_raster_phase2,
    rasterDrawLineH();
    ASSERT_PIXEL_EQ(EXPECT_LINE_H_PIXEL_10_10, 10, 10);
)

CESTER_TEST(lineH_past_end_pixel_11_10, gpu_raster_phase2,
    rasterDrawLineH();
    ASSERT_PIXEL_EQ(EXPECT_LINE_H_PIXEL_11_10, 11, 10);
)

CESTER_TEST(lineH_below_line_pixel_5_11, gpu_raster_phase2,
    rasterDrawLineH();
    ASSERT_PIXEL_EQ(EXPECT_LINE_H_PIXEL_5_11, 5, 11);
)

// --------------------------------------------------------------------------
// Vertical line (10,5) - (10,10)
// --------------------------------------------------------------------------

CESTER_TEST(lineV_before_start_pixel_10_4, gpu_raster_phase2,
    rasterDrawLineV();
    ASSERT_PIXEL_EQ(EXPECT_LINE_V_PIXEL_10_4, 10, 4);
)

CESTER_TEST(lineV_start_pixel_10_5, gpu_raster_phase2,
    rasterDrawLineV();
    ASSERT_PIXEL_EQ(EXPECT_LINE_V_PIXEL_10_5, 10, 5);
)

CESTER_TEST(lineV_interior_pixel_10_7, gpu_raster_phase2,
    rasterDrawLineV();
    ASSERT_PIXEL_EQ(EXPECT_LINE_V_PIXEL_10_7, 10, 7);
)

CESTER_TEST(lineV_end_pixel_10_10_inclusive, gpu_raster_phase2,
    rasterDrawLineV();
    ASSERT_PIXEL_EQ(EXPECT_LINE_V_PIXEL_10_10, 10, 10);
)

CESTER_TEST(lineV_past_end_pixel_10_11, gpu_raster_phase2,
    rasterDrawLineV();
    ASSERT_PIXEL_EQ(EXPECT_LINE_V_PIXEL_10_11, 10, 11);
)

// --------------------------------------------------------------------------
// Diagonal +45 deg (5,5) - (10,10)
// --------------------------------------------------------------------------

CESTER_TEST(lineD45_start_pixel_5_5, gpu_raster_phase2,
    rasterDrawLineD45();
    ASSERT_PIXEL_EQ(EXPECT_LINE_D45_PIXEL_5_5, 5, 5);
)

CESTER_TEST(lineD45_interior_pixel_7_7, gpu_raster_phase2,
    rasterDrawLineD45();
    ASSERT_PIXEL_EQ(EXPECT_LINE_D45_PIXEL_7_7, 7, 7);
)

CESTER_TEST(lineD45_end_pixel_10_10, gpu_raster_phase2,
    rasterDrawLineD45();
    ASSERT_PIXEL_EQ(EXPECT_LINE_D45_PIXEL_10_10, 10, 10);
)

CESTER_TEST(lineD45_off_diag_pixel_5_6, gpu_raster_phase2,
    rasterDrawLineD45();
    ASSERT_PIXEL_EQ(EXPECT_LINE_D45_PIXEL_5_6, 5, 6);
)

CESTER_TEST(lineD45_off_diag_pixel_6_5, gpu_raster_phase2,
    rasterDrawLineD45();
    ASSERT_PIXEL_EQ(EXPECT_LINE_D45_PIXEL_6_5, 6, 5);
)

// --------------------------------------------------------------------------
// Diagonal -45 deg (5,10) - (10,5)
// --------------------------------------------------------------------------

CESTER_TEST(lineDN45_start_pixel_5_10, gpu_raster_phase2,
    rasterDrawLineDN45();
    ASSERT_PIXEL_EQ(EXPECT_LINE_DN45_PIXEL_5_10, 5, 10);
)

CESTER_TEST(lineDN45_interior_pixel_7_8, gpu_raster_phase2,
    rasterDrawLineDN45();
    ASSERT_PIXEL_EQ(EXPECT_LINE_DN45_PIXEL_7_8, 7, 8);
)

CESTER_TEST(lineDN45_end_pixel_10_5, gpu_raster_phase2,
    rasterDrawLineDN45();
    ASSERT_PIXEL_EQ(EXPECT_LINE_DN45_PIXEL_10_5, 10, 5);
)

// --------------------------------------------------------------------------
// Zero-length line (20,20) - (20,20)
// --------------------------------------------------------------------------

CESTER_TEST(lineZero_start_pixel_20_20, gpu_raster_phase2,
    rasterDrawLineZero();
    ASSERT_PIXEL_EQ(EXPECT_LINE_ZERO_PIXEL_20_20, 20, 20);
)

CESTER_TEST(lineZero_neighbor_pixel_21_20, gpu_raster_phase2,
    rasterDrawLineZero();
    ASSERT_PIXEL_EQ(EXPECT_LINE_ZERO_PIXEL_21_20, 21, 20);
)

// --------------------------------------------------------------------------
// Shallow line (0,0) - (10,3): major axis is X
// --------------------------------------------------------------------------

CESTER_TEST(lineShallow_start_pixel_0_0, gpu_raster_phase2,
    rasterDrawLineShallow();
    ASSERT_PIXEL_EQ(EXPECT_LINE_SHALLOW_PIXEL_0_0, 0, 0);
)

CESTER_TEST(lineShallow_midpoint_pixel_5_2, gpu_raster_phase2,
    rasterDrawLineShallow();
    ASSERT_PIXEL_EQ(EXPECT_LINE_SHALLOW_PIXEL_5_2, 5, 2);
)

CESTER_TEST(lineShallow_end_pixel_10_3, gpu_raster_phase2,
    rasterDrawLineShallow();
    ASSERT_PIXEL_EQ(EXPECT_LINE_SHALLOW_PIXEL_10_3, 10, 3);
)

CESTER_TEST(lineShallow_x_2_y_0_bresenham_choice, gpu_raster_phase2,
    rasterDrawLineShallow();
    // At x=2, the Bresenham accumulator should have stepped y to 1.
    // Pixel (2, 0) on the original major-axis row should be empty if
    // the line steps y up before x=2. Verifies major-axis stepping.
    ASSERT_PIXEL_EQ(EXPECT_LINE_SHALLOW_PIXEL_2_0, 2, 0);
)
