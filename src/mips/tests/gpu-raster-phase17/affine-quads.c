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

// Phase-17 affine UV-mapping quad suite. Five 4-vertex flat-textured
// quads spanning the parameter space:
//
//   Q1 axis-aligned 1:1 baseline
//   Q2 90 degree UV rotation
//   Q3 trapezoid (non-parallelogram, top-width != bottom-width)
//   Q4 skewed non-parallelogram (every edge non-axis-aligned)
//   Q5 compressed UV on large quad
//
// These tests primarily validate that the 4-vert path produces
// hardware-matching output across non-trivial geometries. Hardware
// decomposes a quad into two triangles natively; if the 4-vert sweep
// diverges from a (1,3,2)+(0,1,2) decomposition output in ways
// hardware doesn't, that's evidence to retire the 4-vert sweep
// entirely. Q4 in particular probes the diagonal-seam class where
// phase-8's QFD finding showed a single seam-gap pixel.

CESTER_BODY(

// ---- Q1 AQ_AXIS_BASE -----------------------------------------------------
// v0=(5,5)/(0,0)  v1=(20,5)/(15,0)  v2=(5,15)/(0,10)  v3=(20,15)/(15,10)
// Axis-aligned 1:1. Baseline correctness.

static void drawAQ_AXIS_BASE(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      5,  5,  0,  0,
                      20, 5,  15, 0,
                      5,  15, 0,  10,
                      20, 15, 15, 10,
                      TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- Q2 AQ_TWIST_90 ------------------------------------------------------
// v0=(5,5)/(0,0)  v1=(20,5)/(0,15)  v2=(5,18)/(13,0)  v3=(20,18)/(13,15)
// 90 degree UV rotation. dU/dX = 0 along v0-v1, dU/dY = 1 along v0-v2.
// Decomposition's per-triangle UV interpolation has to match at the
// (v1, v2) diagonal seam.

static void drawAQ_TWIST_90(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 20);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      5,  5,  0,  0,
                      20, 5,  0,  15,
                      5,  18, 13, 0,
                      20, 18, 13, 15,
                      TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- Q3 AQ_TRAPEZOID -----------------------------------------------------
// v0=(8,5)/(0,0)  v1=(20,5)/(15,0)  v2=(5,18)/(0,13)  v3=(23,18)/(15,13)
// Top edge 12 wide, bottom 18 wide. Per-row pixel-count varies linearly.
// Stresses both decomposed triangles having different X spans per row.

static void drawAQ_TRAPEZOID(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 20);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      8,  5,  0,  0,
                      20, 5,  15, 0,
                      5,  18, 0,  13,
                      23, 18, 15, 13,
                      TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- Q4 AQ_SKEW_NP -------------------------------------------------------
// v0=(5,5)/(0,0)  v1=(20,8)/(12,0)  v2=(8,22)/(0,12)  v3=(25,18)/(12,12)
// Every edge non-axis-aligned. Diagonal seam between (v1, v2) bisects
// interior. Phase-8 QFD found one seam-gap pixel on a parallelogram;
// arbitrary skew may surface more.

static void drawAQ_SKEW_NP(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 24);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      5,  5,  0,  0,
                      20, 8,  12, 0,
                      8,  22, 0,  12,
                      25, 18, 12, 12,
                      TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- Q5 AQ_COMPRESS_UV ---------------------------------------------------
// v0=(5,5)/(0,0)  v1=(30,5)/(8,0)  v2=(5,22)/(0,5)  v3=(30,22)/(8,5)
// 25x17 screen -> 8x5 UV. Texture stretched. Fractional UV step
// across decomposition seam.

static void drawAQ_COMPRESS_UV(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 24);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      5,  5,  0, 0,
                      30, 5,  8, 0,
                      5,  22, 0, 5,
                      30, 22, 8, 5,
                      TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// Q1 AQ_AXIS_BASE assertions
// --------------------------------------------------------------------------

CESTER_TEST(aq_axis_base_8_8, gpu_raster_phase17,
    drawAQ_AXIS_BASE();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_AXIS_BASE_8_8, 8, 8);
)

CESTER_TEST(aq_axis_base_15_10, gpu_raster_phase17,
    drawAQ_AXIS_BASE();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_AXIS_BASE_15_10, 15, 10);
)

CESTER_TEST(aq_axis_base_5_14, gpu_raster_phase17,
    drawAQ_AXIS_BASE();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_AXIS_BASE_5_14, 5, 14);
)

CESTER_TEST(aq_axis_base_20_5_v1_excluded, gpu_raster_phase17,
    drawAQ_AXIS_BASE();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_AXIS_BASE_20_5, 20, 5);
)

// --------------------------------------------------------------------------
// Q2 AQ_TWIST_90 assertions
// --------------------------------------------------------------------------

CESTER_TEST(aq_twist_90_8_10, gpu_raster_phase17,
    drawAQ_TWIST_90();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_TWIST_90_8_10, 8, 10);
)

CESTER_TEST(aq_twist_90_15_13, gpu_raster_phase17,
    drawAQ_TWIST_90();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_TWIST_90_15_13, 15, 13);
)

CESTER_TEST(aq_twist_90_12_8_near_seam, gpu_raster_phase17,
    drawAQ_TWIST_90();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_TWIST_90_12_8, 12, 8);
)

CESTER_TEST(aq_twist_90_12_11_near_seam, gpu_raster_phase17,
    drawAQ_TWIST_90();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_TWIST_90_12_11, 12, 11);
)

// --------------------------------------------------------------------------
// Q3 AQ_TRAPEZOID assertions
// --------------------------------------------------------------------------

CESTER_TEST(aq_trapezoid_12_8, gpu_raster_phase17,
    drawAQ_TRAPEZOID();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_TRAPEZOID_12_8, 12, 8);
)

CESTER_TEST(aq_trapezoid_14_13, gpu_raster_phase17,
    drawAQ_TRAPEZOID();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_TRAPEZOID_14_13, 14, 13);
)

CESTER_TEST(aq_trapezoid_8_15, gpu_raster_phase17,
    drawAQ_TRAPEZOID();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_TRAPEZOID_8_15, 8, 15);
)

CESTER_TEST(aq_trapezoid_20_15, gpu_raster_phase17,
    drawAQ_TRAPEZOID();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_TRAPEZOID_20_15, 20, 15);
)

// --------------------------------------------------------------------------
// Q4 AQ_SKEW_NP assertions
// --------------------------------------------------------------------------

CESTER_TEST(aq_skew_np_12_10, gpu_raster_phase17,
    drawAQ_SKEW_NP();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_SKEW_NP_12_10, 12, 10);
)

CESTER_TEST(aq_skew_np_15_14, gpu_raster_phase17,
    drawAQ_SKEW_NP();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_SKEW_NP_15_14, 15, 14);
)

CESTER_TEST(aq_skew_np_10_15, gpu_raster_phase17,
    drawAQ_SKEW_NP();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_SKEW_NP_10_15, 10, 15);
)

CESTER_TEST(aq_skew_np_18_12_seam, gpu_raster_phase17,
    drawAQ_SKEW_NP();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_SKEW_NP_18_12, 18, 12);
)

// --------------------------------------------------------------------------
// Q5 AQ_COMPRESS_UV assertions
// --------------------------------------------------------------------------

CESTER_TEST(aq_compress_uv_10_8, gpu_raster_phase17,
    drawAQ_COMPRESS_UV();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_COMPRESS_UV_10_8, 10, 8);
)

CESTER_TEST(aq_compress_uv_20_15, gpu_raster_phase17,
    drawAQ_COMPRESS_UV();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_COMPRESS_UV_20_15, 20, 15);
)

CESTER_TEST(aq_compress_uv_15_10, gpu_raster_phase17,
    drawAQ_COMPRESS_UV();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_COMPRESS_UV_15_10, 15, 10);
)

CESTER_TEST(aq_compress_uv_29_21, gpu_raster_phase17,
    drawAQ_COMPRESS_UV();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AQ_COMPRESS_UV_29_21, 29, 21);
)
