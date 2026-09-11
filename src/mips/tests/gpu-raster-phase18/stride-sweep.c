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

// Phase-18 affine UV stride-magnitude sweep. Six triangles, identical
// 10x10 screen footprint, varying K controls the per-axis UV stride:
//
//   T_AXIS_K:  A=(5, 5)/(0, 0)  B=(15, 5)/(K, 0)  C=(5, 15)/(0, K)
//
// Per-axis stride is K/10 (equal for U and V). K covers a wide range so
// the hardware-sampled (u, v) plotted against K reveals which bias
// model the GPU implements. Five probes per K, identical screen
// positions across all K.

CESTER_BODY(

// ---- T_AXIS_K01: dU/dx = dV/dy = 0.1 (very compressed) -----------------
static void drawT_AXIS_K01(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0, 0,
                 15, 5,  1, 0,
                 5,  15, 0, 1,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T_AXIS_K02: dU/dx = dV/dy = 0.2 ----------------------------------
static void drawT_AXIS_K02(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0, 0,
                 15, 5,  2, 0,
                 5,  15, 0, 2,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T_AXIS_K03: dU/dx = dV/dy = 0.3 ----------------------------------
static void drawT_AXIS_K03(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0, 0,
                 15, 5,  3, 0,
                 5,  15, 0, 3,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T_AXIS_K05: dU/dx = dV/dy = 0.5 (right at the half-step boundary) -
static void drawT_AXIS_K05(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0, 0,
                 15, 5,  5, 0,
                 5,  15, 0, 5,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T_AXIS_K08: dU/dx = dV/dy = 0.8 (near 1:1) ------------------------
static void drawT_AXIS_K08(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0, 0,
                 15, 5,  8, 0,
                 5,  15, 0, 8,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T_AXIS_K16: dU/dx = dV/dy = 1.6 (stretched) -----------------------
static void drawT_AXIS_K16(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0,  0,
                 15, 5,  16, 0,
                 5,  15, 0,  16,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// K=1 probes (stride = 0.1 per axis)
// --------------------------------------------------------------------------

CESTER_TEST(ar_axis_k01_vertex, gpu_raster_phase18,
    drawT_AXIS_K01();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K01_VERTEX, 5, 5);
)

CESTER_TEST(ar_axis_k01_top_near, gpu_raster_phase18,
    drawT_AXIS_K01();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K01_TOP_NEAR, 6, 5);
)

CESTER_TEST(ar_axis_k01_left_near, gpu_raster_phase18,
    drawT_AXIS_K01();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K01_LEFT_NEAR, 5, 6);
)

CESTER_TEST(ar_axis_k01_interior, gpu_raster_phase18,
    drawT_AXIS_K01();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K01_INTERIOR, 8, 8);
)

CESTER_TEST(ar_axis_k01_top_far, gpu_raster_phase18,
    drawT_AXIS_K01();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K01_TOP_FAR, 12, 5);
)

// --------------------------------------------------------------------------
// K=2 probes (stride = 0.2 per axis)
// --------------------------------------------------------------------------

CESTER_TEST(ar_axis_k02_vertex, gpu_raster_phase18,
    drawT_AXIS_K02();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K02_VERTEX, 5, 5);
)

CESTER_TEST(ar_axis_k02_top_near, gpu_raster_phase18,
    drawT_AXIS_K02();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K02_TOP_NEAR, 6, 5);
)

CESTER_TEST(ar_axis_k02_left_near, gpu_raster_phase18,
    drawT_AXIS_K02();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K02_LEFT_NEAR, 5, 6);
)

CESTER_TEST(ar_axis_k02_interior, gpu_raster_phase18,
    drawT_AXIS_K02();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K02_INTERIOR, 8, 8);
)

CESTER_TEST(ar_axis_k02_top_far, gpu_raster_phase18,
    drawT_AXIS_K02();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K02_TOP_FAR, 12, 5);
)

// --------------------------------------------------------------------------
// K=3 probes (stride = 0.3 per axis)
// --------------------------------------------------------------------------

CESTER_TEST(ar_axis_k03_vertex, gpu_raster_phase18,
    drawT_AXIS_K03();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K03_VERTEX, 5, 5);
)

CESTER_TEST(ar_axis_k03_top_near, gpu_raster_phase18,
    drawT_AXIS_K03();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K03_TOP_NEAR, 6, 5);
)

CESTER_TEST(ar_axis_k03_left_near, gpu_raster_phase18,
    drawT_AXIS_K03();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K03_LEFT_NEAR, 5, 6);
)

CESTER_TEST(ar_axis_k03_interior, gpu_raster_phase18,
    drawT_AXIS_K03();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K03_INTERIOR, 8, 8);
)

CESTER_TEST(ar_axis_k03_top_far, gpu_raster_phase18,
    drawT_AXIS_K03();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K03_TOP_FAR, 12, 5);
)

// --------------------------------------------------------------------------
// K=5 probes (stride = 0.5 per axis - right at the half-step boundary)
// --------------------------------------------------------------------------

CESTER_TEST(ar_axis_k05_vertex, gpu_raster_phase18,
    drawT_AXIS_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K05_VERTEX, 5, 5);
)

CESTER_TEST(ar_axis_k05_top_near, gpu_raster_phase18,
    drawT_AXIS_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K05_TOP_NEAR, 6, 5);
)

CESTER_TEST(ar_axis_k05_left_near, gpu_raster_phase18,
    drawT_AXIS_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K05_LEFT_NEAR, 5, 6);
)

CESTER_TEST(ar_axis_k05_interior, gpu_raster_phase18,
    drawT_AXIS_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K05_INTERIOR, 8, 8);
)

CESTER_TEST(ar_axis_k05_top_far, gpu_raster_phase18,
    drawT_AXIS_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K05_TOP_FAR, 12, 5);
)

// --------------------------------------------------------------------------
// K=8 probes (stride = 0.8 per axis - near 1:1)
// --------------------------------------------------------------------------

CESTER_TEST(ar_axis_k08_vertex, gpu_raster_phase18,
    drawT_AXIS_K08();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K08_VERTEX, 5, 5);
)

CESTER_TEST(ar_axis_k08_top_near, gpu_raster_phase18,
    drawT_AXIS_K08();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K08_TOP_NEAR, 6, 5);
)

CESTER_TEST(ar_axis_k08_left_near, gpu_raster_phase18,
    drawT_AXIS_K08();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K08_LEFT_NEAR, 5, 6);
)

CESTER_TEST(ar_axis_k08_interior, gpu_raster_phase18,
    drawT_AXIS_K08();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K08_INTERIOR, 8, 8);
)

CESTER_TEST(ar_axis_k08_top_far, gpu_raster_phase18,
    drawT_AXIS_K08();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K08_TOP_FAR, 12, 5);
)

// --------------------------------------------------------------------------
// K=16 probes (stride = 1.6 per axis - stretched)
// --------------------------------------------------------------------------

CESTER_TEST(ar_axis_k16_vertex, gpu_raster_phase18,
    drawT_AXIS_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K16_VERTEX, 5, 5);
)

CESTER_TEST(ar_axis_k16_top_near, gpu_raster_phase18,
    drawT_AXIS_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K16_TOP_NEAR, 6, 5);
)

CESTER_TEST(ar_axis_k16_left_near, gpu_raster_phase18,
    drawT_AXIS_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K16_LEFT_NEAR, 5, 6);
)

CESTER_TEST(ar_axis_k16_interior, gpu_raster_phase18,
    drawT_AXIS_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K16_INTERIOR, 8, 8);
)

CESTER_TEST(ar_axis_k16_top_far, gpu_raster_phase18,
    drawT_AXIS_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_K16_TOP_FAR, 12, 5);
)
