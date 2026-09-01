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

// Phase-20 row-walk-drift suite. Five triangles (K in {1, 3, 5, 8, 16})
// with identical 10x20 screen footprint. Six probes per K at x=7 and
// y in {5, 8, 11, 14, 17, 20}.

CESTER_BODY(

// Triangle T_LONG_K_N: A=(5,5)/(0,0) B=(15,5)/(N,0) C=(5,25)/(0,2N)
// dU/dx = N/10, dV/dy = N/10. Triangle is 10 wide, 20 tall. Right
// edge BC has slope -0.5; probes at x=7 are well to the left of BC
// at every probed y so row-start X stays at 5.

static void drawT_LONG_K01(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 28);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0, 0,
                 15, 5,  1, 0,
                 5,  25, 0, 2,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

static void drawT_LONG_K03(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 28);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0, 0,
                 15, 5,  3, 0,
                 5,  25, 0, 6,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

static void drawT_LONG_K05(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 28);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0, 0,
                 15, 5,  5, 0,
                 5,  25, 0, 10,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

static void drawT_LONG_K08(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 28);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0, 0,
                 15, 5,  8, 0,
                 5,  25, 0, 16,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

static void drawT_LONG_K16(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 28);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0,  0,
                 15, 5,  16, 0,
                 5,  25, 0,  32,  /* 8-bit UV holds 32 cleanly; probes only reach v=24 */
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// K=01 probes
// --------------------------------------------------------------------------

CESTER_TEST(ar_long_k01_y05, gpu_raster_phase20,
    drawT_LONG_K01();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K01_Y05, 7, 5);
)

CESTER_TEST(ar_long_k01_y08, gpu_raster_phase20,
    drawT_LONG_K01();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K01_Y08, 7, 8);
)

CESTER_TEST(ar_long_k01_y11, gpu_raster_phase20,
    drawT_LONG_K01();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K01_Y11, 7, 11);
)

CESTER_TEST(ar_long_k01_y14, gpu_raster_phase20,
    drawT_LONG_K01();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K01_Y14, 7, 14);
)

CESTER_TEST(ar_long_k01_y17, gpu_raster_phase20,
    drawT_LONG_K01();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K01_Y17, 7, 17);
)

CESTER_TEST(ar_long_k01_y20, gpu_raster_phase20,
    drawT_LONG_K01();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K01_Y20, 7, 20);
)

// --------------------------------------------------------------------------
// K=03 probes
// --------------------------------------------------------------------------

CESTER_TEST(ar_long_k03_y05, gpu_raster_phase20,
    drawT_LONG_K03();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K03_Y05, 7, 5);
)

CESTER_TEST(ar_long_k03_y08, gpu_raster_phase20,
    drawT_LONG_K03();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K03_Y08, 7, 8);
)

CESTER_TEST(ar_long_k03_y11, gpu_raster_phase20,
    drawT_LONG_K03();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K03_Y11, 7, 11);
)

CESTER_TEST(ar_long_k03_y14, gpu_raster_phase20,
    drawT_LONG_K03();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K03_Y14, 7, 14);
)

CESTER_TEST(ar_long_k03_y17, gpu_raster_phase20,
    drawT_LONG_K03();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K03_Y17, 7, 17);
)

CESTER_TEST(ar_long_k03_y20, gpu_raster_phase20,
    drawT_LONG_K03();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K03_Y20, 7, 20);
)

// --------------------------------------------------------------------------
// K=05 probes
// --------------------------------------------------------------------------

CESTER_TEST(ar_long_k05_y05, gpu_raster_phase20,
    drawT_LONG_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K05_Y05, 7, 5);
)

CESTER_TEST(ar_long_k05_y08, gpu_raster_phase20,
    drawT_LONG_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K05_Y08, 7, 8);
)

CESTER_TEST(ar_long_k05_y11, gpu_raster_phase20,
    drawT_LONG_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K05_Y11, 7, 11);
)

CESTER_TEST(ar_long_k05_y14, gpu_raster_phase20,
    drawT_LONG_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K05_Y14, 7, 14);
)

CESTER_TEST(ar_long_k05_y17, gpu_raster_phase20,
    drawT_LONG_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K05_Y17, 7, 17);
)

CESTER_TEST(ar_long_k05_y20, gpu_raster_phase20,
    drawT_LONG_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K05_Y20, 7, 20);
)

// --------------------------------------------------------------------------
// K=08 probes
// --------------------------------------------------------------------------

CESTER_TEST(ar_long_k08_y05, gpu_raster_phase20,
    drawT_LONG_K08();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K08_Y05, 7, 5);
)

CESTER_TEST(ar_long_k08_y08, gpu_raster_phase20,
    drawT_LONG_K08();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K08_Y08, 7, 8);
)

CESTER_TEST(ar_long_k08_y11, gpu_raster_phase20,
    drawT_LONG_K08();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K08_Y11, 7, 11);
)

CESTER_TEST(ar_long_k08_y14, gpu_raster_phase20,
    drawT_LONG_K08();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K08_Y14, 7, 14);
)

CESTER_TEST(ar_long_k08_y17, gpu_raster_phase20,
    drawT_LONG_K08();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K08_Y17, 7, 17);
)

CESTER_TEST(ar_long_k08_y20, gpu_raster_phase20,
    drawT_LONG_K08();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K08_Y20, 7, 20);
)

// --------------------------------------------------------------------------
// K=16 probes
// --------------------------------------------------------------------------

CESTER_TEST(ar_long_k16_y05, gpu_raster_phase20,
    drawT_LONG_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K16_Y05, 7, 5);
)

CESTER_TEST(ar_long_k16_y08, gpu_raster_phase20,
    drawT_LONG_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K16_Y08, 7, 8);
)

CESTER_TEST(ar_long_k16_y11, gpu_raster_phase20,
    drawT_LONG_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K16_Y11, 7, 11);
)

CESTER_TEST(ar_long_k16_y14, gpu_raster_phase20,
    drawT_LONG_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K16_Y14, 7, 14);
)

CESTER_TEST(ar_long_k16_y17, gpu_raster_phase20,
    drawT_LONG_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K16_Y17, 7, 17);
)

CESTER_TEST(ar_long_k16_y20, gpu_raster_phase20,
    drawT_LONG_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_LONG_K16_Y20, 7, 20);
)
