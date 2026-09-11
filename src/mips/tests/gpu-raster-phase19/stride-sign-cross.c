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

// Phase-19 stride-sign + cross-axis sweep. Six triangles, identical
// 10x10 screen footprint to phase-18. Probes are the same five
// screen positions across all families.

CESTER_BODY(

// ---- T_NEG_U_K05: dU/dx = -0.5 (mirror of phase-18's K=5) -------------
//   A=(5,5)/(5,0)  B=(15,5)/(0,0)  C=(5,15)/(5,5)
//   u(x,y) = 7.5 - 0.5*x   v(x,y) = 0.5*y - 2.5
static void drawT_NEG_U_K05(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  5, 0,
                 15, 5,  0, 0,
                 5,  15, 5, 5,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T_NEG_V_K05: dV/dy = -0.5 ----------------------------------------
//   A=(5,5)/(0,5)  B=(15,5)/(5,5)  C=(5,15)/(0,0)
//   u(x,y) = 0.5*x - 2.5   v(x,y) = 7.5 - 0.5*y
static void drawT_NEG_V_K05(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0, 5,
                 15, 5,  5, 5,
                 5,  15, 0, 0,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T_NEG_BOTH_K05: dU/dx = -0.5, dV/dy = -0.5 -----------------------
//   A=(5,5)/(5,5)  B=(15,5)/(0,5)  C=(5,15)/(5,0)
//   u(x,y) = 7.5 - 0.5*x   v(x,y) = 7.5 - 0.5*y
static void drawT_NEG_BOTH_K05(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  5, 5,
                 15, 5,  0, 5,
                 5,  15, 5, 0,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T_NEG_U_K16: dU/dx = -1.6 (stretched negative) -------------------
//   A=(5,5)/(16,0)  B=(15,5)/(0,0)  C=(5,15)/(16,16)
//   u(x,y) = 24 - 1.6*x   v(x,y) = 1.6*y - 8
static void drawT_NEG_U_K16(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  16, 0,
                 15, 5,  0,  0,
                 5,  15, 16, 16,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T_CROSS_45_K05: 45-degree UV rotation, mild ----------------------
//   A=(5,5)/(5,0)  B=(15,5)/(10,5)  C=(5,15)/(0,5)
//   dU/dx = 0.5, dU/dy = -0.5, dV/dx = 0.5, dV/dy = 0.5
//   u(x,y) = 0.5*x - 0.5*y + 5   v(x,y) = 0.5*x + 0.5*y - 5
static void drawT_CROSS_45_K05(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  5,  0,
                 15, 5,  10, 5,
                 5,  15, 0,  5,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T_CROSS_90_K16: 90-degree UV rotation, stretched -----------------
//   A=(5,5)/(0,0)  B=(15,5)/(0,16)  C=(5,15)/(16,0)
//   dU/dx = 0, dU/dy = 1.6, dV/dx = 1.6, dV/dy = 0
//   u(x,y) = 1.6*y - 8   v(x,y) = 1.6*x - 8
static void drawT_CROSS_90_K16(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0,  0,
                 15, 5,  0,  16,
                 5,  15, 16, 0,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// T_NEG_U_K05 probes
// --------------------------------------------------------------------------

CESTER_TEST(ar_neg_u_k05_vertex, gpu_raster_phase19,
    drawT_NEG_U_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_U_K05_VERTEX, 5, 5);
)

CESTER_TEST(ar_neg_u_k05_top_near, gpu_raster_phase19,
    drawT_NEG_U_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_U_K05_TOP_NEAR, 6, 5);
)

CESTER_TEST(ar_neg_u_k05_left_near, gpu_raster_phase19,
    drawT_NEG_U_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_U_K05_LEFT_NEAR, 5, 6);
)

CESTER_TEST(ar_neg_u_k05_interior, gpu_raster_phase19,
    drawT_NEG_U_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_U_K05_INTERIOR, 8, 8);
)

CESTER_TEST(ar_neg_u_k05_top_far, gpu_raster_phase19,
    drawT_NEG_U_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_U_K05_TOP_FAR, 12, 5);
)

// --------------------------------------------------------------------------
// T_NEG_V_K05 probes
// --------------------------------------------------------------------------

CESTER_TEST(ar_neg_v_k05_vertex, gpu_raster_phase19,
    drawT_NEG_V_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_V_K05_VERTEX, 5, 5);
)

CESTER_TEST(ar_neg_v_k05_top_near, gpu_raster_phase19,
    drawT_NEG_V_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_V_K05_TOP_NEAR, 6, 5);
)

CESTER_TEST(ar_neg_v_k05_left_near, gpu_raster_phase19,
    drawT_NEG_V_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_V_K05_LEFT_NEAR, 5, 6);
)

CESTER_TEST(ar_neg_v_k05_interior, gpu_raster_phase19,
    drawT_NEG_V_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_V_K05_INTERIOR, 8, 8);
)

CESTER_TEST(ar_neg_v_k05_top_far, gpu_raster_phase19,
    drawT_NEG_V_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_V_K05_TOP_FAR, 12, 5);
)

// --------------------------------------------------------------------------
// T_NEG_BOTH_K05 probes
// --------------------------------------------------------------------------

CESTER_TEST(ar_neg_both_k05_vertex, gpu_raster_phase19,
    drawT_NEG_BOTH_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_BOTH_K05_VERTEX, 5, 5);
)

CESTER_TEST(ar_neg_both_k05_top_near, gpu_raster_phase19,
    drawT_NEG_BOTH_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_BOTH_K05_TOP_NEAR, 6, 5);
)

CESTER_TEST(ar_neg_both_k05_left_near, gpu_raster_phase19,
    drawT_NEG_BOTH_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_BOTH_K05_LEFT_NEAR, 5, 6);
)

CESTER_TEST(ar_neg_both_k05_interior, gpu_raster_phase19,
    drawT_NEG_BOTH_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_BOTH_K05_INTERIOR, 8, 8);
)

CESTER_TEST(ar_neg_both_k05_top_far, gpu_raster_phase19,
    drawT_NEG_BOTH_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_BOTH_K05_TOP_FAR, 12, 5);
)

// --------------------------------------------------------------------------
// T_NEG_U_K16 probes
// --------------------------------------------------------------------------

CESTER_TEST(ar_neg_u_k16_vertex, gpu_raster_phase19,
    drawT_NEG_U_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_U_K16_VERTEX, 5, 5);
)

CESTER_TEST(ar_neg_u_k16_top_near, gpu_raster_phase19,
    drawT_NEG_U_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_U_K16_TOP_NEAR, 6, 5);
)

CESTER_TEST(ar_neg_u_k16_left_near, gpu_raster_phase19,
    drawT_NEG_U_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_U_K16_LEFT_NEAR, 5, 6);
)

CESTER_TEST(ar_neg_u_k16_interior, gpu_raster_phase19,
    drawT_NEG_U_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_U_K16_INTERIOR, 8, 8);
)

CESTER_TEST(ar_neg_u_k16_top_far, gpu_raster_phase19,
    drawT_NEG_U_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_NEG_U_K16_TOP_FAR, 12, 5);
)

// --------------------------------------------------------------------------
// T_CROSS_45_K05 probes
// --------------------------------------------------------------------------

CESTER_TEST(ar_cross_45_k05_vertex, gpu_raster_phase19,
    drawT_CROSS_45_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_CROSS_45_K05_VERTEX, 5, 5);
)

CESTER_TEST(ar_cross_45_k05_top_near, gpu_raster_phase19,
    drawT_CROSS_45_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_CROSS_45_K05_TOP_NEAR, 6, 5);
)

CESTER_TEST(ar_cross_45_k05_left_near, gpu_raster_phase19,
    drawT_CROSS_45_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_CROSS_45_K05_LEFT_NEAR, 5, 6);
)

CESTER_TEST(ar_cross_45_k05_interior, gpu_raster_phase19,
    drawT_CROSS_45_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_CROSS_45_K05_INTERIOR, 8, 8);
)

CESTER_TEST(ar_cross_45_k05_top_far, gpu_raster_phase19,
    drawT_CROSS_45_K05();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_CROSS_45_K05_TOP_FAR, 12, 5);
)

// --------------------------------------------------------------------------
// T_CROSS_90_K16 probes
// --------------------------------------------------------------------------

CESTER_TEST(ar_cross_90_k16_vertex, gpu_raster_phase19,
    drawT_CROSS_90_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_CROSS_90_K16_VERTEX, 5, 5);
)

CESTER_TEST(ar_cross_90_k16_top_near, gpu_raster_phase19,
    drawT_CROSS_90_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_CROSS_90_K16_TOP_NEAR, 6, 5);
)

CESTER_TEST(ar_cross_90_k16_left_near, gpu_raster_phase19,
    drawT_CROSS_90_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_CROSS_90_K16_LEFT_NEAR, 5, 6);
)

CESTER_TEST(ar_cross_90_k16_interior, gpu_raster_phase19,
    drawT_CROSS_90_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_CROSS_90_K16_INTERIOR, 8, 8);
)

CESTER_TEST(ar_cross_90_k16_top_far, gpu_raster_phase19,
    drawT_CROSS_90_K16();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_CROSS_90_K16_TOP_FAR, 12, 5);
)
