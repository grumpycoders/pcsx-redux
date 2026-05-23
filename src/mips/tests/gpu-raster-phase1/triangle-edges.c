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

// Triangle-edges suite for the gpu-raster test binary.
//
// This file is #included from gpu-raster.c (cester is single-TU). It uses
// helpers defined in raster-helpers.h and expected-value macros defined in
// raster-expected.h, both of which gpu-raster.c includes before pulling in
// this file.
//
// Each CESTER_TEST is one pixel-of-interest. Tests are self-contained: they
// reset the GPU, fill the test region with the sentinel, draw the triangle
// under test, and read back exactly one pixel. cester reports failures as
// "expected X, received Y at file:line" and the ASSERT_PIXEL_EQ macro also
// emits an OBS line so a hardware capture run produces a complete log
// independent of cester's pass/fail accounting.

// --------------------------------------------------------------------------
// Per-triangle draw helpers
// --------------------------------------------------------------------------
//
// All static helpers must be wrapped in CESTER_BODY(...) because cester
// re-#includes __BASE_FILE__ multiple times during its forward-declaration
// + array-build + function-body passes. CESTER_BODY's expansion is empty
// on the early passes and contains its argument only on the final pass,
// so a static helper inside CESTER_BODY is defined exactly once. See
// cop0/cester-cop0.c for the canonical pattern.

CESTER_BODY(

// Triangle A: 4x4 right-angle, vertices (0,0),(4,0),(0,4), color RED.
static void rasterDrawTriA(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 4, 0, 0, 4);
    rasterFlushPrimitive();
}

// Triangle B: 1-pixel degenerate at near corner, (0,0),(1,0),(0,1), RED.
static void rasterDrawTriB(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 4, 4);
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 1, 0, 0, 1);
    rasterFlushPrimitive();
}

// Triangle C: 1-pixel degenerate at far corner.
static void rasterDrawTriC(void) {
    rasterReset();
    rasterClearTestRegion(1016, 504, 8, 8);
    rasterFlatTri(RASTER_CMD_BLUE, 1019, 507, 1020, 507, 1019, 508);
    rasterFlushPrimitive();
}

// Triangle D: vertical-right-edge, (0,0),(4,0),(4,4), GREEN.
static void rasterDrawTriD(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatTri(RASTER_CMD_GREEN, 0, 0, 4, 0, 4, 4);
    rasterFlushPrimitive();
}

// Triangle E: horizontal-top-edge isoceles, (0,0),(4,0),(2,4), RED.
static void rasterDrawTriE(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 4, 0, 2, 4);
    rasterFlushPrimitive();
}

// Triangle F: collinear-diagonal, (0,0),(2,2),(4,4), WHITE.
static void rasterDrawTriF(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatTri(RASTER_CMD_WHITE, 0, 0, 2, 2, 4, 4);
    rasterFlushPrimitive();
}

// Triangle G: collinear-horizontal, (0,0),(10,0),(5,0), WHITE.
static void rasterDrawTriG(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 8);
    rasterFlatTri(RASTER_CMD_WHITE, 0, 0, 10, 0, 5, 0);
    rasterFlushPrimitive();
}

// Triangle H: collinear-vertical, (0,0),(0,10),(0,5), WHITE.
static void rasterDrawTriH(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 8, 16);
    rasterFlatTri(RASTER_CMD_WHITE, 0, 0, 0, 10, 0, 5);
    rasterFlushPrimitive();
}

// Triangle I: xmax==xmin single-pixel span at top. (0,0),(2,1),(0,2), WHITE.
// This is the audit's soft.cc:2547/2593 critical case: the top row of this
// triangle has the right-edge xmax equal to xmin (single-pixel span). Soft
// renderer fast path keeps the pixel; slow path drops it.
static void rasterDrawTriI(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 8, 8);
    rasterFlatTri(RASTER_CMD_WHITE, 0, 0, 2, 1, 0, 2);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// Triangle A: 4x4 right-angle - full interior + complement
// --------------------------------------------------------------------------

CESTER_TEST(triA_pixel_0_0, gpu_raster_phase1,
    rasterDrawTriA();
    ASSERT_PIXEL_EQ(EXPECT_TRI_A_PIXEL_0_0, 0, 0);
)

CESTER_TEST(triA_pixel_1_0, gpu_raster_phase1,
    rasterDrawTriA();
    ASSERT_PIXEL_EQ(EXPECT_TRI_A_PIXEL_1_0, 1, 0);
)

CESTER_TEST(triA_pixel_2_0, gpu_raster_phase1,
    rasterDrawTriA();
    ASSERT_PIXEL_EQ(EXPECT_TRI_A_PIXEL_2_0, 2, 0);
)

CESTER_TEST(triA_pixel_3_0, gpu_raster_phase1,
    rasterDrawTriA();
    ASSERT_PIXEL_EQ(EXPECT_TRI_A_PIXEL_3_0, 3, 0);
)

CESTER_TEST(triA_pixel_4_0_right_edge, gpu_raster_phase1,
    rasterDrawTriA();
    ASSERT_PIXEL_EQ(EXPECT_TRI_A_PIXEL_4_0, 4, 0);
)

CESTER_TEST(triA_pixel_0_1, gpu_raster_phase1,
    rasterDrawTriA();
    ASSERT_PIXEL_EQ(EXPECT_TRI_A_PIXEL_0_1, 0, 1);
)

CESTER_TEST(triA_pixel_2_1, gpu_raster_phase1,
    rasterDrawTriA();
    ASSERT_PIXEL_EQ(EXPECT_TRI_A_PIXEL_2_1, 2, 1);
)

CESTER_TEST(triA_pixel_3_1_hypotenuse, gpu_raster_phase1,
    rasterDrawTriA();
    ASSERT_PIXEL_EQ(EXPECT_TRI_A_PIXEL_3_1, 3, 1);
)

CESTER_TEST(triA_pixel_1_2, gpu_raster_phase1,
    rasterDrawTriA();
    ASSERT_PIXEL_EQ(EXPECT_TRI_A_PIXEL_1_2, 1, 2);
)

CESTER_TEST(triA_pixel_2_2_hypotenuse, gpu_raster_phase1,
    rasterDrawTriA();
    ASSERT_PIXEL_EQ(EXPECT_TRI_A_PIXEL_2_2, 2, 2);
)

CESTER_TEST(triA_pixel_0_3, gpu_raster_phase1,
    rasterDrawTriA();
    ASSERT_PIXEL_EQ(EXPECT_TRI_A_PIXEL_0_3, 0, 3);
)

CESTER_TEST(triA_pixel_1_3_hypotenuse, gpu_raster_phase1,
    rasterDrawTriA();
    ASSERT_PIXEL_EQ(EXPECT_TRI_A_PIXEL_1_3, 1, 3);
)

CESTER_TEST(triA_pixel_0_4_bottom_edge, gpu_raster_phase1,
    rasterDrawTriA();
    ASSERT_PIXEL_EQ(EXPECT_TRI_A_PIXEL_0_4, 0, 4);
)

// --------------------------------------------------------------------------
// Triangle B: 1-pixel degenerate at near corner
// --------------------------------------------------------------------------

CESTER_TEST(triB_pixel_0_0, gpu_raster_phase1,
    rasterDrawTriB();
    ASSERT_PIXEL_EQ(EXPECT_TRI_B_PIXEL_0_0, 0, 0);
)

CESTER_TEST(triB_pixel_1_0, gpu_raster_phase1,
    rasterDrawTriB();
    ASSERT_PIXEL_EQ(EXPECT_TRI_B_PIXEL_1_0, 1, 0);
)

CESTER_TEST(triB_pixel_0_1, gpu_raster_phase1,
    rasterDrawTriB();
    ASSERT_PIXEL_EQ(EXPECT_TRI_B_PIXEL_0_1, 0, 1);
)

CESTER_TEST(triB_pixel_1_1, gpu_raster_phase1,
    rasterDrawTriB();
    ASSERT_PIXEL_EQ(EXPECT_TRI_B_PIXEL_1_1, 1, 1);
)

// --------------------------------------------------------------------------
// Triangle C: 1-pixel degenerate at far corner of draw area
// --------------------------------------------------------------------------

CESTER_TEST(triC_pixel_1019_507, gpu_raster_phase1,
    rasterDrawTriC();
    ASSERT_PIXEL_EQ(EXPECT_TRI_C_PIXEL_1019_507, 1019, 507);
)

CESTER_TEST(triC_pixel_1020_507, gpu_raster_phase1,
    rasterDrawTriC();
    ASSERT_PIXEL_EQ(EXPECT_TRI_C_PIXEL_1020_507, 1020, 507);
)

CESTER_TEST(triC_pixel_1019_508, gpu_raster_phase1,
    rasterDrawTriC();
    ASSERT_PIXEL_EQ(EXPECT_TRI_C_PIXEL_1019_508, 1019, 508);
)

CESTER_TEST(triC_pixel_1020_508, gpu_raster_phase1,
    rasterDrawTriC();
    ASSERT_PIXEL_EQ(EXPECT_TRI_C_PIXEL_1020_508, 1020, 508);
)

// --------------------------------------------------------------------------
// Triangle D: vertical right edge - tests right-edge inclusion
// --------------------------------------------------------------------------

CESTER_TEST(triD_pixel_0_0_top_left, gpu_raster_phase1,
    rasterDrawTriD();
    ASSERT_PIXEL_EQ(EXPECT_TRI_D_PIXEL_0_0, 0, 0);
)

CESTER_TEST(triD_pixel_3_0_top_inner, gpu_raster_phase1,
    rasterDrawTriD();
    ASSERT_PIXEL_EQ(EXPECT_TRI_D_PIXEL_3_0, 3, 0);
)

CESTER_TEST(triD_pixel_4_0_top_right_corner, gpu_raster_phase1,
    rasterDrawTriD();
    ASSERT_PIXEL_EQ(EXPECT_TRI_D_PIXEL_4_0, 4, 0);
)

CESTER_TEST(triD_pixel_0_1_left_of_diag, gpu_raster_phase1,
    rasterDrawTriD();
    ASSERT_PIXEL_EQ(EXPECT_TRI_D_PIXEL_0_1, 0, 1);
)

CESTER_TEST(triD_pixel_1_1, gpu_raster_phase1,
    rasterDrawTriD();
    ASSERT_PIXEL_EQ(EXPECT_TRI_D_PIXEL_1_1, 1, 1);
)

CESTER_TEST(triD_pixel_3_1, gpu_raster_phase1,
    rasterDrawTriD();
    ASSERT_PIXEL_EQ(EXPECT_TRI_D_PIXEL_3_1, 3, 1);
)

CESTER_TEST(triD_pixel_4_1_right_edge, gpu_raster_phase1,
    rasterDrawTriD();
    ASSERT_PIXEL_EQ(EXPECT_TRI_D_PIXEL_4_1, 4, 1);
)

CESTER_TEST(triD_pixel_3_3_bottom_right_interior, gpu_raster_phase1,
    rasterDrawTriD();
    ASSERT_PIXEL_EQ(EXPECT_TRI_D_PIXEL_3_3, 3, 3);
)

CESTER_TEST(triD_pixel_4_4_bottom_right_vertex, gpu_raster_phase1,
    rasterDrawTriD();
    ASSERT_PIXEL_EQ(EXPECT_TRI_D_PIXEL_4_4, 4, 4);
)

// --------------------------------------------------------------------------
// Triangle E: horizontal top edge - tests top-edge inclusion
// --------------------------------------------------------------------------

CESTER_TEST(triE_pixel_0_0_top_left_of_top, gpu_raster_phase1,
    rasterDrawTriE();
    ASSERT_PIXEL_EQ(EXPECT_TRI_E_PIXEL_0_0, 0, 0);
)

CESTER_TEST(triE_pixel_3_0_top_inner, gpu_raster_phase1,
    rasterDrawTriE();
    ASSERT_PIXEL_EQ(EXPECT_TRI_E_PIXEL_3_0, 3, 0);
)

CESTER_TEST(triE_pixel_4_0_top_right_vertex, gpu_raster_phase1,
    rasterDrawTriE();
    ASSERT_PIXEL_EQ(EXPECT_TRI_E_PIXEL_4_0, 4, 0);
)

CESTER_TEST(triE_pixel_1_1, gpu_raster_phase1,
    rasterDrawTriE();
    ASSERT_PIXEL_EQ(EXPECT_TRI_E_PIXEL_1_1, 1, 1);
)

CESTER_TEST(triE_pixel_3_1, gpu_raster_phase1,
    rasterDrawTriE();
    ASSERT_PIXEL_EQ(EXPECT_TRI_E_PIXEL_3_1, 3, 1);
)

CESTER_TEST(triE_pixel_2_2_center, gpu_raster_phase1,
    rasterDrawTriE();
    ASSERT_PIXEL_EQ(EXPECT_TRI_E_PIXEL_2_2, 2, 2);
)

CESTER_TEST(triE_pixel_2_3_near_apex, gpu_raster_phase1,
    rasterDrawTriE();
    ASSERT_PIXEL_EQ(EXPECT_TRI_E_PIXEL_2_3, 2, 3);
)

CESTER_TEST(triE_pixel_2_4_apex, gpu_raster_phase1,
    rasterDrawTriE();
    ASSERT_PIXEL_EQ(EXPECT_TRI_E_PIXEL_2_4, 2, 4);
)

// --------------------------------------------------------------------------
// Triangle F: collinear-diagonal - expects zero fill
// --------------------------------------------------------------------------

CESTER_TEST(triF_collinear_diag_pixel_0_0, gpu_raster_phase1,
    rasterDrawTriF();
    ASSERT_PIXEL_EQ(EXPECT_TRI_F_PIXEL_0_0, 0, 0);
)

CESTER_TEST(triF_collinear_diag_pixel_1_1, gpu_raster_phase1,
    rasterDrawTriF();
    ASSERT_PIXEL_EQ(EXPECT_TRI_F_PIXEL_1_1, 1, 1);
)

CESTER_TEST(triF_collinear_diag_pixel_2_2, gpu_raster_phase1,
    rasterDrawTriF();
    ASSERT_PIXEL_EQ(EXPECT_TRI_F_PIXEL_2_2, 2, 2);
)

CESTER_TEST(triF_collinear_diag_pixel_4_4, gpu_raster_phase1,
    rasterDrawTriF();
    ASSERT_PIXEL_EQ(EXPECT_TRI_F_PIXEL_4_4, 4, 4);
)

// --------------------------------------------------------------------------
// Triangle G: collinear-horizontal - expects zero fill
// --------------------------------------------------------------------------

CESTER_TEST(triG_collinear_horiz_pixel_0_0, gpu_raster_phase1,
    rasterDrawTriG();
    ASSERT_PIXEL_EQ(EXPECT_TRI_G_PIXEL_0_0, 0, 0);
)

CESTER_TEST(triG_collinear_horiz_pixel_5_0, gpu_raster_phase1,
    rasterDrawTriG();
    ASSERT_PIXEL_EQ(EXPECT_TRI_G_PIXEL_5_0, 5, 0);
)

CESTER_TEST(triG_collinear_horiz_pixel_10_0, gpu_raster_phase1,
    rasterDrawTriG();
    ASSERT_PIXEL_EQ(EXPECT_TRI_G_PIXEL_10_0, 10, 0);
)

// --------------------------------------------------------------------------
// Triangle H: collinear-vertical - expects zero fill
// --------------------------------------------------------------------------

CESTER_TEST(triH_collinear_vert_pixel_0_0, gpu_raster_phase1,
    rasterDrawTriH();
    ASSERT_PIXEL_EQ(EXPECT_TRI_H_PIXEL_0_0, 0, 0);
)

CESTER_TEST(triH_collinear_vert_pixel_0_5, gpu_raster_phase1,
    rasterDrawTriH();
    ASSERT_PIXEL_EQ(EXPECT_TRI_H_PIXEL_0_5, 0, 5);
)

CESTER_TEST(triH_collinear_vert_pixel_0_10, gpu_raster_phase1,
    rasterDrawTriH();
    ASSERT_PIXEL_EQ(EXPECT_TRI_H_PIXEL_0_10, 0, 10);
)

// --------------------------------------------------------------------------
// Triangle I: xmax==xmin top row - CRITICAL audit case (soft.cc:2547/2593)
// --------------------------------------------------------------------------

CESTER_TEST(triI_xmax_eq_xmin_pixel_0_0, gpu_raster_phase1,
    rasterDrawTriI();
    ASSERT_PIXEL_EQ(EXPECT_TRI_I_PIXEL_0_0, 0, 0);
)

CESTER_TEST(triI_xmax_eq_xmin_pixel_1_0, gpu_raster_phase1,
    rasterDrawTriI();
    ASSERT_PIXEL_EQ(EXPECT_TRI_I_PIXEL_1_0, 1, 0);
)

CESTER_TEST(triI_xmax_eq_xmin_pixel_0_1, gpu_raster_phase1,
    rasterDrawTriI();
    ASSERT_PIXEL_EQ(EXPECT_TRI_I_PIXEL_0_1, 0, 1);
)

CESTER_TEST(triI_xmax_eq_xmin_pixel_1_1, gpu_raster_phase1,
    rasterDrawTriI();
    ASSERT_PIXEL_EQ(EXPECT_TRI_I_PIXEL_1_1, 1, 1);
)

CESTER_TEST(triI_xmax_eq_xmin_pixel_0_2_bottom_excluded, gpu_raster_phase1,
    rasterDrawTriI();
    ASSERT_PIXEL_EQ(EXPECT_TRI_I_PIXEL_0_2, 0, 2);
)
