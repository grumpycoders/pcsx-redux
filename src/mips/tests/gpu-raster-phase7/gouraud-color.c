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

// Gouraud color precision suite. PS1 GPU gouraud interpolation uses
// integer-truncated per-row and per-pixel-X color deltas. This suite
// probes the resulting truncation behavior in three independent
// dimensions:
//
//   1. Triangle size sweep (small / medium / large). Small triangles
//      have lossy per-row deltas; large triangles drift across many
//      rows. Same shape, different precision pressure.
//
//   2. R-only single-axis gradients (vertical and horizontal). Strip
//      one axis of variation so the OBS log directly shows where the
//      accumulator landed at each step.
//
//   3. Vertex-order permutations. Hardware should be order-independent
//      and the soft renderer's longest-edge sort should produce the
//      same accumulators regardless of caller-supplied ordering.

CESTER_BODY(

// --------------------------------------------------------------------------
// GC: Canonical RGB-vertex triangle at three sizes
// --------------------------------------------------------------------------

static void drawGC1(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterGouraudTri(RASTER_CMD_RED,   0, 0,
                     RASTER_CMD_GREEN, 7, 0,
                     RASTER_CMD_BLUE,  0, 7);
    rasterFlushPrimitive();
}

static void drawGC2(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 48, 48);
    rasterGouraudTri(RASTER_CMD_RED,   0,  0,
                     RASTER_CMD_GREEN, 31, 0,
                     RASTER_CMD_BLUE,  0,  31);
    rasterFlushPrimitive();
}

static void drawGC3(void) {
    rasterReset();
    /* Draw region just over 128x128 so we can probe out-of-tri sentinels too. */
    rasterClearTestRegion(0, 0, 144, 144);
    rasterGouraudTri(RASTER_CMD_RED,   0,   0,
                     RASTER_CMD_GREEN, 127, 0,
                     RASTER_CMD_BLUE,  0,   127);
    rasterFlushPrimitive();
}

// --------------------------------------------------------------------------
// GV: R-only vertical gradient. Apex (0,0) at max R, base at R=0.
// Width matches height so the triangle is the same shape as GC but
// only the R channel varies. Probe column x=0 to read the left-edge
// accumulator directly.
// --------------------------------------------------------------------------

static void drawGV(int n) {
    /* R apex, R=0 elsewhere. */
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    rasterGouraudTri(RASTER_CMD_RED, 0, 0,
                     0u,             (int16_t)n, 0,
                     0u,             0, (int16_t)n);
    rasterFlushPrimitive();
}

// --------------------------------------------------------------------------
// GH: R-only horizontal gradient. Top edge interpolates R 31->0 across
// W. Left edge stays at R=31 down the height (apex and v2 both R=31).
// --------------------------------------------------------------------------

static void drawGH(int n) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    rasterGouraudTri(RASTER_CMD_RED, 0, 0,
                     0u,             (int16_t)n, 0,
                     RASTER_CMD_RED, 0, (int16_t)n);
    rasterFlushPrimitive();
}

// --------------------------------------------------------------------------
// GS: Saturation / vertex-exactness probes.
// --------------------------------------------------------------------------

static void drawGSNearMax(void) {
    /* Apex R=31, others R=30 (1 LSB below max in 5-bit space). 16x16. */
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    rasterGouraudTri(rasterCmdColor(31, 0, 0), 0,  0,
                     rasterCmdColor(30, 0, 0), 16, 0,
                     rasterCmdColor(30, 0, 0), 0,  16);
    rasterFlushPrimitive();
}

static void drawGSNearMin(void) {
    /* Apex R=0, others R=1 (1 LSB above min). 16x16. */
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    rasterGouraudTri(rasterCmdColor(0, 0, 0), 0,  0,
                     rasterCmdColor(1, 0, 0), 16, 0,
                     rasterCmdColor(1, 0, 0), 0,  16);
    rasterFlushPrimitive();
}

static void drawGSHalfOfLSB(void) {
    /* Apex R=1, others R=0. 8x8. The accumulator drops smoothly past
       the 5-bit truncation point - hardware may keep R=1 for the first
       few rows and quantize to 0 below. */
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterGouraudTri(rasterCmdColor(1, 0, 0), 0, 0,
                     rasterCmdColor(0, 0, 0), 8, 0,
                     rasterCmdColor(0, 0, 0), 0, 8);
    rasterFlushPrimitive();
}

// --------------------------------------------------------------------------
// GD: Dither ON for the canonical 32x32 triangle.
// --------------------------------------------------------------------------

static void drawGD(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 48, 48);
    rasterSetDither(1);
    rasterGouraudTri(RASTER_CMD_RED,   0,  0,
                     RASTER_CMD_GREEN, 31, 0,
                     RASTER_CMD_BLUE,  0,  31);
    rasterFlushPrimitive();
    rasterSetDither(0);
}

// --------------------------------------------------------------------------
// GO: Vertex-order permutations of the GC1 triangle.
// Same three vertex/color pairs, six orderings.
// --------------------------------------------------------------------------

#define GO_TRI_R_FIRST_GB() \
    rasterGouraudTri(RASTER_CMD_RED, 0, 0, RASTER_CMD_GREEN, 7, 0, RASTER_CMD_BLUE, 0, 7)
#define GO_TRI_R_FIRST_BG() \
    rasterGouraudTri(RASTER_CMD_RED, 0, 0, RASTER_CMD_BLUE, 0, 7, RASTER_CMD_GREEN, 7, 0)
#define GO_TRI_G_FIRST_RB() \
    rasterGouraudTri(RASTER_CMD_GREEN, 7, 0, RASTER_CMD_RED, 0, 0, RASTER_CMD_BLUE, 0, 7)
#define GO_TRI_G_FIRST_BR() \
    rasterGouraudTri(RASTER_CMD_GREEN, 7, 0, RASTER_CMD_BLUE, 0, 7, RASTER_CMD_RED, 0, 0)
#define GO_TRI_B_FIRST_RG() \
    rasterGouraudTri(RASTER_CMD_BLUE, 0, 7, RASTER_CMD_RED, 0, 0, RASTER_CMD_GREEN, 7, 0)
#define GO_TRI_B_FIRST_GR() \
    rasterGouraudTri(RASTER_CMD_BLUE, 0, 7, RASTER_CMD_GREEN, 7, 0, RASTER_CMD_RED, 0, 0)

static void drawGOPerm(int perm) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    switch (perm) {
        case 0: GO_TRI_R_FIRST_GB(); break;
        case 1: GO_TRI_R_FIRST_BG(); break;
        case 2: GO_TRI_G_FIRST_RB(); break;
        case 3: GO_TRI_G_FIRST_BR(); break;
        case 4: GO_TRI_B_FIRST_RG(); break;
        case 5: GO_TRI_B_FIRST_GR(); break;
    }
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// GC1: 8x8 canonical RGB triangle
// --------------------------------------------------------------------------

CESTER_TEST(gc1_v0_apex_red, gpu_raster_phase7,
    drawGC1();
    /* Apex pixel = pure R at vertex 0. */
    ASSERT_PIXEL_EQ(GC1_V0_R, 0, 0);
)

CESTER_TEST(gc1_top_x4, gpu_raster_phase7,
    drawGC1();
    /* Mid R-G edge at (4, 0). Top-left rule includes top edge. */
    ASSERT_PIXEL_EQ(GC1_TOP_X4, 4, 0);
)

CESTER_TEST(gc1_left_y4, gpu_raster_phase7,
    drawGC1();
    /* Mid R-B edge at (0, 4). Left edge included. */
    ASSERT_PIXEL_EQ(GC1_LEFT_Y4, 0, 4);
)

CESTER_TEST(gc1_interior_1_1, gpu_raster_phase7,
    drawGC1();
    ASSERT_PIXEL_EQ(GC1_INTERIOR_1_1, 1, 1);
)

CESTER_TEST(gc1_interior_2_2, gpu_raster_phase7,
    drawGC1();
    ASSERT_PIXEL_EQ(GC1_INTERIOR_2_2, 2, 2);
)

CESTER_TEST(gc1_interior_3_3, gpu_raster_phase7,
    drawGC1();
    ASSERT_PIXEL_EQ(GC1_INTERIOR_3_3, 3, 3);
)

CESTER_TEST(gc1_interior_1_3, gpu_raster_phase7,
    drawGC1();
    /* Below diagonal: more B weight than G. */
    ASSERT_PIXEL_EQ(GC1_INTERIOR_1_3, 1, 3);
)

CESTER_TEST(gc1_interior_3_1, gpu_raster_phase7,
    drawGC1();
    /* Above diagonal: more G weight than B. */
    ASSERT_PIXEL_EQ(GC1_INTERIOR_3_1, 3, 1);
)

// --------------------------------------------------------------------------
// GC2: 32x32 canonical RGB triangle
// --------------------------------------------------------------------------

CESTER_TEST(gc2_v0_apex_red, gpu_raster_phase7,
    drawGC2();
    ASSERT_PIXEL_EQ(GC2_V0_R, 0, 0);
)

CESTER_TEST(gc2_top_x16, gpu_raster_phase7,
    drawGC2();
    ASSERT_PIXEL_EQ(GC2_TOP_X16, 16, 0);
)

CESTER_TEST(gc2_left_y16, gpu_raster_phase7,
    drawGC2();
    ASSERT_PIXEL_EQ(GC2_LEFT_Y16, 0, 16);
)

CESTER_TEST(gc2_interior_8_8, gpu_raster_phase7,
    drawGC2();
    ASSERT_PIXEL_EQ(GC2_INTERIOR_8_8, 8, 8);
)

CESTER_TEST(gc2_interior_16_8, gpu_raster_phase7,
    drawGC2();
    ASSERT_PIXEL_EQ(GC2_INTERIOR_16_8, 16, 8);
)

CESTER_TEST(gc2_interior_8_16, gpu_raster_phase7,
    drawGC2();
    ASSERT_PIXEL_EQ(GC2_INTERIOR_8_16, 8, 16);
)

CESTER_TEST(gc2_interior_1_1, gpu_raster_phase7,
    drawGC2();
    ASSERT_PIXEL_EQ(GC2_INTERIOR_1_1, 1, 1);
)

CESTER_TEST(gc2_interior_30_0, gpu_raster_phase7,
    drawGC2();
    /* Near right vertex (32,0). Top edge included, top-left includes
       this pixel if right xmax includes it. */
    ASSERT_PIXEL_EQ(GC2_INTERIOR_30_0, 30, 0);
)

// --------------------------------------------------------------------------
// GC3: 128x128 canonical RGB triangle
// --------------------------------------------------------------------------

CESTER_TEST(gc3_v0_apex_red, gpu_raster_phase7,
    drawGC3();
    ASSERT_PIXEL_EQ(GC3_V0_R, 0, 0);
)

CESTER_TEST(gc3_top_x64, gpu_raster_phase7,
    drawGC3();
    ASSERT_PIXEL_EQ(GC3_TOP_X64, 64, 0);
)

CESTER_TEST(gc3_left_y64, gpu_raster_phase7,
    drawGC3();
    ASSERT_PIXEL_EQ(GC3_LEFT_Y64, 0, 64);
)

CESTER_TEST(gc3_interior_32_32, gpu_raster_phase7,
    drawGC3();
    ASSERT_PIXEL_EQ(GC3_INTERIOR_32_32, 32, 32);
)

CESTER_TEST(gc3_interior_1_1, gpu_raster_phase7,
    drawGC3();
    ASSERT_PIXEL_EQ(GC3_INTERIOR_1_1, 1, 1);
)

CESTER_TEST(gc3_interior_64_32, gpu_raster_phase7,
    drawGC3();
    ASSERT_PIXEL_EQ(GC3_INTERIOR_64_32, 64, 32);
)

CESTER_TEST(gc3_interior_32_64, gpu_raster_phase7,
    drawGC3();
    ASSERT_PIXEL_EQ(GC3_INTERIOR_32_64, 32, 64);
)

CESTER_TEST(gc3_interior_96_16, gpu_raster_phase7,
    drawGC3();
    ASSERT_PIXEL_EQ(GC3_INTERIOR_96_16, 96, 16);
)

// --------------------------------------------------------------------------
// GV: Vertical R-only gradient
// --------------------------------------------------------------------------

CESTER_TEST(gv3_x0_y0, gpu_raster_phase7,
    drawGV(3);
    ASSERT_PIXEL_EQ(GV3_X0_Y0, 0, 0);
)
CESTER_TEST(gv3_x0_y1, gpu_raster_phase7,
    drawGV(3);
    ASSERT_PIXEL_EQ(GV3_X0_Y1, 0, 1);
)
CESTER_TEST(gv3_x0_y2, gpu_raster_phase7,
    drawGV(3);
    ASSERT_PIXEL_EQ(GV3_X0_Y2, 0, 2);
)

CESTER_TEST(gv5_x0_y0, gpu_raster_phase7,
    drawGV(5);
    ASSERT_PIXEL_EQ(GV5_X0_Y0, 0, 0);
)
CESTER_TEST(gv5_x0_y1, gpu_raster_phase7,
    drawGV(5);
    ASSERT_PIXEL_EQ(GV5_X0_Y1, 0, 1);
)
CESTER_TEST(gv5_x0_y2, gpu_raster_phase7,
    drawGV(5);
    ASSERT_PIXEL_EQ(GV5_X0_Y2, 0, 2);
)
CESTER_TEST(gv5_x0_y3, gpu_raster_phase7,
    drawGV(5);
    ASSERT_PIXEL_EQ(GV5_X0_Y3, 0, 3);
)
CESTER_TEST(gv5_x0_y4, gpu_raster_phase7,
    drawGV(5);
    ASSERT_PIXEL_EQ(GV5_X0_Y4, 0, 4);
)

CESTER_TEST(gv7_x0_y0, gpu_raster_phase7, drawGV(7); ASSERT_PIXEL_EQ(GV7_X0_Y0, 0, 0); )
CESTER_TEST(gv7_x0_y1, gpu_raster_phase7, drawGV(7); ASSERT_PIXEL_EQ(GV7_X0_Y1, 0, 1); )
CESTER_TEST(gv7_x0_y2, gpu_raster_phase7, drawGV(7); ASSERT_PIXEL_EQ(GV7_X0_Y2, 0, 2); )
CESTER_TEST(gv7_x0_y3, gpu_raster_phase7, drawGV(7); ASSERT_PIXEL_EQ(GV7_X0_Y3, 0, 3); )
CESTER_TEST(gv7_x0_y4, gpu_raster_phase7, drawGV(7); ASSERT_PIXEL_EQ(GV7_X0_Y4, 0, 4); )
CESTER_TEST(gv7_x0_y5, gpu_raster_phase7, drawGV(7); ASSERT_PIXEL_EQ(GV7_X0_Y5, 0, 5); )
CESTER_TEST(gv7_x0_y6, gpu_raster_phase7, drawGV(7); ASSERT_PIXEL_EQ(GV7_X0_Y6, 0, 6); )

CESTER_TEST(gv11_x0_y0,  gpu_raster_phase7, drawGV(11); ASSERT_PIXEL_EQ(GV11_X0_Y0,  0,  0); )
CESTER_TEST(gv11_x0_y2,  gpu_raster_phase7, drawGV(11); ASSERT_PIXEL_EQ(GV11_X0_Y2,  0,  2); )
CESTER_TEST(gv11_x0_y4,  gpu_raster_phase7, drawGV(11); ASSERT_PIXEL_EQ(GV11_X0_Y4,  0,  4); )
CESTER_TEST(gv11_x0_y6,  gpu_raster_phase7, drawGV(11); ASSERT_PIXEL_EQ(GV11_X0_Y6,  0,  6); )
CESTER_TEST(gv11_x0_y8,  gpu_raster_phase7, drawGV(11); ASSERT_PIXEL_EQ(GV11_X0_Y8,  0,  8); )
CESTER_TEST(gv11_x0_y10, gpu_raster_phase7, drawGV(11); ASSERT_PIXEL_EQ(GV11_X0_Y10, 0, 10); )

// --------------------------------------------------------------------------
// GH: Horizontal R-only gradient
// --------------------------------------------------------------------------

CESTER_TEST(gh3_y0_x0, gpu_raster_phase7, drawGH(3); ASSERT_PIXEL_EQ(GH3_Y0_X0, 0, 0); )
CESTER_TEST(gh3_y0_x1, gpu_raster_phase7, drawGH(3); ASSERT_PIXEL_EQ(GH3_Y0_X1, 1, 0); )
CESTER_TEST(gh3_y0_x2, gpu_raster_phase7, drawGH(3); ASSERT_PIXEL_EQ(GH3_Y0_X2, 2, 0); )

CESTER_TEST(gh5_y0_x0, gpu_raster_phase7, drawGH(5); ASSERT_PIXEL_EQ(GH5_Y0_X0, 0, 0); )
CESTER_TEST(gh5_y0_x1, gpu_raster_phase7, drawGH(5); ASSERT_PIXEL_EQ(GH5_Y0_X1, 1, 0); )
CESTER_TEST(gh5_y0_x2, gpu_raster_phase7, drawGH(5); ASSERT_PIXEL_EQ(GH5_Y0_X2, 2, 0); )
CESTER_TEST(gh5_y0_x3, gpu_raster_phase7, drawGH(5); ASSERT_PIXEL_EQ(GH5_Y0_X3, 3, 0); )
CESTER_TEST(gh5_y0_x4, gpu_raster_phase7, drawGH(5); ASSERT_PIXEL_EQ(GH5_Y0_X4, 4, 0); )

CESTER_TEST(gh7_y0_x0, gpu_raster_phase7, drawGH(7); ASSERT_PIXEL_EQ(GH7_Y0_X0, 0, 0); )
CESTER_TEST(gh7_y0_x1, gpu_raster_phase7, drawGH(7); ASSERT_PIXEL_EQ(GH7_Y0_X1, 1, 0); )
CESTER_TEST(gh7_y0_x2, gpu_raster_phase7, drawGH(7); ASSERT_PIXEL_EQ(GH7_Y0_X2, 2, 0); )
CESTER_TEST(gh7_y0_x3, gpu_raster_phase7, drawGH(7); ASSERT_PIXEL_EQ(GH7_Y0_X3, 3, 0); )
CESTER_TEST(gh7_y0_x4, gpu_raster_phase7, drawGH(7); ASSERT_PIXEL_EQ(GH7_Y0_X4, 4, 0); )
CESTER_TEST(gh7_y0_x5, gpu_raster_phase7, drawGH(7); ASSERT_PIXEL_EQ(GH7_Y0_X5, 5, 0); )
CESTER_TEST(gh7_y0_x6, gpu_raster_phase7, drawGH(7); ASSERT_PIXEL_EQ(GH7_Y0_X6, 6, 0); )

CESTER_TEST(gh11_y0_x0,  gpu_raster_phase7, drawGH(11); ASSERT_PIXEL_EQ(GH11_Y0_X0,  0,  0); )
CESTER_TEST(gh11_y0_x2,  gpu_raster_phase7, drawGH(11); ASSERT_PIXEL_EQ(GH11_Y0_X2,  2,  0); )
CESTER_TEST(gh11_y0_x4,  gpu_raster_phase7, drawGH(11); ASSERT_PIXEL_EQ(GH11_Y0_X4,  4,  0); )
CESTER_TEST(gh11_y0_x6,  gpu_raster_phase7, drawGH(11); ASSERT_PIXEL_EQ(GH11_Y0_X6,  6,  0); )
CESTER_TEST(gh11_y0_x8,  gpu_raster_phase7, drawGH(11); ASSERT_PIXEL_EQ(GH11_Y0_X8,  8,  0); )
CESTER_TEST(gh11_y0_x10, gpu_raster_phase7, drawGH(11); ASSERT_PIXEL_EQ(GH11_Y0_X10, 10, 0); )

// --------------------------------------------------------------------------
// GS: Saturation / vertex-exactness
// --------------------------------------------------------------------------

CESTER_TEST(gs_near_max_apex, gpu_raster_phase7,
    drawGSNearMax();
    ASSERT_PIXEL_EQ(GS_NEAR_MAX_APEX, 0, 0);
)

CESTER_TEST(gs_near_max_interior, gpu_raster_phase7,
    drawGSNearMax();
    /* Deep interior should be R=30 (the base color), not drift up to 31. */
    ASSERT_PIXEL_EQ(GS_NEAR_MAX_INTERIOR, 4, 8);
)

CESTER_TEST(gs_near_min_apex, gpu_raster_phase7,
    drawGSNearMin();
    ASSERT_PIXEL_EQ(GS_NEAR_MIN_APEX, 0, 0);
)

CESTER_TEST(gs_near_min_interior, gpu_raster_phase7,
    drawGSNearMin();
    /* Deep interior should be R=1, not underflow to 31. */
    ASSERT_PIXEL_EQ(GS_NEAR_MIN_INTERIOR, 4, 8);
)

CESTER_TEST(gs_half_of_lsb_apex, gpu_raster_phase7,
    drawGSHalfOfLSB();
    ASSERT_PIXEL_EQ(GS_HALF_OF_LSB_APEX, 0, 0);
)

CESTER_TEST(gs_half_of_lsb_y2, gpu_raster_phase7,
    drawGSHalfOfLSB();
    ASSERT_PIXEL_EQ(GS_HALF_OF_LSB_Y2, 0, 2);
)

CESTER_TEST(gs_half_of_lsb_y4, gpu_raster_phase7,
    drawGSHalfOfLSB();
    ASSERT_PIXEL_EQ(GS_HALF_OF_LSB_Y4, 0, 4);
)

CESTER_TEST(gs_half_of_lsb_y6, gpu_raster_phase7,
    drawGSHalfOfLSB();
    ASSERT_PIXEL_EQ(GS_HALF_OF_LSB_Y6, 0, 6);
)

// --------------------------------------------------------------------------
// GD: Dither overlay - 4x4 Bayer pattern probe
// --------------------------------------------------------------------------

CESTER_TEST(gd_8_8,   gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_8_8,   8, 8); )
CESTER_TEST(gd_9_8,   gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_9_8,   9, 8); )
CESTER_TEST(gd_10_8,  gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_10_8,  10, 8); )
CESTER_TEST(gd_11_8,  gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_11_8,  11, 8); )
CESTER_TEST(gd_8_9,   gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_8_9,   8, 9); )
CESTER_TEST(gd_9_9,   gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_9_9,   9, 9); )
CESTER_TEST(gd_10_9,  gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_10_9,  10, 9); )
CESTER_TEST(gd_11_9,  gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_11_9,  11, 9); )
CESTER_TEST(gd_8_10,  gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_8_10,  8, 10); )
CESTER_TEST(gd_9_10,  gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_9_10,  9, 10); )
CESTER_TEST(gd_10_10, gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_10_10, 10, 10); )
CESTER_TEST(gd_11_10, gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_11_10, 11, 10); )
CESTER_TEST(gd_8_11,  gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_8_11,  8, 11); )
CESTER_TEST(gd_9_11,  gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_9_11,  9, 11); )
CESTER_TEST(gd_10_11, gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_10_11, 10, 11); )
CESTER_TEST(gd_11_11, gpu_raster_phase7, drawGD(); ASSERT_PIXEL_EQ(GD_11_11, 11, 11); )

// --------------------------------------------------------------------------
// GO: Vertex-order permutations
// All six permutations should produce identical interior pixels.
// --------------------------------------------------------------------------

CESTER_TEST(go_perm0_R_GB_2_2, gpu_raster_phase7,
    drawGOPerm(0); ASSERT_PIXEL_EQ(GO_PERM_INTERIOR_2_2, 2, 2);
)
CESTER_TEST(go_perm1_R_BG_2_2, gpu_raster_phase7,
    drawGOPerm(1); ASSERT_PIXEL_EQ(GO_PERM_INTERIOR_2_2, 2, 2);
)
CESTER_TEST(go_perm2_G_RB_2_2, gpu_raster_phase7,
    drawGOPerm(2); ASSERT_PIXEL_EQ(GO_PERM_INTERIOR_2_2, 2, 2);
)
CESTER_TEST(go_perm3_G_BR_2_2, gpu_raster_phase7,
    drawGOPerm(3); ASSERT_PIXEL_EQ(GO_PERM_INTERIOR_2_2, 2, 2);
)
CESTER_TEST(go_perm4_B_RG_2_2, gpu_raster_phase7,
    drawGOPerm(4); ASSERT_PIXEL_EQ(GO_PERM_INTERIOR_2_2, 2, 2);
)
CESTER_TEST(go_perm5_B_GR_2_2, gpu_raster_phase7,
    drawGOPerm(5); ASSERT_PIXEL_EQ(GO_PERM_INTERIOR_2_2, 2, 2);
)

CESTER_TEST(go_perm0_R_GB_1_3, gpu_raster_phase7,
    drawGOPerm(0); ASSERT_PIXEL_EQ(GO_PERM_INTERIOR_1_3, 1, 3);
)
CESTER_TEST(go_perm1_R_BG_1_3, gpu_raster_phase7,
    drawGOPerm(1); ASSERT_PIXEL_EQ(GO_PERM_INTERIOR_1_3, 1, 3);
)
CESTER_TEST(go_perm2_G_RB_1_3, gpu_raster_phase7,
    drawGOPerm(2); ASSERT_PIXEL_EQ(GO_PERM_INTERIOR_1_3, 1, 3);
)
CESTER_TEST(go_perm3_G_BR_1_3, gpu_raster_phase7,
    drawGOPerm(3); ASSERT_PIXEL_EQ(GO_PERM_INTERIOR_1_3, 1, 3);
)
CESTER_TEST(go_perm4_B_RG_1_3, gpu_raster_phase7,
    drawGOPerm(4); ASSERT_PIXEL_EQ(GO_PERM_INTERIOR_1_3, 1, 3);
)
CESTER_TEST(go_perm5_B_GR_1_3, gpu_raster_phase7,
    drawGOPerm(5); ASSERT_PIXEL_EQ(GO_PERM_INTERIOR_1_3, 1, 3);
)
