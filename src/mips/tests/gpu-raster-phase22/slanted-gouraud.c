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

// Slanted gouraud color suite. Every triangle here has BOTH the long
// left edge and the top edge off-axis, so the per-row left-edge color
// seed lands at a fractional x and the horizontal span delta both carry
// truncated accumulators. That compounding is precisely what the
// axis-aligned phase-7 gouraud suite cannot reach, and where a soft
// renderer can drift by a single LSB on slanted gouraud fills.
//
// All probes target interior pixels or a covered (left) vertex; none
// hit a top-left-excluded bottom/right vertex (those read sentinel).
// SG_AB reproduces the exact triangle the 24 carried-over silicon
// pixels were captured from, using full 8-bit 0xFF command colors (see
// raster-expected-phase22.h).

CESTER_BODY(

// SG_AB: the libgouraud cross-check triangle. Raw 0xFF command colors to
// match the captured silicon. v0=(20,20)R v1=(200,60)G v2=(90,230)B.
static void drawSGAB(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 64, 32);
    rasterGouraudTri(0x0000ffu, 20,  20,
                     0x00ff00u, 200, 60,
                     0xff0000u, 90,  230);
    rasterFlushPrimitive();
}

// SG1: medium slanted RGB triangle, suite idiom (5-bit colors).
static void drawSG1(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 64, 56);
    rasterGouraudTri(RASTER_CMD_RED,   8,  4,
                     RASTER_CMD_GREEN, 58, 22,
                     RASTER_CMD_BLUE,  22, 52);
    rasterFlushPrimitive();
}

// SG2: flatter slanted RGB triangle, apex-low orientation.
static void drawSG2(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 72, 56);
    rasterGouraudTri(RASTER_CMD_RED,   40, 6,
                     RASTER_CMD_GREEN, 70, 48,
                     RASTER_CMD_BLUE,  6,  40);
    rasterFlushPrimitive();
}

// SG_R: R-only slanted gradient. Apex R=31, base verts R=0. Isolates a
// single channel's accumulator on a slanted shape.
static void drawSGR(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 56, 56);
    rasterGouraudTri(RASTER_CMD_RED, 6,  6,
                     0u,             54, 18,
                     0u,             18, 50);
    rasterFlushPrimitive();
}

// SG3: narrow / steep slanted triangle.
static void drawSG3(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 48, 56);
    rasterGouraudTri(RASTER_CMD_RED,   30, 4,
                     RASTER_CMD_GREEN, 40, 50,
                     RASTER_CMD_BLUE,  20, 46);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// SG_AB: 24 silicon cross-check probes
// --------------------------------------------------------------------------

CESTER_TEST(sg_ab_26_22, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_26_22, 26, 22); )
CESTER_TEST(sg_ab_24_23, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_24_23, 24, 23); )
CESTER_TEST(sg_ab_26_23, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_26_23, 26, 23); )
CESTER_TEST(sg_ab_27_24, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_27_24, 27, 24); )
CESTER_TEST(sg_ab_30_24, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_30_24, 30, 24); )
CESTER_TEST(sg_ab_32_24, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_32_24, 32, 24); )
CESTER_TEST(sg_ab_37_24, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_37_24, 37, 24); )
CESTER_TEST(sg_ab_27_25, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_27_25, 27, 25); )
CESTER_TEST(sg_ab_32_25, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_32_25, 32, 25); )
CESTER_TEST(sg_ab_22_26, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_22_26, 22, 26); )
CESTER_TEST(sg_ab_27_26, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_27_26, 27, 26); )
CESTER_TEST(sg_ab_35_26, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_35_26, 35, 26); )
CESTER_TEST(sg_ab_25_27, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_25_27, 25, 27); )
CESTER_TEST(sg_ab_28_27, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_28_27, 28, 27); )
CESTER_TEST(sg_ab_33_27, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_33_27, 33, 27); )
CESTER_TEST(sg_ab_38_27, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_38_27, 38, 27); )
CESTER_TEST(sg_ab_41_27, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_41_27, 41, 27); )
CESTER_TEST(sg_ab_43_27, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_43_27, 43, 27); )
CESTER_TEST(sg_ab_49_27, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_49_27, 49, 27); )
CESTER_TEST(sg_ab_28_28, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_28_28, 28, 28); )
CESTER_TEST(sg_ab_29_28, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_29_28, 29, 28); )
CESTER_TEST(sg_ab_30_28, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_30_28, 30, 28); )
CESTER_TEST(sg_ab_33_28, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_33_28, 33, 28); )
CESTER_TEST(sg_ab_49_28, gpu_raster_phase22, drawSGAB(); ASSERT_PIXEL_EQ(SG_AB_49_28, 49, 28); )

// --------------------------------------------------------------------------
// SG1: medium slanted RGB triangle (interior probes)
// --------------------------------------------------------------------------

CESTER_TEST(sg1_29_26, gpu_raster_phase22, drawSG1(); ASSERT_PIXEL_EQ(SG1_29_26, 29, 26); )
CESTER_TEST(sg1_24_24, gpu_raster_phase22, drawSG1(); ASSERT_PIXEL_EQ(SG1_24_24, 24, 24); )
CESTER_TEST(sg1_36_28, gpu_raster_phase22, drawSG1(); ASSERT_PIXEL_EQ(SG1_36_28, 36, 28); )
CESTER_TEST(sg1_20_20, gpu_raster_phase22, drawSG1(); ASSERT_PIXEL_EQ(SG1_20_20, 20, 20); )
CESTER_TEST(sg1_30_32, gpu_raster_phase22, drawSG1(); ASSERT_PIXEL_EQ(SG1_30_32, 30, 32); )
CESTER_TEST(sg1_40_24, gpu_raster_phase22, drawSG1(); ASSERT_PIXEL_EQ(SG1_40_24, 40, 24); )

// --------------------------------------------------------------------------
// SG2: flatter slanted RGB triangle (v2 covered vertex + interior)
// --------------------------------------------------------------------------

CESTER_TEST(sg2_v2_6_40, gpu_raster_phase22, drawSG2(); ASSERT_PIXEL_EQ(SG2_V2_6_40, 6,  40); )
CESTER_TEST(sg2_39_31,   gpu_raster_phase22, drawSG2(); ASSERT_PIXEL_EQ(SG2_39_31,   39, 31); )
CESTER_TEST(sg2_30_30,   gpu_raster_phase22, drawSG2(); ASSERT_PIXEL_EQ(SG2_30_30,   30, 30); )
CESTER_TEST(sg2_48_32,   gpu_raster_phase22, drawSG2(); ASSERT_PIXEL_EQ(SG2_48_32,   48, 32); )
CESTER_TEST(sg2_40_20,   gpu_raster_phase22, drawSG2(); ASSERT_PIXEL_EQ(SG2_40_20,   40, 20); )
CESTER_TEST(sg2_20_34,   gpu_raster_phase22, drawSG2(); ASSERT_PIXEL_EQ(SG2_20_34,   20, 34); )

// --------------------------------------------------------------------------
// SG_R: R-only slanted gradient (interior probes)
// --------------------------------------------------------------------------

CESTER_TEST(sgr_8_8,   gpu_raster_phase22, drawSGR(); ASSERT_PIXEL_EQ(SGR_8_8,   8,  8);  )
CESTER_TEST(sgr_26_25, gpu_raster_phase22, drawSGR(); ASSERT_PIXEL_EQ(SGR_26_25, 26, 25); )
CESTER_TEST(sgr_16_16, gpu_raster_phase22, drawSGR(); ASSERT_PIXEL_EQ(SGR_16_16, 16, 16); )
CESTER_TEST(sgr_22_28, gpu_raster_phase22, drawSGR(); ASSERT_PIXEL_EQ(SGR_22_28, 22, 28); )
CESTER_TEST(sgr_31_20, gpu_raster_phase22, drawSGR(); ASSERT_PIXEL_EQ(SGR_31_20, 31, 20); )
CESTER_TEST(sgr_13_22, gpu_raster_phase22, drawSGR(); ASSERT_PIXEL_EQ(SGR_13_22, 13, 22); )

// --------------------------------------------------------------------------
// SG3: narrow / steep slanted triangle (v2 covered vertex + interior)
// --------------------------------------------------------------------------

CESTER_TEST(sg3_v2_20_46, gpu_raster_phase22, drawSG3(); ASSERT_PIXEL_EQ(SG3_V2_20_46, 20, 46); )
CESTER_TEST(sg3_30_33,    gpu_raster_phase22, drawSG3(); ASSERT_PIXEL_EQ(SG3_30_33,    30, 33); )
CESTER_TEST(sg3_30_22,    gpu_raster_phase22, drawSG3(); ASSERT_PIXEL_EQ(SG3_30_22,    30, 22); )
CESTER_TEST(sg3_31_40,    gpu_raster_phase22, drawSG3(); ASSERT_PIXEL_EQ(SG3_31_40,    31, 40); )
CESTER_TEST(sg3_28_30,    gpu_raster_phase22, drawSG3(); ASSERT_PIXEL_EQ(SG3_28_30,    28, 30); )
CESTER_TEST(sg3_33_38,    gpu_raster_phase22, drawSG3(); ASSERT_PIXEL_EQ(SG3_33_38,    33, 38); )
