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

// Phase-17 affine UV-mapping triangle suite. Eight triangles spanning
// the parameter space: UV-vs-screen rotation, scale ratios, and
// stress geometries (narrow-tall, flat-wide).
//
// All draws use the phase-17 TEX17 signature texture (texpage cell
// TX=11, 32x32 15-bit direct). Texel(u, v) encodes (u, v) uniquely in
// (red, green) channels so probe failures decode directly into the
// (u, v) the rasterizer actually sampled.

CESTER_BODY(

// ---- T1 AR_AXIS_BASE -----------------------------------------------------
// A=(5,5)/(0,0)  B=(25,5)/(20,0)  C=(5,15)/(0,10)
// Affine: UV(x, y) = (x - 5, y - 5). 1:1 ratio, axis-aligned.

static void drawAR_AXIS_BASE(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0,  0,
                 25, 5,  20, 0,
                 5,  15, 0,  10,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T2 AR_COMPRESS ------------------------------------------------------
// A=(5,5)/(0,0)  B=(35,5)/(6,0)  C=(5,15)/(0,3)
// 30x10 screen -> 6x3 UV. Sub-unit per-pixel UV step.

static void drawAR_COMPRESS(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 48, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0, 0,
                 35, 5,  6, 0,
                 5,  15, 0, 3,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T3 AR_STRETCH -------------------------------------------------------
// A=(5,5)/(0,0)  B=(15,5)/(30,0)  C=(5,10)/(0,20)
// 10x5 screen -> 30x20 UV. Per-pixel UV step ~3x and ~4x.

static void drawAR_STRETCH(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  0,  0,
                 15, 5,  30, 0,
                 5,  10, 0,  20,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T4 AR_TWIST_90 ------------------------------------------------------
// A=(4,4)/(0,0)  B=(20,4)/(0,16)  C=(4,20)/(16,0)
// UV axes swapped. UV(x, y) = (y - 4, x - 4) inside triangle.
// Tests cross-span UV step at maximum rate vs zero row-edge step.

static void drawAR_TWIST_90(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 24);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 4,  4,  0,  0,
                 20, 4,  0,  16,
                 4,  20, 16, 0,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T5 AR_TWIST_45 ------------------------------------------------------
// A=(4,4)/(8,0)  B=(20,4)/(16,8)  C=(4,20)/(0,8)
// UV rotated 45 degrees. dU/dX = 0.5, dU/dY = -0.5, dV/dX = 0.5,
// dV/dY = 0.5 (uniform-magnitude in both UV axes).

static void drawAR_TWIST_45(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 24);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 4,  4,  8,  0,
                 20, 4,  16, 8,
                 4,  20, 0,  8,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T6 AR_NATURAL -------------------------------------------------------
// A=(5,5)/(3,2)  B=(25,9)/(20,5)  C=(8,22)/(8,22)
// Arbitrary triangle, arbitrary UV. No symmetry, no special structure.

static void drawAR_NATURAL(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 24);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 5,  5,  3,  2,
                 25, 9,  20, 5,
                 8,  22, 8,  22,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T7 AR_NARROW_TALL ---------------------------------------------------
// A=(10,4)/(0,0)  B=(14,4)/(20,0)  C=(12,24)/(10,30)
// 4 wide, 20 tall. Cross-span UV step dominates row edge step.

static void drawAR_NARROW_TALL(void) {
    rasterReset();
    rasterClearTestRegion(4, 0, 16, 28);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 10, 4,  0,  0,
                 14, 4,  20, 0,
                 12, 24, 10, 30,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

// ---- T8 AR_FLAT_WIDE -----------------------------------------------------
// A=(4,8)/(0,0)  B=(34,9)/(30,0)  C=(4,11)/(0,4)
// 30 wide, 3 tall. Row edge step dominates cross-span step.

static void drawAR_FLAT_WIDE(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 48, 16);
    setTexpage(TEX17_TX, TEX17_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 4,  8,  0,  0,
                 34, 9,  30, 0,
                 4,  11, 0,  4,
                 TEX17_CLUT_FIELD, TEX17_TPAGE);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// T1 AR_AXIS_BASE assertions
// --------------------------------------------------------------------------

CESTER_TEST(ar_axis_base_10_8, gpu_raster_phase17,
    drawAR_AXIS_BASE();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_AXIS_BASE_10_8, 10, 8);
)

CESTER_TEST(ar_axis_base_20_6, gpu_raster_phase17,
    drawAR_AXIS_BASE();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_AXIS_BASE_20_6, 20, 6);
)

CESTER_TEST(ar_axis_base_8_12, gpu_raster_phase17,
    drawAR_AXIS_BASE();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_AXIS_BASE_8_12, 8, 12);
)

CESTER_TEST(ar_axis_base_24_5_top_edge, gpu_raster_phase17,
    drawAR_AXIS_BASE();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_AXIS_BASE_24_5, 24, 5);
)

CESTER_TEST(ar_axis_base_25_5_right_vert_excluded, gpu_raster_phase17,
    drawAR_AXIS_BASE();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_AXIS_BASE_25_5, 25, 5);
)

// --------------------------------------------------------------------------
// T2 AR_COMPRESS assertions
// --------------------------------------------------------------------------

CESTER_TEST(ar_compress_10_7, gpu_raster_phase17,
    drawAR_COMPRESS();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_COMPRESS_10_7, 10, 7);
)

CESTER_TEST(ar_compress_20_8, gpu_raster_phase17,
    drawAR_COMPRESS();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_COMPRESS_20_8, 20, 8);
)

CESTER_TEST(ar_compress_15_10, gpu_raster_phase17,
    drawAR_COMPRESS();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_COMPRESS_15_10, 15, 10);
)

CESTER_TEST(ar_compress_30_5, gpu_raster_phase17,
    drawAR_COMPRESS();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_COMPRESS_30_5, 30, 5);
)

// --------------------------------------------------------------------------
// T3 AR_STRETCH assertions
// --------------------------------------------------------------------------

CESTER_TEST(ar_stretch_6_6, gpu_raster_phase17,
    drawAR_STRETCH();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_STRETCH_6_6, 6, 6);
)

CESTER_TEST(ar_stretch_10_7, gpu_raster_phase17,
    drawAR_STRETCH();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_STRETCH_10_7, 10, 7);
)

CESTER_TEST(ar_stretch_8_8, gpu_raster_phase17,
    drawAR_STRETCH();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_STRETCH_8_8, 8, 8);
)

CESTER_TEST(ar_stretch_5_5_a_vert, gpu_raster_phase17,
    drawAR_STRETCH();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_STRETCH_5_5, 5, 5);
)

// --------------------------------------------------------------------------
// T4 AR_TWIST_90 assertions
// --------------------------------------------------------------------------

CESTER_TEST(ar_twist_90_10_10, gpu_raster_phase17,
    drawAR_TWIST_90();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_TWIST_90_10_10, 10, 10);
)

CESTER_TEST(ar_twist_90_6_10, gpu_raster_phase17,
    drawAR_TWIST_90();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_TWIST_90_6_10, 6, 10);
)

CESTER_TEST(ar_twist_90_10_6, gpu_raster_phase17,
    drawAR_TWIST_90();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_TWIST_90_10_6, 10, 6);
)

CESTER_TEST(ar_twist_90_4_4_a_vert, gpu_raster_phase17,
    drawAR_TWIST_90();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_TWIST_90_4_4, 4, 4);
)

// --------------------------------------------------------------------------
// T5 AR_TWIST_45 assertions
// --------------------------------------------------------------------------

CESTER_TEST(ar_twist_45_12_4_ab_mid, gpu_raster_phase17,
    drawAR_TWIST_45();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_TWIST_45_12_4, 12, 4);
)

CESTER_TEST(ar_twist_45_4_12_ac_mid, gpu_raster_phase17,
    drawAR_TWIST_45();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_TWIST_45_4_12, 4, 12);
)

CESTER_TEST(ar_twist_45_8_8, gpu_raster_phase17,
    drawAR_TWIST_45();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_TWIST_45_8_8, 8, 8);
)

CESTER_TEST(ar_twist_45_12_12_bc_mid, gpu_raster_phase17,
    drawAR_TWIST_45();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_TWIST_45_12_12, 12, 12);
)

// --------------------------------------------------------------------------
// T6 AR_NATURAL assertions
// --------------------------------------------------------------------------

CESTER_TEST(ar_natural_12_10, gpu_raster_phase17,
    drawAR_NATURAL();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_NATURAL_12_10, 12, 10);
)

CESTER_TEST(ar_natural_18_15, gpu_raster_phase17,
    drawAR_NATURAL();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_NATURAL_18_15, 18, 15);
)

CESTER_TEST(ar_natural_10_18, gpu_raster_phase17,
    drawAR_NATURAL();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_NATURAL_10_18, 10, 18);
)

CESTER_TEST(ar_natural_5_5_a_vert, gpu_raster_phase17,
    drawAR_NATURAL();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_NATURAL_5_5, 5, 5);
)

// --------------------------------------------------------------------------
// T7 AR_NARROW_TALL assertions
// --------------------------------------------------------------------------

CESTER_TEST(ar_narrow_tall_11_8, gpu_raster_phase17,
    drawAR_NARROW_TALL();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_NARROW_TALL_11_8, 11, 8);
)

CESTER_TEST(ar_narrow_tall_12_14, gpu_raster_phase17,
    drawAR_NARROW_TALL();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_NARROW_TALL_12_14, 12, 14);
)

CESTER_TEST(ar_narrow_tall_11_20, gpu_raster_phase17,
    drawAR_NARROW_TALL();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_NARROW_TALL_11_20, 11, 20);
)

CESTER_TEST(ar_narrow_tall_13_6, gpu_raster_phase17,
    drawAR_NARROW_TALL();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_NARROW_TALL_13_6, 13, 6);
)

// --------------------------------------------------------------------------
// T8 AR_FLAT_WIDE assertions
// --------------------------------------------------------------------------

CESTER_TEST(ar_flat_wide_8_9, gpu_raster_phase17,
    drawAR_FLAT_WIDE();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_FLAT_WIDE_8_9, 8, 9);
)

CESTER_TEST(ar_flat_wide_20_9, gpu_raster_phase17,
    drawAR_FLAT_WIDE();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_FLAT_WIDE_20_9, 20, 9);
)

CESTER_TEST(ar_flat_wide_30_9, gpu_raster_phase17,
    drawAR_FLAT_WIDE();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_FLAT_WIDE_30_9, 30, 9);
)

CESTER_TEST(ar_flat_wide_6_10, gpu_raster_phase17,
    drawAR_FLAT_WIDE();
    PHASE17_ASSERT_PIXEL_EQ(EXPECT_AR_FLAT_WIDE_6_10, 6, 10);
)
