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

// Textured triangle basic sampling correctness at 4-bit, 8-bit, and
// 15-bit depths. Triangles are drawn with vertex UVs matching screen
// positions 1:1 so pixel (x, y) samples texel (x, y). The fixture
// textures encode known functions of (u, v) so we can predict and
// assert the exact VRAM color at each rasterized pixel.
//
// The audit's drawPoly3TEx4 / drawPoly3TEx8 / drawPoly3TD paths get
// exercised here for the first time - phase 1-3 were all untextured.
//
// Texture command color: 0x808080 (neutral modulation - texel passes
// through unchanged at 128/128 = 1.0).

CESTER_BODY(

static void drawTex4Tri(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 16);
    setTexpage(TEX4_TX, TEX4_TY, 0);
    setTextureWindow(0, 0, 0, 0);
    /* Triangle (0,0)-(16,0)-(0,8) with UV matching screen. */
    rasterTexTri(TEX_MOD_NEUTRAL,
                 0, 0,  0, 0,
                 16, 0, 16, 0,
                 0, 8,  0, 8,
                 CLUT4_FIELD, TEX4_TPAGE);
    rasterFlushPrimitive();
}

static void drawTex8Tri(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 64, 16);
    setTexpage(TEX8_TX, TEX8_TY, 1);
    setTextureWindow(0, 0, 0, 0);
    /* Wider triangle to span more 8-bit texels. */
    rasterTexTri(TEX_MOD_NEUTRAL,
                 0, 0,   0, 0,
                 32, 0,  32, 0,
                 0, 8,   0, 8,
                 CLUT8_FIELD, TEX8_TPAGE);
    rasterFlushPrimitive();
}

static void drawTex15Tri(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 16);
    setTexpage(TEX15_TX, TEX15_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 0, 0,   0, 0,
                 16, 0,  16, 0,
                 0, 8,   0, 8,
                 CLUT15_FIELD, TEX15_TPAGE);
    rasterFlushPrimitive();
}

// Single-pixel 4-bit textured triangle. Reads back exactly one pixel
// and expects the texel at UV (3, 3) -> CLUT[3].
static void drawTex4Single(void) {
    rasterReset();
    rasterClearTestRegion(20, 20, 4, 4);
    setTexpage(TEX4_TX, TEX4_TY, 0);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 20, 20, 3, 3,
                 21, 20, 4, 3,
                 20, 21, 3, 4,
                 CLUT4_FIELD, TEX4_TPAGE);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// 4-bit CLUT triangle - basic sampling
// --------------------------------------------------------------------------

CESTER_TEST(tex4_pixel_0_0, gpu_raster_phase4,
    drawTex4Tri();
    /* At screen (0, 0), UV = (0, 0), texel = 0 & 0xf = 0,
       CLUT[0] = vram555(0, 31, 0) = 0x03E0 (green). */
    ASSERT_PIXEL_EQ(expectedClut4Color(0), 0, 0);
)

CESTER_TEST(tex4_pixel_3_0, gpu_raster_phase4,
    drawTex4Tri();
    ASSERT_PIXEL_EQ(expectedClut4Color(3), 3, 0);
)

CESTER_TEST(tex4_pixel_7_0, gpu_raster_phase4,
    drawTex4Tri();
    ASSERT_PIXEL_EQ(expectedClut4Color(7), 7, 0);
)

CESTER_TEST(tex4_pixel_15_0, gpu_raster_phase4,
    drawTex4Tri();
    ASSERT_PIXEL_EQ(expectedClut4Color(15), 15, 0);
)

CESTER_TEST(tex4_pixel_16_0_right_edge, gpu_raster_phase4,
    drawTex4Tri();
    /* x=16 is the right edge of the triangle (top-left rule excludes). */
    ASSERT_PIXEL_UNTOUCHED(16, 0);
)

CESTER_TEST(tex4_pixel_0_4_interior, gpu_raster_phase4,
    drawTex4Tri();
    /* At y=4, the hypotenuse limits x to about (16 * (8-4)/8) = 8.
       Pixel (0, 4) is well inside. UV at screen (0, 4) is (0, 4),
       texel = 0, CLUT[0]. */
    ASSERT_PIXEL_EQ(expectedClut4Color(0), 0, 4);
)

CESTER_TEST(tex4_pixel_5_4_interior, gpu_raster_phase4,
    drawTex4Tri();
    ASSERT_PIXEL_EQ(expectedClut4Color(5), 5, 4);
)

CESTER_TEST(tex4_pixel_0_7_bottom_inner, gpu_raster_phase4,
    drawTex4Tri();
    ASSERT_PIXEL_EQ(expectedClut4Color(0), 0, 7);
)

CESTER_TEST(tex4_pixel_0_8_bottom_excluded, gpu_raster_phase4,
    drawTex4Tri();
    ASSERT_PIXEL_UNTOUCHED(0, 8);
)

CESTER_TEST(tex4_single_pixel_at_20_20, gpu_raster_phase4,
    drawTex4Single();
    /* 1-pixel triangle at (20,20) with UV (3,3) -> CLUT[3]. */
    ASSERT_PIXEL_EQ(expectedClut4Color(3), 20, 20);
)

CESTER_TEST(tex4_single_pixel_complement_21_20, gpu_raster_phase4,
    drawTex4Single();
    ASSERT_PIXEL_UNTOUCHED(21, 20);
)

// --------------------------------------------------------------------------
// 8-bit CLUT triangle - basic sampling
// --------------------------------------------------------------------------

CESTER_TEST(tex8_pixel_0_0, gpu_raster_phase4,
    drawTex8Tri();
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 0, 0);
)

CESTER_TEST(tex8_pixel_7_0, gpu_raster_phase4,
    drawTex8Tri();
    ASSERT_PIXEL_EQ(expectedClut8Color(7), 7, 0);
)

CESTER_TEST(tex8_pixel_15_0, gpu_raster_phase4,
    drawTex8Tri();
    ASSERT_PIXEL_EQ(expectedClut8Color(15), 15, 0);
)

CESTER_TEST(tex8_pixel_31_0, gpu_raster_phase4,
    drawTex8Tri();
    ASSERT_PIXEL_EQ(expectedClut8Color(31), 31, 0);
)

CESTER_TEST(tex8_pixel_32_0_right_edge, gpu_raster_phase4,
    drawTex8Tri();
    ASSERT_PIXEL_UNTOUCHED(32, 0);
)

CESTER_TEST(tex8_pixel_10_4_interior, gpu_raster_phase4,
    drawTex8Tri();
    ASSERT_PIXEL_EQ(expectedClut8Color(10), 10, 4);
)

CESTER_TEST(tex8_pixel_0_7_bottom_inner, gpu_raster_phase4,
    drawTex8Tri();
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 0, 7);
)

CESTER_TEST(tex8_pixel_0_8_bottom_excluded, gpu_raster_phase4,
    drawTex8Tri();
    ASSERT_PIXEL_UNTOUCHED(0, 8);
)

// --------------------------------------------------------------------------
// 15-bit direct triangle - basic sampling
// --------------------------------------------------------------------------

CESTER_TEST(tex15_pixel_0_0_transparent, gpu_raster_phase4,
    drawTex15Tri();
    /* TEXEL 0x0000 IS TRANSPARENT - canonical PSX rule (HW_VERIFIED
       2026-05-15). At screen (0, 0), UV = (0, 0), the fixture texel
       is vram555(0, 0, 0) = 0x0000. The rasterizer detects all-zero
       texel and skips the write, so the destination stays sentinel.
       This applies to ALL three texture depths: a CLUT entry of
       0x0000 OR a direct 15-bit texel of 0x0000 = transparent. */
    ASSERT_PIXEL_UNTOUCHED(0, 0);
)

CESTER_TEST(tex15_pixel_5_0, gpu_raster_phase4,
    drawTex15Tri();
    ASSERT_PIXEL_EQ(expectedTex15Color(5, 0), 5, 0);
)

CESTER_TEST(tex15_pixel_15_0, gpu_raster_phase4,
    drawTex15Tri();
    ASSERT_PIXEL_EQ(expectedTex15Color(15, 0), 15, 0);
)

CESTER_TEST(tex15_pixel_16_0_right_edge, gpu_raster_phase4,
    drawTex15Tri();
    ASSERT_PIXEL_UNTOUCHED(16, 0);
)

CESTER_TEST(tex15_pixel_0_4_interior, gpu_raster_phase4,
    drawTex15Tri();
    ASSERT_PIXEL_EQ(expectedTex15Color(0, 4), 0, 4);
)

CESTER_TEST(tex15_pixel_5_4_interior, gpu_raster_phase4,
    drawTex15Tri();
    ASSERT_PIXEL_EQ(expectedTex15Color(5, 4), 5, 4);
)

CESTER_TEST(tex15_pixel_0_7_bottom_inner, gpu_raster_phase4,
    drawTex15Tri();
    ASSERT_PIXEL_EQ(expectedTex15Color(0, 7), 0, 7);
)

CESTER_TEST(tex15_pixel_0_8_bottom_excluded, gpu_raster_phase4,
    drawTex15Tri();
    ASSERT_PIXEL_UNTOUCHED(0, 8);
)
