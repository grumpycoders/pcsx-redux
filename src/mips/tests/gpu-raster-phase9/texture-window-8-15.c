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

// Texture-window probes at 8-bit (CLUT8) and 15-bit (direct) depths.
//
// Same formula as the 4-bit path:
//   filtered_u = (u AND NOT (mask_u * 8)) OR ((offset_u * 8) AND (mask_u * 8))
//
// mask_u = 0x01 -> bit 3 of u forced from offset_u
// mask_u = 0x03 -> bits 3 AND 4 of u forced from offset_u
// mask_u = 0x07 -> bits 3, 4, 5 of u forced (24 high bits collapse window)
//
// The 8-bit fixture spans u=0..63 (64 texels) and 15-bit spans the
// same range. Mask values up to 0x07 (collapse 24 high bits, leaving
// 3-bit window) are meaningful at these widths.

CESTER_BODY(

static void drawTexWindow8Tri(uint8_t mask_x, uint8_t off_x) {
    rasterReset();
    rasterClearTestRegion(0, 0, 64, 16);
    setTexpage(TEX8_TX, TEX8_TY, 1);
    setTextureWindow(mask_x, 0, off_x, 0);
    /* Triangle (0,0)-(32,0)-(0,8). UV matches screen so pixel (x,y)
       wants texel (x, y); window filtering rewrites the U bits. */
    rasterTexTri(TEX_MOD_NEUTRAL,
                 0,  0,  0,  0,
                 32, 0,  32, 0,
                 0,  8,  0,  8,
                 CLUT8_FIELD, TEX8_TPAGE);
    rasterFlushPrimitive();
}

static void drawTexWindow15Tri(uint8_t mask_x, uint8_t off_x) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 16);
    setTexpage(TEX15_TX, TEX15_TY, 2);
    setTextureWindow(mask_x, 0, off_x, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 0,  0,  0,  0,
                 16, 0,  16, 0,
                 0,  8,  0,  8,
                 CLUT15_FIELD, TEX15_TPAGE);
    rasterFlushPrimitive();
}

// Vertical-window variant: mask_y forces high bits of v from offset_y.
// Useful for confirming V-axis windowing isn't subtly different from U.
static void drawTexWindow8TriV(uint8_t mask_y, uint8_t off_y) {
    rasterReset();
    rasterClearTestRegion(0, 0, 64, 16);
    setTexpage(TEX8_TX, TEX8_TY, 1);
    setTextureWindow(0, mask_y, 0, off_y);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 0,  0,  0,  0,
                 32, 0,  32, 0,
                 0,  8,  0,  8,
                 CLUT8_FIELD, TEX8_TPAGE);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// ==========================================================================
// 8-bit: mask_u=0x01, offset_u=0  -> bit 3 of u cleared
//        u=0..7   -> texel 0..7
//        u=8..15  -> texel 0..7 (bit 3 cleared)
//        u=16..23 -> texel 16..23 (bit 3 of 16=0x10 unchanged; only bit 3
//                                  collapses 8-aligned 8-blocks)
// ==========================================================================

CESTER_TEST(texwin8_mask01_off00_u0, gpu_raster_phase9,
    drawTexWindow8Tri(0x01, 0x00);
    /* u=0, filtered=0, CLUT8[0]. */
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 0, 0);
)
CESTER_TEST(texwin8_mask01_off00_u7, gpu_raster_phase9,
    drawTexWindow8Tri(0x01, 0x00);
    ASSERT_PIXEL_EQ(expectedClut8Color(7), 7, 0);
)
CESTER_TEST(texwin8_mask01_off00_u8_wraps_to_0, gpu_raster_phase9,
    drawTexWindow8Tri(0x01, 0x00);
    /* u=8, bit 3 cleared -> texel 0. */
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 8, 0);
)
CESTER_TEST(texwin8_mask01_off00_u15_wraps_to_7, gpu_raster_phase9,
    drawTexWindow8Tri(0x01, 0x00);
    /* u=15=0x0F, bit 3 cleared -> texel 7. */
    ASSERT_PIXEL_EQ(expectedClut8Color(7), 15, 0);
)
CESTER_TEST(texwin8_mask01_off00_u16, gpu_raster_phase9,
    drawTexWindow8Tri(0x01, 0x00);
    /* u=16=0x10, bit 3 already cleared -> texel 16. */
    ASSERT_PIXEL_EQ(expectedClut8Color(16), 16, 0);
)
CESTER_TEST(texwin8_mask01_off00_u24_wraps_to_16, gpu_raster_phase9,
    drawTexWindow8Tri(0x01, 0x00);
    /* u=24=0x18, bit 3 cleared -> texel 16. */
    ASSERT_PIXEL_EQ(expectedClut8Color(16), 24, 0);
)

// ==========================================================================
// 8-bit: mask_u=0x01, offset_u=0x01 -> bit 3 of u SET from offset
//        u=0..7  -> texel 8..15
//        u=8..15 -> texel 8..15 (already set)
// ==========================================================================

CESTER_TEST(texwin8_mask01_off01_u0_forced_to_8, gpu_raster_phase9,
    drawTexWindow8Tri(0x01, 0x01);
    ASSERT_PIXEL_EQ(expectedClut8Color(8), 0, 0);
)
CESTER_TEST(texwin8_mask01_off01_u3_forced_to_b, gpu_raster_phase9,
    drawTexWindow8Tri(0x01, 0x01);
    /* u=3, bit 3 set -> texel 0xB. */
    ASSERT_PIXEL_EQ(expectedClut8Color(0x0b), 3, 0);
)

// ==========================================================================
// 8-bit: mask_u=0x03 (bits 3 and 4) -> collapse 16-texel window
//        offset_u=0: u with bits 3-4 cleared
//        u=0..7    -> 0..7
//        u=8..23   -> texels 0..7 then 0..7 (16-byte wrap)
// ==========================================================================

CESTER_TEST(texwin8_mask03_off00_u20_wraps_to_4, gpu_raster_phase9,
    drawTexWindow8Tri(0x03, 0x00);
    /* u=20=0x14, &~0x18=0x04 -> texel 4. */
    ASSERT_PIXEL_EQ(expectedClut8Color(4), 20, 0);
)
CESTER_TEST(texwin8_mask03_off00_u31_wraps_to_7, gpu_raster_phase9,
    drawTexWindow8Tri(0x03, 0x00);
    /* u=31=0x1F, &~0x18=0x07 -> texel 7. */
    ASSERT_PIXEL_EQ(expectedClut8Color(7), 31, 0);
)

// ==========================================================================
// 8-bit: mask_u=0x07 -> collapse 24 high bits, 3-bit u window
//        offset_u=0x03 (set bit 4 and bit 3 from offset_u*8 = 0x18)
// ==========================================================================

CESTER_TEST(texwin8_mask07_off03_u0_forced_to_18, gpu_raster_phase9,
    drawTexWindow8Tri(0x07, 0x03);
    /* u=0, &~0x38 = 0, | 0x18 = 0x18 -> texel 24. */
    ASSERT_PIXEL_EQ(expectedClut8Color(0x18), 0, 0);
)
CESTER_TEST(texwin8_mask07_off03_u5_forced_to_1d, gpu_raster_phase9,
    drawTexWindow8Tri(0x07, 0x03);
    /* u=5, &~0x38=5, | 0x18 = 0x1D -> texel 29. */
    ASSERT_PIXEL_EQ(expectedClut8Color(0x1d), 5, 0);
)

// ==========================================================================
// 8-bit V-axis windowing: mask_v=0x01, off_v=0 -> bit 3 of v cleared
//        At y=8, v=8 wraps to v=0. The texture's V dimension carries
//        the row, but our fixture is constant across rows (texel value
//        depends only on u). So V-window wrapping doesn't change the
//        pixel color - it should match the equivalent non-wrapped row.
//        This is a control test: confirms V-window is applied but
//        invisible for U-only fixtures.
// ==========================================================================

CESTER_TEST(texwin8_maskV01_off00_v0, gpu_raster_phase9,
    drawTexWindow8TriV(0x01, 0x00);
    /* y=0, v=0, no wrap. */
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 0, 0);
)

// ==========================================================================
// 15-bit: mask_u=0x01, offset_u=0 -> bit 3 of u cleared
// Texel value at (u, v) = vram555(u & 0x1f, v & 0x1f, (u+v) & 0x1f).
// Window-rewritten u changes BOTH the R channel and the (u+v) blue
// channel, so the read-back pixel is a direct function of filtered_u.
// ==========================================================================

CESTER_TEST(texwin15_mask01_off00_u0, gpu_raster_phase9,
    drawTexWindow15Tri(0x01, 0x00);
    /* (u=0, v=0): vram555(0, 0, 0) = 0. NOTE: this pixel might be
       excluded by the top-left rule (apex of axis-aligned triangle).
       If hardware draws it, value is 0x0000; if excluded, sentinel. */
    ASSERT_PIXEL_EQ(TW15_M01_O00_U0_Y0, 0, 0);
)
CESTER_TEST(texwin15_mask01_off00_u7, gpu_raster_phase9,
    drawTexWindow15Tri(0x01, 0x00);
    /* (u=7, v=0): vram555(7, 0, 7) = 7 | (7<<10) = 0x1c07. */
    ASSERT_PIXEL_EQ(TW15_M01_O00_U7_Y0, 7, 0);
)
CESTER_TEST(texwin15_mask01_off00_u8_wraps_to_0, gpu_raster_phase9,
    drawTexWindow15Tri(0x01, 0x00);
    /* (u=8, filtered=0, v=0): vram555(0, 0, 0) = 0x0000. */
    ASSERT_PIXEL_EQ(TW15_M01_O00_U8_Y0, 8, 0);
)
CESTER_TEST(texwin15_mask01_off00_u15_wraps_to_7, gpu_raster_phase9,
    drawTexWindow15Tri(0x01, 0x00);
    /* (u=15, filtered=7, v=0): vram555(7, 0, 7) = 0x1c07. */
    ASSERT_PIXEL_EQ(TW15_M01_O00_U15_Y0, 15, 0);
)

// ==========================================================================
// 15-bit: mask_u=0x01, offset_u=0x01 -> bit 3 forced set
//         u=0..7 -> texel 8..15 -> vram555(8..15, 0, 8..15)
// ==========================================================================

CESTER_TEST(texwin15_mask01_off01_u0_forced_to_8, gpu_raster_phase9,
    drawTexWindow15Tri(0x01, 0x01);
    /* (filtered=8, v=0): vram555(8, 0, 8) = 8 | (8<<10) = 0x2008. */
    ASSERT_PIXEL_EQ(TW15_M01_O01_U0_Y0, 0, 0);
)
CESTER_TEST(texwin15_mask01_off01_u3_forced_to_b, gpu_raster_phase9,
    drawTexWindow15Tri(0x01, 0x01);
    /* (filtered=0xB=11, v=0): vram555(11, 0, 11) = 11 | (11<<10) = 0x2c0b. */
    ASSERT_PIXEL_EQ(TW15_M01_O01_U3_Y0, 3, 0);
)
CESTER_TEST(texwin15_mask01_off01_u8_already_set, gpu_raster_phase9,
    drawTexWindow15Tri(0x01, 0x01);
    /* (filtered=8, v=0). */
    ASSERT_PIXEL_EQ(TW15_M01_O01_U8_Y0, 8, 0);
)

// ==========================================================================
// 15-bit: mask_u=0x03 (bits 3-4 collapse, 16-texel window)
// ==========================================================================

CESTER_TEST(texwin15_mask03_off00_u13, gpu_raster_phase9,
    drawTexWindow15Tri(0x03, 0x00);
    /* u=13=0xD, &~0x18=0x05 -> texel 5 at v=0 -> vram555(5, 0, 5). */
    ASSERT_PIXEL_EQ(TW15_M03_O00_U13_Y0, 13, 0);
)
