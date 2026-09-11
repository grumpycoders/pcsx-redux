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

// Texture window mask + offset behavior. GP0(E2) sets:
//   bits 0-4    mask_x (5-bit, in 8-texel units)
//   bits 5-9    mask_y
//   bits 10-14  offset_x
//   bits 15-19  offset_y
//
// Sampling formula (per psx-spx):
//   texel.u = (u AND NOT (mask.u * 8)) OR ((offset.u * 8) AND (mask.u * 8))
//   texel.v = same for v
//
// Mask bits set in mask.u force those high bits of u to be taken from
// offset.u (each unit = 8 texels). Mask=0 means no windowing.
//
// These tests use the 4-bit CLUT fixture (16 distinct texels, u=0..15
// per pattern row) at TEX4_TPAGE. With mask.u=0x01 (8-texel unit), bit
// 3 of u gets forced to bit 3 of offset.u*8. So:
//   mask.u=0x01, offset.u=0x00 -> u with bit 3 cleared
//                                 (u=8..15 all collapse to texel u=0..7)
//   mask.u=0x01, offset.u=0x01 -> u with bit 3 set (u=0..7 collapse to 8..15)

CESTER_BODY(

// Texture-window test setup: 4-bit triangle large enough to span 16
// texel positions horizontally, with chosen E2 window state.
static void drawTexWindowTri(uint8_t mask_x, uint8_t off_x) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 16);
    setTexpage(TEX4_TX, TEX4_TY, 0);
    setTextureWindow(mask_x, 0, off_x, 0);
    /* Triangle (0,0)-(16,0)-(0,8), UV (0,0)-(16,0)-(0,8). At pixel
       (x, y), sample texel (x, y) -> window-filter -> CLUT[filtered_u]. */
    rasterTexTri(TEX_MOD_NEUTRAL,
                 0, 0,   0, 0,
                 16, 0,  16, 0,
                 0, 8,   0, 8,
                 CLUT4_FIELD, TEX4_TPAGE);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// mask_x = 0, offset_x = 0: identity (no windowing)
// --------------------------------------------------------------------------
// Already covered by phase-4a's texture-basic.c. Skipping duplicates.

// --------------------------------------------------------------------------
// mask_x = 0x01 (= 8-texel-unit mask), offset_x = 0
//   filtered_u = u & ~0x08 = u with bit 3 cleared
//   u=0..7   -> texel 0..7
//   u=8..15  -> texel 0..7 (bit 3 cleared maps 8->0, 9->1, ..., 15->7)
// --------------------------------------------------------------------------

CESTER_TEST(texwin_mask01_off00_pixel_0_0, gpu_raster_phase4,
    drawTexWindowTri(0x01, 0x00);
    /* u=0, filtered=0, CLUT[0]. But CLUT[0] is texel 0 from
       expectedClut4Color(0) = vram555(0, 31, 0). NOTE: at (0,0) this
       reads as transparent if texel value happens to be 0x0000 (after
       CLUT lookup). CLUT[0] = vram555(0, 31, 0) = 0x03E0 != 0x0000,
       so the pixel SHOULD be drawn. */
    ASSERT_PIXEL_EQ(expectedClut4Color(0), 0, 0);
)

CESTER_TEST(texwin_mask01_off00_pixel_7_0_last_unwrapped, gpu_raster_phase4,
    drawTexWindowTri(0x01, 0x00);
    /* u=7, filtered=7, CLUT[7]. */
    ASSERT_PIXEL_EQ(expectedClut4Color(7), 7, 0);
)

CESTER_TEST(texwin_mask01_off00_pixel_8_0_wrapped_to_0, gpu_raster_phase4,
    drawTexWindowTri(0x01, 0x00);
    /* u=8, filtered=8&~8=0, CLUT[0]. So pixel 8 samples same texel as
       pixel 0. */
    ASSERT_PIXEL_EQ(expectedClut4Color(0), 8, 0);
)

CESTER_TEST(texwin_mask01_off00_pixel_11_0_wrapped_to_3, gpu_raster_phase4,
    drawTexWindowTri(0x01, 0x00);
    /* u=11=0xB, filtered=0xB&~0x8=0x3, CLUT[3]. */
    ASSERT_PIXEL_EQ(expectedClut4Color(3), 11, 0);
)

CESTER_TEST(texwin_mask01_off00_pixel_15_0_wrapped_to_7, gpu_raster_phase4,
    drawTexWindowTri(0x01, 0x00);
    /* u=15=0xF, filtered=0xF&~0x8=0x7, CLUT[7]. */
    ASSERT_PIXEL_EQ(expectedClut4Color(7), 15, 0);
)

// --------------------------------------------------------------------------
// mask_x = 0x01, offset_x = 0x01: bit 3 forced to 1
//   filtered_u = (u & ~0x08) | (0x08) = u with bit 3 SET
//   u=0..7   -> 0x08..0x0F (texels 8..15)
//   u=8..15  -> texels 8..15
// --------------------------------------------------------------------------

CESTER_TEST(texwin_mask01_off01_pixel_0_0_forced_to_8, gpu_raster_phase4,
    drawTexWindowTri(0x01, 0x01);
    /* u=0, filtered=0|8=8, CLUT[8]. */
    ASSERT_PIXEL_EQ(expectedClut4Color(8), 0, 0);
)

CESTER_TEST(texwin_mask01_off01_pixel_3_0_forced_to_b, gpu_raster_phase4,
    drawTexWindowTri(0x01, 0x01);
    /* u=3, filtered=3|8=0xB, CLUT[0xB]. */
    ASSERT_PIXEL_EQ(expectedClut4Color(0x0b), 3, 0);
)

CESTER_TEST(texwin_mask01_off01_pixel_8_0_already_set, gpu_raster_phase4,
    drawTexWindowTri(0x01, 0x01);
    /* u=8, filtered=8 (bit 3 already set), CLUT[8]. */
    ASSERT_PIXEL_EQ(expectedClut4Color(8), 8, 0);
)

// --------------------------------------------------------------------------
// mask_x = 0x03 (= 24-bit mask = bits 3,4 of u): bits 3-4 forced from offset
//   With offset_x=0: filtered_u = u & ~0x18 (bits 3 and 4 cleared)
//   u=0..7   -> 0..7
//   u=8..15  -> 0..7 (bit 3 cleared)
// (Same as mask=0x01 for u in 0..15 since bit 4 doesn't apply yet.)
// We test u values where bit 4 would matter at higher u, but my 4-bit
// fixture only covers u=0..15. So just one probe to characterize.
// --------------------------------------------------------------------------

CESTER_TEST(texwin_mask03_off00_pixel_13_0, gpu_raster_phase4,
    drawTexWindowTri(0x03, 0x00);
    /* u=13=0xD, filtered=0xD & ~0x18 = 5, CLUT[5]. */
    ASSERT_PIXEL_EQ(expectedClut4Color(5), 13, 0);
)
