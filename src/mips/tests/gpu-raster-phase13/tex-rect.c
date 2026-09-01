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

// Textured rect probes at 8/15-bit. Naming:
//   TR8_<test>   8-bit CLUT textured rect (GP0 0x64)
//   TR15_<test>  15-bit direct textured rect
//   TR_SEMI_*    semi-trans variant (GP0 0x66)
//   TR_MASK_*    set-mask / check-mask E6 interaction

CESTER_BODY(

// Basic 8-bit textured rect: 8x4 at (0, 0), UV (0, 0). Texel u maps
// to CLUT8[u].
static void drawTR8(int16_t w, int16_t h, uint8_t u, uint8_t v) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 16);
    setTexpage(TEX8_TX, TEX8_TY, 1);
    setTextureWindow(0, 0, 0, 0);
    rasterTexRect(TEX_MOD_NEUTRAL, 0, 0, u, v, w, h, CLUT8_FIELD);
    rasterFlushPrimitive();
}

// Basic 15-bit direct textured rect.
static void drawTR15(int16_t w, int16_t h, uint8_t u, uint8_t v) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 16);
    setTexpage(TEX15_TX, TEX15_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexRect(TEX_MOD_NEUTRAL, 0, 0, u, v, w, h, CLUT15_FIELD);
    rasterFlushPrimitive();
}

// 8-bit semi-trans rect over a red-filled background. Texture uses
// unmasked CLUT - per phase-8 (polygon) finding bit-15=0 should mean
// no blend. Phase-13 verifies whether textured RECTS honor the same
// gate semantics as polygons. Note: textured-rect commands carry NO
// embedded tpage word, so E1 (set via setTexpageAbr) carries both
// the texture page AND the ABR mode for this draw.
static void drawTR8Semi(uint8_t abr) {
    rasterReset();
    rasterFillRect(0, 0, 32, 16, RASTER_VRAM_RED);
    setTexpageAbr(TEX8_TX, TEX8_TY, 1, abr);
    setTextureWindow(0, 0, 0, 0);
    rasterTexRectSemi(TEX_MOD_NEUTRAL, 0, 0, 0, 0, 8, 4, CLUT8_FIELD);
    rasterFlushPrimitive();
    /* Restore default E1 for subsequent tests. */
    setTexpage(0, 0, 0);
}

// 15-bit semi-trans rect with the masked-15-bit fixture installed.
// Bit-15 = 1 on every texel. Per phase-12 polygon finding the gate
// fires and ABR blend applies with bit-15 preserved into VRAM.
// Phase-13 verifies that rule for the rect path.
static void drawTR15SemiMasked(uint8_t abr) {
    rasterReset();
    rasterFillRect(0, 0, 32, 16, RASTER_VRAM_RED);
    uploadTex15Masked();
    setTexpageAbr(TEX15_TX, TEX15_TY, 2, abr);
    setTextureWindow(0, 0, 0, 0);
    rasterTexRectSemi(TEX_MOD_NEUTRAL, 0, 0, 0, 0, 8, 4, CLUT15_FIELD);
    rasterFlushPrimitive();
    setTexpage(0, 0, 0);
    restoreTex15Standard();
}

// 8-bit textured rect with E6 set-mask. Output should carry bit-15.
static void drawTR8SetMask(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 16);
    setTexpage(TEX8_TX, TEX8_TY, 1);
    setTextureWindow(0, 0, 0, 0);
    rasterSetMaskCtrl(1, 0);
    rasterTexRect(TEX_MOD_NEUTRAL, 0, 0, 0, 0, 8, 4, CLUT8_FIELD);
    rasterFlushPrimitive();
    rasterSetMaskCtrl(0, 0);
}

// 15-bit textured rect with E6 check-mask. Pre-fill has bit-15 set
// so writes are skipped; the pre-fill survives.
static void drawTR15CheckMask(void) {
    rasterReset();
    uint16_t bg = (uint16_t)(rasterVram555(8, 0, 0) | 0x8000u);
    rasterFillRect(0, 0, 32, 16, bg);
    setTexpage(TEX15_TX, TEX15_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterSetMaskCtrl(0, 1);
    rasterTexRect(TEX_MOD_NEUTRAL, 0, 0, 0, 0, 8, 4, CLUT15_FIELD);
    rasterFlushPrimitive();
    rasterSetMaskCtrl(0, 0);
}

)  // CESTER_BODY

// ============================================================================
// TR8: basic 8-bit textured rect. Texel(u, v) = u & 0xff -> CLUT8[u].
// ============================================================================

CESTER_TEST(tr8_basic_8x4_0_0, gpu_raster_phase13,
    drawTR8(8, 4, 0, 0);
    /* Pixel (0,0) samples texel u=0 -> CLUT8[0]. */
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 0, 0);
)
CESTER_TEST(tr8_basic_8x4_7_0, gpu_raster_phase13,
    drawTR8(8, 4, 0, 0);
    /* Last column inside rect (x=7) samples texel u=7. */
    ASSERT_PIXEL_EQ(expectedClut8Color(7), 7, 0);
)
CESTER_TEST(tr8_basic_8x4_just_past_8, gpu_raster_phase13,
    drawTR8(8, 4, 0, 0);
    /* x=8 is the right boundary - INCLUSIVE for rects per phase-5
       finding (untextured/textured rects include their right and
       bottom edges, unlike triangles). */
    ASSERT_PIXEL_UNTOUCHED(8, 0);
)
CESTER_TEST(tr8_basic_8x4_bottom_row, gpu_raster_phase13,
    drawTR8(8, 4, 0, 0);
    /* y=3 should be drawn (last row of 4-tall rect). */
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 0, 3);
)
CESTER_TEST(tr8_basic_8x4_past_bottom, gpu_raster_phase13,
    drawTR8(8, 4, 0, 0);
    ASSERT_PIXEL_UNTOUCHED(0, 4);
)

// 1x1 sprite - smallest case.
CESTER_TEST(tr8_1x1_pixel, gpu_raster_phase13,
    drawTR8(1, 1, 5, 0);
    /* Single pixel at (0,0) samples texel u=5. */
    ASSERT_PIXEL_EQ(expectedClut8Color(5), 0, 0);
)
CESTER_TEST(tr8_1x1_neighbor_right, gpu_raster_phase13,
    drawTR8(1, 1, 5, 0);
    ASSERT_PIXEL_UNTOUCHED(1, 0);
)
CESTER_TEST(tr8_1x1_neighbor_below, gpu_raster_phase13,
    drawTR8(1, 1, 5, 0);
    ASSERT_PIXEL_UNTOUCHED(0, 1);
)

// 1xN vertical strip.
CESTER_TEST(tr8_1x4_top, gpu_raster_phase13,
    drawTR8(1, 4, 3, 0);
    /* All four pixels at x=0 sample texel u=3 (V doesn't change u in
       our fixture). */
    ASSERT_PIXEL_EQ(expectedClut8Color(3), 0, 0);
)
CESTER_TEST(tr8_1x4_bottom, gpu_raster_phase13,
    drawTR8(1, 4, 3, 0);
    ASSERT_PIXEL_EQ(expectedClut8Color(3), 0, 3);
)

// Nx1 horizontal strip.
CESTER_TEST(tr8_4x1_left, gpu_raster_phase13,
    drawTR8(4, 1, 0, 0);
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 0, 0);
)
CESTER_TEST(tr8_4x1_right, gpu_raster_phase13,
    drawTR8(4, 1, 0, 0);
    ASSERT_PIXEL_EQ(expectedClut8Color(3), 3, 0);
)

// UV non-zero offset.
CESTER_TEST(tr8_uv_offset_10, gpu_raster_phase13,
    drawTR8(4, 1, 10, 0);
    /* x=0 samples texel u=10. */
    ASSERT_PIXEL_EQ(expectedClut8Color(10), 0, 0);
)
CESTER_TEST(tr8_uv_offset_10_far, gpu_raster_phase13,
    drawTR8(4, 1, 10, 0);
    /* x=3 samples texel u=10+3=13. */
    ASSERT_PIXEL_EQ(expectedClut8Color(13), 3, 0);
)

// ============================================================================
// TR15: basic 15-bit direct textured rect.
// Texel(u, v) = vram555(u & 0x1f, v & 0x1f, (u + v) & 0x1f).
// ============================================================================

CESTER_TEST(tr15_basic_8x4_0_0, gpu_raster_phase13,
    drawTR15(8, 4, 0, 0);
    /* (0,0) -> texel vram555(0, 0, 0) = 0x0000 - transparent! */
    ASSERT_PIXEL_UNTOUCHED(0, 0);
)
CESTER_TEST(tr15_basic_8x4_7_0, gpu_raster_phase13,
    drawTR15(8, 4, 0, 0);
    /* (7, 0) -> vram555(7, 0, 7) = 7 | (7<<10) = 0x1c07 */
    ASSERT_PIXEL_EQ(expectedTex15Color(7, 0), 7, 0);
)
CESTER_TEST(tr15_basic_8x4_0_2, gpu_raster_phase13,
    drawTR15(8, 4, 0, 0);
    /* (0, 2) -> vram555(0, 2, 2) = (2<<5) | (2<<10) = 0x0840 */
    ASSERT_PIXEL_EQ(expectedTex15Color(0, 2), 0, 2);
)
CESTER_TEST(tr15_basic_8x4_5_3, gpu_raster_phase13,
    drawTR15(8, 4, 0, 0);
    /* (5, 3) -> vram555(5, 3, 8) = 5 | (3<<5) | (8<<10) */
    ASSERT_PIXEL_EQ(expectedTex15Color(5, 3), 5, 3);
)

// 1x1 sprite.
CESTER_TEST(tr15_1x1, gpu_raster_phase13,
    drawTR15(1, 1, 4, 4);
    /* (0, 0) -> texel(4, 4) = vram555(4, 4, 8) */
    ASSERT_PIXEL_EQ(expectedTex15Color(4, 4), 0, 0);
)
CESTER_TEST(tr15_1x1_neighbor, gpu_raster_phase13,
    drawTR15(1, 1, 4, 4);
    ASSERT_PIXEL_UNTOUCHED(1, 0);
)

// 1xN vertical strip - V changes down the rect.
CESTER_TEST(tr15_1x4_v_walk_row0, gpu_raster_phase13,
    drawTR15(1, 4, 2, 0);
    /* (0, 0) -> texel(2, 0) = vram555(2, 0, 2) */
    ASSERT_PIXEL_EQ(expectedTex15Color(2, 0), 0, 0);
)
CESTER_TEST(tr15_1x4_v_walk_row3, gpu_raster_phase13,
    drawTR15(1, 4, 2, 0);
    /* (0, 3) -> texel(2, 3) = vram555(2, 3, 5) */
    ASSERT_PIXEL_EQ(expectedTex15Color(2, 3), 0, 3);
)

// UV offset.
CESTER_TEST(tr15_uv_offset, gpu_raster_phase13,
    drawTR15(4, 1, 3, 5);
    /* (0, 0) -> texel(3, 5) = vram555(3, 5, 8) */
    ASSERT_PIXEL_EQ(expectedTex15Color(3, 5), 0, 0);
)
CESTER_TEST(tr15_uv_offset_far, gpu_raster_phase13,
    drawTR15(4, 1, 3, 5);
    /* (3, 0) -> texel(6, 5) = vram555(6, 5, 11) */
    ASSERT_PIXEL_EQ(expectedTex15Color(6, 5), 3, 0);
)

// ============================================================================
// TR8 + UV at texture-window edge. mask_u=0x01 collapses 8-texel
// windows. Verifies the textured rect path applies E2 windowing the
// same way the textured triangle path does.
// ============================================================================

CESTER_TEST(tr8_window_mask01_off00_basic, gpu_raster_phase13,
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 16);
    setTexpage(TEX8_TX, TEX8_TY, 1);
    setTextureWindow(0x01, 0, 0, 0);  /* bit 3 of u cleared */
    rasterTexRect(TEX_MOD_NEUTRAL, 0, 0, 0, 0, 16, 4, CLUT8_FIELD);
    rasterFlushPrimitive();
    /* x=10 samples texel u=10, &~0x08 = 2 -> CLUT8[2] */
    ASSERT_PIXEL_EQ(expectedClut8Color(2), 10, 0);
)

CESTER_TEST(tr8_window_mask01_off00_wrap_7, gpu_raster_phase13,
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 16);
    setTexpage(TEX8_TX, TEX8_TY, 1);
    setTextureWindow(0x01, 0, 0, 0);
    rasterTexRect(TEX_MOD_NEUTRAL, 0, 0, 0, 0, 16, 4, CLUT8_FIELD);
    rasterFlushPrimitive();
    /* x=15 -> u=15=0xF -> &~0x08 = 7 -> CLUT8[7] */
    ASSERT_PIXEL_EQ(expectedClut8Color(7), 15, 0);
)

// ============================================================================
// TR8_SEMI: 8-bit textured rect semi-trans. Bit-15 NOT set in our
// fixture CLUT8 entries, so semi-trans gate does NOT fire - output
// is the un-blended texel value (just CLUT8[u]).
// ============================================================================

CESTER_TEST(tr8_semi_abr0_no_blend, gpu_raster_phase13,
    drawTR8Semi(0);
    /* (0, 0) -> CLUT8[0], no blend (mask=0 gate). */
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 0, 0);
)
CESTER_TEST(tr8_semi_abr1_no_blend, gpu_raster_phase13,
    drawTR8Semi(1);
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 0, 0);
)

// ============================================================================
// TR15_SEMI_MASKED: 15-bit semi-trans rect with masked fixture.
// Gate fires, blend applies, bit-15 preserved (phase-12 finding).
// Probe (0, 0): texel(0,0) = vram555(0,0,0)|0x8000 = 0x8000.
// B = vram555(31, 0, 0) = 0x001f (red pre-fill).
// F8 = (0, 0, 0).
// ABR=0: (B + F)/2 per channel = (31/0/0 / 2) -> R5=15 -> 0x000f | 0x8000 = 0x800f
// ABR=1: B + F = 31/0/0 -> R5=31 -> 0x001f | 0x8000 = 0x801f
// ABR=2: B - F = 31/0/0 -> 0x001f | 0x8000 = 0x801f
// ABR=3: B + F/4 = 31/0/0 -> 0x001f | 0x8000 = 0x801f
// ============================================================================

CESTER_TEST(tr15_semi_masked_abr0, gpu_raster_phase13,
    drawTR15SemiMasked(0);
    /* B/2 + F/2 with F=0 -> B/2. Background red R8=248 -> 124 -> R5=15 */
    ASSERT_PIXEL_EQ(TR15_SEMI_ABR0_BLEND, 0, 0);
)
CESTER_TEST(tr15_semi_masked_abr1, gpu_raster_phase13,
    drawTR15SemiMasked(1);
    /* B + F with F=0 -> B. R5=31. */
    ASSERT_PIXEL_EQ(TR15_SEMI_ABR1_BLEND, 0, 0);
)
CESTER_TEST(tr15_semi_masked_abr2, gpu_raster_phase13,
    drawTR15SemiMasked(2);
    /* B - F with F=0 -> B. R5=31. */
    ASSERT_PIXEL_EQ(TR15_SEMI_ABR2_BLEND, 0, 0);
)
CESTER_TEST(tr15_semi_masked_abr3, gpu_raster_phase13,
    drawTR15SemiMasked(3);
    /* B + F/4 with F=0 -> B. R5=31. */
    ASSERT_PIXEL_EQ(TR15_SEMI_ABR3_BLEND, 0, 0);
)

// ============================================================================
// TR_MASK_*: E6 mask interaction with textured rect.
// ============================================================================

CESTER_TEST(tr8_setmask_output_carries_bit15, gpu_raster_phase13,
    drawTR8SetMask();
    /* CLUT8[0] = vram555(0, 31, 0) = 0x03e0; with set-mask: 0x03e0 | 0x8000 = 0x83e0 */
    ASSERT_PIXEL_EQ(TR8_SETMASK_OUTPUT, 0, 0);
)

CESTER_TEST(tr15_checkmask_writes_skipped, gpu_raster_phase13,
    drawTR15CheckMask();
    /* Pre-fill (R5=8, mask=1) survives. */
    ASSERT_PIXEL_EQ(TR15_CHECKMASK_PREFILL, 0, 0);
)
