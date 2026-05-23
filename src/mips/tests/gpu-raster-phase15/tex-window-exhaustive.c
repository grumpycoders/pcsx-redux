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

// Texture windowing exhaustive probes. Naming:
//   WT_MASKxx_OFFxx_<probe>  triangle path window
//   WR_MASKxx_OFFxx_<probe>  rect path window
//   WQ_MASKxx_OFFxx_<probe>  quad path window (verifies the rule
//                            applies to 4-vert sweep too)
//   WS_ABR<n>_<probe>        window × semi-trans
//   WX_<probe>               window × bit-15 transparency

CESTER_BODY(

// Draw a 32x16 8-bit textured triangle with UV matching screen, then
// the test reads back at a given probe pixel position. Window state
// is set just before the draw via the caller.
static void drawWindowTri(uint8_t mask_x, uint8_t mask_y,
                          uint8_t off_x, uint8_t off_y) {
    rasterReset();
    rasterClearTestRegion(0, 0, 64, 16);
    setTexpage(TEX8_TX, TEX8_TY, 1);
    setTextureWindow(mask_x, mask_y, off_x, off_y);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 0, 0,    0, 0,
                 32, 0,   32, 0,
                 0, 8,    0, 8,
                 CLUT8_FIELD, TEX8_TPAGE);
    rasterFlushPrimitive();
}

static void drawWindowRect(uint8_t mask_x, uint8_t mask_y,
                           uint8_t off_x, uint8_t off_y) {
    rasterReset();
    rasterClearTestRegion(0, 0, 64, 16);
    setTexpage(TEX8_TX, TEX8_TY, 1);
    setTextureWindow(mask_x, mask_y, off_x, off_y);
    rasterTexRect(TEX_MOD_NEUTRAL, 0, 0, 0, 0, 32, 8, CLUT8_FIELD);
    rasterFlushPrimitive();
}

static void drawWindowQuad(uint8_t mask_x, uint8_t mask_y,
                           uint8_t off_x, uint8_t off_y) {
    rasterReset();
    rasterClearTestRegion(0, 0, 64, 16);
    setTexpage(TEX8_TX, TEX8_TY, 1);
    setTextureWindow(mask_x, mask_y, off_x, off_y);
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      0, 0,    0, 0,
                      31, 0,   31, 0,
                      0, 7,    0, 7,
                      31, 7,   31, 7,
                      CLUT8_FIELD, TEX8_TPAGE);
    rasterFlushPrimitive();
}

// Window × semi-trans: 8-bit rect with mask_u=0x01, offset_u=0,
// background pre-filled red. Window collapses u=8..15 to texels 0..7.
// Probe x=8 - WITHOUT window, samples CLUT8[8] = vram555(8, 23, 0).
// WITH window, samples CLUT8[0] = vram555(0, 31, 0). Bit-15 not set,
// no blend - hardware should write the windowed texel value through.
//
// At ABR != 0 the rect command line above shouldn't blend (texel bit
// 15 is 0). This series verifies the gate semantics under window.
static void drawWindowSemi(uint8_t abr) {
    rasterReset();
    rasterFillRect(0, 0, 64, 16, RASTER_VRAM_RED);
    setTexpageAbr(TEX8_TX, TEX8_TY, 1, abr);
    setTextureWindow(0x01, 0, 0, 0);
    rasterTexRectSemi(TEX_MOD_NEUTRAL, 0, 0, 0, 0, 16, 4, CLUT8_FIELD);
    rasterFlushPrimitive();
    setTexpage(0, 0, 0);
}

// Window × bit-15-mask transparency: same window as above (mask_u=0x01
// collapses u=8..15 to 0..7), but CLUT8[0] has bit-15 SET. Without
// the window, sampling u=8 gives CLUT8[8] (no mask, opaque). With the
// window, sampling u=8 gives CLUT8[0] (mask SET, semi-trans gate
// fires). Probes whether transparency applies on the windowed sample.
static void drawWindowTransparency(uint8_t abr) {
    rasterReset();
    rasterFillRect(0, 0, 64, 16, RASTER_VRAM_RED);
    uploadClut8MaskedAt0();
    setTexpageAbr(TEX8_TX, TEX8_TY, 1, abr);
    setTextureWindow(0x01, 0, 0, 0);
    /* At x=8 in semi-trans rect path, hardware samples u=8 -> window
       collapses to u=0 -> CLUT8[0] (now masked). Whether the gate
       fires on the windowed or unwindowed value is the question. */
    rasterTexRectSemi(TEX_MOD_NEUTRAL, 0, 0, 0, 0, 16, 4, CLUT8_FIELD);
    rasterFlushPrimitive();
    setTexpage(0, 0, 0);
    /* Restore standard CLUT8 for subsequent tests. */
    uploadClut8();
}

)  // CESTER_BODY

// ============================================================================
// WT_MASK0X_OFF00: mask sweep at offset=0, single-axis (U).
// Probe x=8 - the test position where the mask effect kicks in.
// ============================================================================

CESTER_TEST(wt_mask00_off00_identity, gpu_raster_phase15,
    drawWindowTri(0x00, 0, 0, 0);
    /* mask=0 = identity. x=8 samples texel u=8 normally. */
    ASSERT_PIXEL_EQ(expectedClut8Color(8), 8, 0);
)
CESTER_TEST(wt_mask01_off00_wrap8, gpu_raster_phase15,
    drawWindowTri(0x01, 0, 0, 0);
    /* bit 3 cleared: x=8 -> u=8 -> &~0x08=0 -> CLUT8[0]. */
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 8, 0);
)
CESTER_TEST(wt_mask07_off00_x8, gpu_raster_phase15,
    drawWindowTri(0x07, 0, 0, 0);
    /* bits 3,4,5 cleared: x=8 -> u=8 -> &~0x38=0 -> CLUT8[0]. */
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 8, 0);
)
CESTER_TEST(wt_mask0f_off00_x8, gpu_raster_phase15,
    drawWindowTri(0x0f, 0, 0, 0);
    /* bits 3-6 cleared: x=8 -> u=8 -> &~0x78=0 -> CLUT8[0]. */
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 8, 0);
)
CESTER_TEST(wt_mask1f_off00_x8, gpu_raster_phase15,
    drawWindowTri(0x1f, 0, 0, 0);
    /* bits 3-7 cleared: x=8 -> u=8 -> &~0xf8=0 -> CLUT8[0]. */
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 8, 0);
)
CESTER_TEST(wt_mask1f_off00_x1, gpu_raster_phase15,
    drawWindowTri(0x1f, 0, 0, 0);
    /* x=1 -> u=1. &~0xf8 = 1 -> CLUT8[1]. */
    ASSERT_PIXEL_EQ(expectedClut8Color(1), 1, 0);
)
CESTER_TEST(wt_mask1f_off00_x7, gpu_raster_phase15,
    drawWindowTri(0x1f, 0, 0, 0);
    /* x=7 -> u=7 -> &~0xf8 = 7 -> CLUT8[7]. */
    ASSERT_PIXEL_EQ(expectedClut8Color(7), 7, 0);
)

// ============================================================================
// WT_MASK0F_OFFxx: offset sweep at mask=0x0F (4-bit window).
// Offset bits get OR'd into the high bits of u after masking.
// ============================================================================

CESTER_TEST(wt_mask0f_off01_x0, gpu_raster_phase15,
    drawWindowTri(0x0f, 0, 0x01, 0);
    /* x=0 -> u=0; filtered_u = 0 | (0x01 << 3) = 0x08 -> CLUT8[8]. */
    ASSERT_PIXEL_EQ(expectedClut8Color(8), 0, 0);
)
CESTER_TEST(wt_mask0f_off03_x0, gpu_raster_phase15,
    drawWindowTri(0x0f, 0, 0x03, 0);
    /* filtered_u = 0 | 0x18 = 0x18 = 24 -> CLUT8[24]. */
    ASSERT_PIXEL_EQ(expectedClut8Color(0x18), 0, 0);
)
CESTER_TEST(wt_mask0f_off0f_x0, gpu_raster_phase15,
    drawWindowTri(0x0f, 0, 0x0f, 0);
    /* filtered_u = 0 | 0x78 = 0x78 = 120. Per the formula CLUT8[120]
       would apply, but the 8-bit fixture is only uploaded for u=0..63
       so u=120 reads BEYOND the uploaded region into whatever VRAM
       contains there. Hardware truth captured at 0x03e0; this is an
       artefact of the test fixture not covering the full mask range,
       not a window-formula divergence. The formula was already
       verified within-range above. */
    ASSERT_PIXEL_EQ(WT_MASK0F_OFF0F_X0_HW, 0, 0);
)
CESTER_TEST(wt_mask1f_off1f_x0, gpu_raster_phase15,
    drawWindowTri(0x1f, 0, 0x1f, 0);
    /* filtered_u = 0xf8 = 248. Outside uploaded texture range; hardware
       truth captured. Same caveat as above. */
    ASSERT_PIXEL_EQ(WT_MASK1F_OFF1F_X0_HW, 0, 0);
)

// ============================================================================
// Combined U-V mask × offset. V is interesting because our fixture
// pattern doesn't depend on V, so V-windowing alone should be a no-op
// at the pixel level. But the V coords get applied to VRAM read
// addressing - hardware truth is what matters.
// ============================================================================

CESTER_TEST(wt_maskU01_maskV01_off00_x8y4, gpu_raster_phase15,
    drawWindowTri(0x01, 0x01, 0, 0);
    /* (8, 4) -> u=8 & ~8 = 0, v=4 & ~8 = 4. CLUT8[0] (V not used). */
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 8, 4);
)
CESTER_TEST(wt_maskU01_maskV01_off11_x8y4, gpu_raster_phase15,
    drawWindowTri(0x01, 0x01, 0x01, 0x01);
    /* offset (1, 1) sets bit 3 of u and v.
       u=8 & ~8 | 8 = 8; v=4 & ~8 | 8 = 12. CLUT8[8] = expectedClut8Color(8). */
    ASSERT_PIXEL_EQ(expectedClut8Color(8), 8, 4);
)

// ============================================================================
// Offset > mask. When offset bits are NOT covered by mask, only the
// mask-covered bits of offset apply. psx-spx: filtered = (u & ~M) | (O & M).
// ============================================================================

CESTER_TEST(wt_mask01_off07_x0, gpu_raster_phase15,
    drawWindowTri(0x01, 0, 0x07, 0);
    /* mask=0x01 only covers bit 3. offset=0x07 has bits 3-5 set.
       Only bit 3 of offset applies (the rest masked out).
       filtered_u = 0 & ~8 | (0x07 << 3) & 8 = 0 | 8 = 8 -> CLUT8[8]. */
    ASSERT_PIXEL_EQ(expectedClut8Color(8), 0, 0);
)
CESTER_TEST(wt_mask03_off1f_x0, gpu_raster_phase15,
    drawWindowTri(0x03, 0, 0x1f, 0);
    /* mask=0x03 covers bits 3-4. offset=0x1F has bits 3-7.
       filtered_u = 0 | (0xf8 & 0x18) = 0x18 -> CLUT8[24]. */
    ASSERT_PIXEL_EQ(expectedClut8Color(0x18), 0, 0);
)

// ============================================================================
// Prim-type sweep: window applied to rect and quad. Same mask/offset
// as the triangle reference probe; output should match.
// ============================================================================

CESTER_TEST(wr_mask01_off00_x8, gpu_raster_phase15,
    drawWindowRect(0x01, 0, 0, 0);
    /* Rect at (0,0) 32x8 with mask_u=0x01, x=8 -> u=8 -> wraps to 0. */
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 8, 0);
)
CESTER_TEST(wq_mask01_off00_x8, gpu_raster_phase15,
    drawWindowQuad(0x01, 0, 0, 0);
    /* Quad at (0,0)-(31,0)-(0,7)-(31,7) with mask_u=0x01, x=8 same as
       triangle - wraps to u=0. */
    ASSERT_PIXEL_EQ(expectedClut8Color(0), 8, 0);
)
CESTER_TEST(wr_mask03_off01_x12, gpu_raster_phase15,
    drawWindowRect(0x03, 0, 0x01, 0);
    /* x=12 -> u=12=0x0C, &~0x18 = 0x04, | 0x08 = 0x0C -> CLUT8[12]. */
    ASSERT_PIXEL_EQ(expectedClut8Color(12), 12, 0);
)
CESTER_TEST(wq_mask03_off01_x12, gpu_raster_phase15,
    drawWindowQuad(0x03, 0, 0x01, 0);
    ASSERT_PIXEL_EQ(expectedClut8Color(12), 12, 0);
)

// ============================================================================
// Window × semi-trans (window-filtered texel through ABR blend).
// At x=8 with mask_u=0x01: windowed u=0, CLUT8[0] = vram555(0, 31, 0)
// = 0x03e0 (bit-15 = 0 in standard fixture). With bit-15=0, semi-trans
// gate does NOT fire - texel writes through opaquely. So all four
// ABR modes should produce the same un-blended texel = 0x03e0.
// ============================================================================

CESTER_TEST(ws_window_semi_abr0, gpu_raster_phase15,
    drawWindowSemi(0);
    ASSERT_PIXEL_EQ(WS_WINDOW_SEMI_NO_BLEND, 8, 0);
)
CESTER_TEST(ws_window_semi_abr1, gpu_raster_phase15,
    drawWindowSemi(1);
    ASSERT_PIXEL_EQ(WS_WINDOW_SEMI_NO_BLEND, 8, 0);
)
CESTER_TEST(ws_window_semi_abr2, gpu_raster_phase15,
    drawWindowSemi(2);
    ASSERT_PIXEL_EQ(WS_WINDOW_SEMI_NO_BLEND, 8, 0);
)
CESTER_TEST(ws_window_semi_abr3, gpu_raster_phase15,
    drawWindowSemi(3);
    ASSERT_PIXEL_EQ(WS_WINDOW_SEMI_NO_BLEND, 8, 0);
)

// ============================================================================
// Window × bit-15 transparency. With mask_u=0x01, x=8 collapses to
// u=0, sampling CLUT8[0] which now has bit-15 SET. Question: does
// the gate fire on the WINDOWED sample (yes -> blend with bg) or on
// the unfiltered u=8 sample (no - CLUT8[8] has bit-15=0)?
// ============================================================================

CESTER_TEST(wx_window_transparency_abr0_x8, gpu_raster_phase15,
    drawWindowTransparency(0);
    /* If gate fires on windowed sample (bit-15=1 at CLUT8[0]): ABR=0
       blend of red bg and CLUT8[0]. If gate fires on raw u=8 sample
       (bit-15=0 at CLUT8[8] before window): no blend, output = ???
       Hardware truth captured. */
    ASSERT_PIXEL_EQ(WX_WINDOW_TRANS_ABR0, 8, 0);
)
CESTER_TEST(wx_window_transparency_abr0_x0, gpu_raster_phase15,
    drawWindowTransparency(0);
    /* Control: x=0 doesn't go through window (u=0 mapped to u=0).
       Same as no-window case at x=0. */
    ASSERT_PIXEL_EQ(WX_WINDOW_TRANS_X0, 0, 0);
)
