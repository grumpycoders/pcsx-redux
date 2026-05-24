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

// Mask-bit set + check behavior across PRIMITIVE TYPES. Phase-2 only
// tested triangles; this suite extends to rectangles, lines, textured
// rectangles, and textured triangles at all three depths. Each
// primitive type goes through its own writer code path in the soft
// renderer, and the audit (writer-policy refactor track) treats mask
// behavior as embedded in writers rather than templated. Cross-
// primitive coverage matters for the refactor.
//
// Pattern: pass 1 draws with set-mask (E6=0x01), expecting pixels to
// land with bit 15 forced. Pass 2 with check-mask (E6=0x02) overlays
// a second primitive; pixels with bit 15 set should be preserved,
// pixels with bit 15 clear (or sentinel) should be overwritten.
//
// Local sentinel 0x5555 (bit 15 clear) - same workaround as phase-2.

#define MASK_SUITE_SENTINEL  0x5555u

CESTER_BODY(

static void fillSuiteRegion(int16_t x, int16_t y, int16_t w, int16_t h) {
    rasterFillRect(x, y, w, h, MASK_SUITE_SENTINEL);
}

// -- Rectangle (GP0 0x60) --

static void drawRectSet(void) {
    rasterReset();
    fillSuiteRegion(0, 0, 16, 8);
    sendGPUData(0xe6000001u);
    /* 4x4 RED rect at (0,0). */
    rasterFlatRect(RASTER_CMD_RED, 0, 0, 4, 4);
    rasterFlushPrimitive();
    sendGPUData(0xe6000000u);
}

static void drawRectSetThenCheck(void) {
    rasterReset();
    fillSuiteRegion(0, 0, 16, 8);
    /* Pass 1: RED rect (0,0,4,4) with set-mask. */
    sendGPUData(0xe6000001u);
    rasterFlatRect(RASTER_CMD_RED, 0, 0, 4, 4);
    rasterFlushPrimitive();
    /* Pass 2: GREEN rect (2,0,6,4) with check-mask. Overlap region
       (2..3, 0..3) should be preserved RED-with-mask. Non-overlap
       (4..7, 0..3) should fill GREEN. */
    sendGPUData(0xe6000002u);
    rasterFlatRect(RASTER_CMD_GREEN, 2, 0, 6, 4);
    rasterFlushPrimitive();
    sendGPUData(0xe6000000u);
}

// -- Line (GP0 0x40) --

static void drawLineSet(void) {
    rasterReset();
    fillSuiteRegion(0, 0, 16, 4);
    sendGPUData(0xe6000001u);
    /* Horizontal RED line from (0,0) to (5,0). */
    rasterFlatLine(RASTER_CMD_RED, 0, 0, 5, 0);
    rasterFlushPrimitive();
    sendGPUData(0xe6000000u);
}

static void drawLineSetThenCheck(void) {
    rasterReset();
    fillSuiteRegion(0, 0, 16, 4);
    sendGPUData(0xe6000001u);
    rasterFlatLine(RASTER_CMD_RED, 0, 0, 5, 0);
    rasterFlushPrimitive();
    sendGPUData(0xe6000002u);
    /* Overlay GREEN line (3,0)-(8,0). Overlap pixels (3..5) preserved,
       new pixels (6..8) filled GREEN. */
    rasterFlatLine(RASTER_CMD_GREEN, 3, 0, 8, 0);
    rasterFlushPrimitive();
    sendGPUData(0xe6000000u);
}

// -- Textured rectangle (GP0 0x64) - 4-bit CLUT --

// GP0(0x64) variable-size textured rectangle. Word layout:
//   word 0: 0x64xxxxxx (24-bit modulation color)
//   word 1: y << 16 | x   (top-left corner)
//   word 2: clut << 16 | (v0 << 8) | u0   (UV at top-left + CLUT)
//   word 3: h << 16 | w   (size)
//
// Texpage state comes from the LAST GP0(E1), not embedded in the
// command. So setTexpage() must precede the draw.
static inline void rasterFlatTexRect(uint32_t cmdColor, int16_t x, int16_t y,
                                     int16_t w, int16_t h, uint8_t u0,
                                     uint8_t v0, uint16_t clut_field) {
    waitGPU();
    GPU_DATA = 0x64000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)x;
    GPU_DATA = ((uint32_t)clut_field << 16) |
               ((uint32_t)v0 << 8) | (uint32_t)u0;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)w;
}

static void drawTexRect4Set(void) {
    rasterReset();
    fillSuiteRegion(0, 0, 16, 8);
    setTexpage(TEX4_TX, TEX4_TY, 0);
    setTextureWindow(0, 0, 0, 0);
    sendGPUData(0xe6000001u);
    /* 4x4 textured rect at (0,0) with UV (1,1)-(4,4) at 4-bit. */
    rasterFlatTexRect(TEX_MOD_NEUTRAL, 0, 0, 4, 4, 1, 1, CLUT4_FIELD);
    rasterFlushPrimitive();
    sendGPUData(0xe6000000u);
}

// -- Textured triangle (GP0 0x24) - 4-bit CLUT --

static void drawTexTri4Set(void) {
    rasterReset();
    fillSuiteRegion(0, 0, 16, 8);
    setTexpage(TEX4_TX, TEX4_TY, 0);
    setTextureWindow(0, 0, 0, 0);
    sendGPUData(0xe6000001u);
    /* 4-pixel triangle at (0,0)(4,0)(0,4) with UV matching. */
    rasterTexTri(TEX_MOD_NEUTRAL,
                 0, 0,   1, 1,
                 4, 0,   5, 1,
                 0, 4,   1, 5,
                 CLUT4_FIELD, TEX4_TPAGE);
    rasterFlushPrimitive();
    sendGPUData(0xe6000000u);
}

// -- Textured triangle (GP0 0x24) - 8-bit CLUT --

static void drawTexTri8Set(void) {
    rasterReset();
    fillSuiteRegion(0, 0, 16, 8);
    setTexpage(TEX8_TX, TEX8_TY, 1);
    setTextureWindow(0, 0, 0, 0);
    sendGPUData(0xe6000001u);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 0, 0,   1, 1,
                 4, 0,   5, 1,
                 0, 4,   1, 5,
                 CLUT8_FIELD, TEX8_TPAGE);
    rasterFlushPrimitive();
    sendGPUData(0xe6000000u);
}

// -- Textured triangle (GP0 0x24) - 15-bit direct --

static void drawTexTri15Set(void) {
    rasterReset();
    fillSuiteRegion(0, 0, 16, 8);
    setTexpage(TEX15_TX, TEX15_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    sendGPUData(0xe6000001u);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 0, 0,   1, 1,
                 4, 0,   5, 1,
                 0, 4,   1, 5,
                 CLUT15_FIELD, TEX15_TPAGE);
    rasterFlushPrimitive();
    sendGPUData(0xe6000000u);
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// Rectangle mask-bit
// --------------------------------------------------------------------------

CESTER_TEST(rect_mask_set_origin_has_bit15, gpu_raster_phase5,
    drawRectSet();
    /* (0,0) drawn RED with mask -> 0x801f. */
    ASSERT_PIXEL_EQ(0x801fu, 0, 0);
)

CESTER_TEST(rect_mask_set_interior_has_bit15, gpu_raster_phase5,
    drawRectSet();
    ASSERT_PIXEL_EQ(0x801fu, 2, 2);
)

CESTER_TEST(rect_mask_set_right_edge_excluded, gpu_raster_phase5,
    drawRectSet();
    ASSERT_PIXEL_EQ((unsigned)MASK_SUITE_SENTINEL, 4, 0);
)

CESTER_TEST(rect_mask_check_preserves_red_in_overlap, gpu_raster_phase5,
    drawRectSetThenCheck();
    /* (2, 0) in both rects. RED mask-set written first, GREEN
       check-mask should skip. Expect 0x801f preserved. */
    ASSERT_PIXEL_EQ(0x801fu, 2, 0);
)

CESTER_TEST(rect_mask_check_fills_green_in_non_overlap, gpu_raster_phase5,
    drawRectSetThenCheck();
    /* (6, 0) only in GREEN rect, sentinel before, mask bit clear,
       should fill GREEN. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 6, 0);
)

CESTER_TEST(rect_mask_check_red_untouched_left, gpu_raster_phase5,
    drawRectSetThenCheck();
    /* (0, 0) RED-mask only (not in GREEN overlap). Stays 0x801f. */
    ASSERT_PIXEL_EQ(0x801fu, 0, 0);
)

// --------------------------------------------------------------------------
// Line mask-bit
// --------------------------------------------------------------------------

CESTER_TEST(line_mask_set_start_has_bit15, gpu_raster_phase5,
    drawLineSet();
    ASSERT_PIXEL_EQ(0x801fu, 0, 0);
)

CESTER_TEST(line_mask_set_mid_has_bit15, gpu_raster_phase5,
    drawLineSet();
    ASSERT_PIXEL_EQ(0x801fu, 3, 0);
)

CESTER_TEST(line_mask_set_end_inclusive, gpu_raster_phase5,
    drawLineSet();
    /* PSX lines are endpoint-inclusive (verified phase-2). */
    ASSERT_PIXEL_EQ(0x801fu, 5, 0);
)

CESTER_TEST(line_mask_check_preserves_overlap, gpu_raster_phase5,
    drawLineSetThenCheck();
    ASSERT_PIXEL_EQ(0x801fu, 4, 0);
)

CESTER_TEST(line_mask_check_fills_new_pixel, gpu_raster_phase5,
    drawLineSetThenCheck();
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 7, 0);
)

// --------------------------------------------------------------------------
// Textured rectangle mask-bit (4-bit CLUT)
// --------------------------------------------------------------------------

CESTER_TEST(texrect4_mask_set_origin_has_bit15, gpu_raster_phase5,
    drawTexRect4Set();
    /* (0,0) of textured rect samples UV (1,1) -> CLUT[1] from 4-bit
       fixture = vram555(1, 30, 0) = 0x03C1, with mask bit forced:
       0x83C1. */
    uint16_t expected = (uint16_t)(expectedClut4Color(1) | 0x8000);
    ASSERT_PIXEL_EQ(expected, 0, 0);
)

CESTER_TEST(texrect4_mask_set_interior_has_bit15, gpu_raster_phase5,
    drawTexRect4Set();
    /* (2,2) of rect samples UV (3,3) -> CLUT[3] | 0x8000. */
    uint16_t expected = (uint16_t)(expectedClut4Color(3) | 0x8000);
    ASSERT_PIXEL_EQ(expected, 2, 2);
)

CESTER_TEST(texrect4_mask_set_right_edge_excluded, gpu_raster_phase5,
    drawTexRect4Set();
    ASSERT_PIXEL_EQ((unsigned)MASK_SUITE_SENTINEL, 4, 0);
)

// --------------------------------------------------------------------------
// Textured triangle mask-bit at all three depths
// --------------------------------------------------------------------------

CESTER_TEST(textri4_mask_set_origin, gpu_raster_phase5,
    drawTexTri4Set();
    /* At screen (0,0), UV (1,1), CLUT[1] | 0x8000. */
    uint16_t expected = (uint16_t)(expectedClut4Color(1) | 0x8000);
    ASSERT_PIXEL_EQ(expected, 0, 0);
)

CESTER_TEST(textri4_mask_set_interior, gpu_raster_phase5,
    drawTexTri4Set();
    uint16_t expected = (uint16_t)(expectedClut4Color(2) | 0x8000);
    ASSERT_PIXEL_EQ(expected, 1, 1);
)

CESTER_TEST(textri4_mask_set_right_edge_excluded, gpu_raster_phase5,
    drawTexTri4Set();
    ASSERT_PIXEL_EQ((unsigned)MASK_SUITE_SENTINEL, 4, 0);
)

CESTER_TEST(textri8_mask_set_origin, gpu_raster_phase5,
    drawTexTri8Set();
    uint16_t expected = (uint16_t)(expectedClut8Color(1) | 0x8000);
    ASSERT_PIXEL_EQ(expected, 0, 0);
)

CESTER_TEST(textri8_mask_set_interior, gpu_raster_phase5,
    drawTexTri8Set();
    uint16_t expected = (uint16_t)(expectedClut8Color(2) | 0x8000);
    ASSERT_PIXEL_EQ(expected, 1, 1);
)

CESTER_TEST(textri15_mask_set_origin, gpu_raster_phase5,
    drawTexTri15Set();
    /* 15-bit direct: texel at UV (1,1) is vram555(1, 1, 2) | 0x8000. */
    uint16_t expected = (uint16_t)(expectedTex15Color(1, 1) | 0x8000);
    ASSERT_PIXEL_EQ(expected, 0, 0);
)

CESTER_TEST(textri15_mask_set_interior, gpu_raster_phase5,
    drawTexTri15Set();
    uint16_t expected = (uint16_t)(expectedTex15Color(2, 2) | 0x8000);
    ASSERT_PIXEL_EQ(expected, 1, 1);
)

CESTER_TEST(textri15_mask_set_right_edge_excluded, gpu_raster_phase5,
    drawTexTri15Set();
    ASSERT_PIXEL_EQ((unsigned)MASK_SUITE_SENTINEL, 4, 0);
)
