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

// Dither characterization. Each draw call below produces a CONSTANT-
// color triangle (all three vertices the same 24-bit GP0 color) under
// gouraud + dither on. Input color is constant across every pixel,
// so any per-pixel output difference is the dither table offset at
// that screen-space position.
//
// rgb24(R8, G8, B8) builds the 24-bit GP0 command color in the
// canonical wire layout: bits 0-7 = R, 8-15 = G, 16-23 = B.

CESTER_BODY(

static inline uint32_t rgb24(uint8_t r, uint8_t g, uint8_t b) {
    return (uint32_t)r | ((uint32_t)g << 8) | ((uint32_t)b << 16);
}

// Draw a 32x32 constant-color gouraud triangle at (x0, y0).
// All three vertices share the same 24-bit color so per-pixel input
// is constant. Dither bit (E1[9]) is set before the draw.
static void drawDitherConstTri(uint32_t color24, int16_t x0, int16_t y0) {
    rasterReset();
    rasterClearTestRegion(0, 0, 64, 64);
    rasterSetDither(1);
    rasterGouraudTri(color24, x0,         y0,
                     color24, (int16_t)(x0 + 31), y0,
                     color24, x0,         (int16_t)(y0 + 31));
    rasterFlushPrimitive();
    rasterSetDither(0);
}

// Standard probe origin: (0, 0) for the canonical capture series.
// The 4x4 Bayer cell at (cx, cy) lands at probe (8 + cx, 8 + cy)
// when the triangle is at origin and dither table is screen-space-
// anchored to (0, 0).
static void drawCanonicalAt(uint32_t color24) {
    drawDitherConstTri(color24, 0, 0);
}

)  // CESTER_BODY

// ============================================================================
// DT_BAYER: 4x4 Bayer capture at mid-gray (R=G=B=128). Probes all 16
// cells of one period at (8..11, 8..11). The output at each cell is
// the dither-altered VRAM value for input (R=128, G=128, B=128).
// Subtracting the nominal mid-gray (vram555(16, 16, 16) = 0x4210)
// gives the per-cell offset map at this base color.
// ============================================================================

CESTER_TEST(dt_bayer_mid_8_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_8_8,  8,  8); )
CESTER_TEST(dt_bayer_mid_9_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_9_8,  9,  8); )
CESTER_TEST(dt_bayer_mid_10_8, gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_10_8, 10, 8); )
CESTER_TEST(dt_bayer_mid_11_8, gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_11_8, 11, 8); )
CESTER_TEST(dt_bayer_mid_8_9,  gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_8_9,  8,  9); )
CESTER_TEST(dt_bayer_mid_9_9,  gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_9_9,  9,  9); )
CESTER_TEST(dt_bayer_mid_10_9, gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_10_9, 10, 9); )
CESTER_TEST(dt_bayer_mid_11_9, gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_11_9, 11, 9); )
CESTER_TEST(dt_bayer_mid_8_10, gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_8_10, 8,  10); )
CESTER_TEST(dt_bayer_mid_9_10, gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_9_10, 9,  10); )
CESTER_TEST(dt_bayer_mid_10_10,gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_10_10,10, 10); )
CESTER_TEST(dt_bayer_mid_11_10,gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_11_10,11, 10); )
CESTER_TEST(dt_bayer_mid_8_11, gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_8_11, 8,  11); )
CESTER_TEST(dt_bayer_mid_9_11, gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_9_11, 9,  11); )
CESTER_TEST(dt_bayer_mid_10_11,gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_10_11,10, 11); )
CESTER_TEST(dt_bayer_mid_11_11,gpu_raster_phase11, drawCanonicalAt(rgb24(128, 128, 128)); ASSERT_PIXEL_EQ(DT_BAYER_MID_11_11,11, 11); )

// ============================================================================
// DT_BASE_R: R-only base color sweep. G=0, B=0 across all 16 cells at
// base R = 0x40, 0x80, 0xC0. Together with DT_SAT_R series this gives
// a 5-base sweep on the R channel: 0x04 (near-min), 0x40, 0x80, 0xC0,
// 0xFC (near-max). If the dither table is additive across base color,
// each cell's offset (output_R - nominal_R) should be the same across
// bases. If it's base-dependent (multiplicative or LUT-based), the
// per-base offsets diverge.
// ============================================================================

CESTER_TEST(dt_base_r40_8_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_8_8,  8,  8); )
CESTER_TEST(dt_base_r40_9_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_9_8,  9,  8); )
CESTER_TEST(dt_base_r40_10_8, gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_10_8, 10, 8); )
CESTER_TEST(dt_base_r40_11_8, gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_11_8, 11, 8); )
CESTER_TEST(dt_base_r40_8_9,  gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_8_9,  8,  9); )
CESTER_TEST(dt_base_r40_9_9,  gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_9_9,  9,  9); )
CESTER_TEST(dt_base_r40_10_9, gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_10_9, 10, 9); )
CESTER_TEST(dt_base_r40_11_9, gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_11_9, 11, 9); )
CESTER_TEST(dt_base_r40_8_10, gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_8_10, 8,  10); )
CESTER_TEST(dt_base_r40_9_10, gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_9_10, 9,  10); )
CESTER_TEST(dt_base_r40_10_10,gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_10_10,10, 10); )
CESTER_TEST(dt_base_r40_11_10,gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_11_10,11, 10); )
CESTER_TEST(dt_base_r40_8_11, gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_8_11, 8,  11); )
CESTER_TEST(dt_base_r40_9_11, gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_9_11, 9,  11); )
CESTER_TEST(dt_base_r40_10_11,gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_10_11,10, 11); )
CESTER_TEST(dt_base_r40_11_11,gpu_raster_phase11, drawCanonicalAt(rgb24(0x40, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R40_11_11,11, 11); )

CESTER_TEST(dt_base_r80_8_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_8_8,  8,  8); )
CESTER_TEST(dt_base_r80_9_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_9_8,  9,  8); )
CESTER_TEST(dt_base_r80_10_8, gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_10_8, 10, 8); )
CESTER_TEST(dt_base_r80_11_8, gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_11_8, 11, 8); )
CESTER_TEST(dt_base_r80_8_9,  gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_8_9,  8,  9); )
CESTER_TEST(dt_base_r80_9_9,  gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_9_9,  9,  9); )
CESTER_TEST(dt_base_r80_10_9, gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_10_9, 10, 9); )
CESTER_TEST(dt_base_r80_11_9, gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_11_9, 11, 9); )
CESTER_TEST(dt_base_r80_8_10, gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_8_10, 8,  10); )
CESTER_TEST(dt_base_r80_9_10, gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_9_10, 9,  10); )
CESTER_TEST(dt_base_r80_10_10,gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_10_10,10, 10); )
CESTER_TEST(dt_base_r80_11_10,gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_11_10,11, 10); )
CESTER_TEST(dt_base_r80_8_11, gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_8_11, 8,  11); )
CESTER_TEST(dt_base_r80_9_11, gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_9_11, 9,  11); )
CESTER_TEST(dt_base_r80_10_11,gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_10_11,10, 11); )
CESTER_TEST(dt_base_r80_11_11,gpu_raster_phase11, drawCanonicalAt(rgb24(0x80, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_R80_11_11,11, 11); )

CESTER_TEST(dt_base_rc0_8_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_8_8,  8,  8); )
CESTER_TEST(dt_base_rc0_9_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_9_8,  9,  8); )
CESTER_TEST(dt_base_rc0_10_8, gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_10_8, 10, 8); )
CESTER_TEST(dt_base_rc0_11_8, gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_11_8, 11, 8); )
CESTER_TEST(dt_base_rc0_8_9,  gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_8_9,  8,  9); )
CESTER_TEST(dt_base_rc0_9_9,  gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_9_9,  9,  9); )
CESTER_TEST(dt_base_rc0_10_9, gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_10_9, 10, 9); )
CESTER_TEST(dt_base_rc0_11_9, gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_11_9, 11, 9); )
CESTER_TEST(dt_base_rc0_8_10, gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_8_10, 8,  10); )
CESTER_TEST(dt_base_rc0_9_10, gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_9_10, 9,  10); )
CESTER_TEST(dt_base_rc0_10_10,gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_10_10,10, 10); )
CESTER_TEST(dt_base_rc0_11_10,gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_11_10,11, 10); )
CESTER_TEST(dt_base_rc0_8_11, gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_8_11, 8,  11); )
CESTER_TEST(dt_base_rc0_9_11, gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_9_11, 9,  11); )
CESTER_TEST(dt_base_rc0_10_11,gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_10_11,10, 11); )
CESTER_TEST(dt_base_rc0_11_11,gpu_raster_phase11, drawCanonicalAt(rgb24(0xc0, 0, 0)); ASSERT_PIXEL_EQ(DT_BASE_RC0_11_11,11, 11); )

// ============================================================================
// DT_CHAN_G / DT_CHAN_B: 4-cell controls at G-only and B-only base 128.
// Confirms the dither table is channel-independent - the per-cell offset
// at (8, 8) should be the same for R-only, G-only, and B-only base 128.
// ============================================================================

CESTER_TEST(dt_chan_g80_8_8,   gpu_raster_phase11, drawCanonicalAt(rgb24(0, 0x80, 0)); ASSERT_PIXEL_EQ(DT_CHAN_G80_8_8,  8,  8); )
CESTER_TEST(dt_chan_g80_9_8,   gpu_raster_phase11, drawCanonicalAt(rgb24(0, 0x80, 0)); ASSERT_PIXEL_EQ(DT_CHAN_G80_9_8,  9,  8); )
CESTER_TEST(dt_chan_g80_10_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(0, 0x80, 0)); ASSERT_PIXEL_EQ(DT_CHAN_G80_10_8, 10, 8); )
CESTER_TEST(dt_chan_g80_11_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(0, 0x80, 0)); ASSERT_PIXEL_EQ(DT_CHAN_G80_11_8, 11, 8); )

CESTER_TEST(dt_chan_b80_8_8,   gpu_raster_phase11, drawCanonicalAt(rgb24(0, 0, 0x80)); ASSERT_PIXEL_EQ(DT_CHAN_B80_8_8,  8,  8); )
CESTER_TEST(dt_chan_b80_9_8,   gpu_raster_phase11, drawCanonicalAt(rgb24(0, 0, 0x80)); ASSERT_PIXEL_EQ(DT_CHAN_B80_9_8,  9,  8); )
CESTER_TEST(dt_chan_b80_10_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(0, 0, 0x80)); ASSERT_PIXEL_EQ(DT_CHAN_B80_10_8, 10, 8); )
CESTER_TEST(dt_chan_b80_11_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(0, 0, 0x80)); ASSERT_PIXEL_EQ(DT_CHAN_B80_11_8, 11, 8); )

// ============================================================================
// DT_POS: position sweep. Same constant-color mid-gray triangle at
// different (x, y) origins. Probe a fixed screen-space pixel under
// each triangle. If dither is screen-space-anchored to (0, 0), the
// captured value at screen-space (16, 16) should be the same
// regardless of which triangle covers it. If it's triangle-relative,
// the value varies with origin offset.
//
// Triangles at:
//   POS_00: origin (0, 0),  probe (16, 16)
//   POS_04: origin (0, 4),  probe (16, 16)  - shifted +4Y
//   POS_40: origin (4, 0),  probe (16, 16)  - shifted +4X
//   POS_44: origin (4, 4),  probe (16, 16)  - shifted (+4, +4)
//
// All four are mid-gray (R=G=B=128); only the triangle origin differs.
// If the 4-cell shift moves the captured pixel into a different Bayer
// cell, screen-space anchoring is confirmed. If all four read the same
// value, the dither table is anchored to the triangle's start vertex.
// ============================================================================

CESTER_TEST(dt_pos_00_at_16_16, gpu_raster_phase11,
    drawDitherConstTri(rgb24(128, 128, 128), 0, 0);
    ASSERT_PIXEL_EQ(DT_POS_00_AT_16_16, 16, 16);
)
CESTER_TEST(dt_pos_04_at_16_16, gpu_raster_phase11,
    drawDitherConstTri(rgb24(128, 128, 128), 0, 4);
    ASSERT_PIXEL_EQ(DT_POS_04_AT_16_16, 16, 16);
)
CESTER_TEST(dt_pos_40_at_16_16, gpu_raster_phase11,
    drawDitherConstTri(rgb24(128, 128, 128), 4, 0);
    ASSERT_PIXEL_EQ(DT_POS_40_AT_16_16, 16, 16);
)
CESTER_TEST(dt_pos_44_at_16_16, gpu_raster_phase11,
    drawDitherConstTri(rgb24(128, 128, 128), 4, 4);
    ASSERT_PIXEL_EQ(DT_POS_44_AT_16_16, 16, 16);
)

// ============================================================================
// DT_SAT_LOW: near-min base (R=4). Dither cells that would push below
// 0 must clamp at 0 - not wrap. Probes 4 cells.
// ============================================================================

CESTER_TEST(dt_sat_low_r04_8_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(0x04, 0, 0)); ASSERT_PIXEL_EQ(DT_SAT_LOW_R04_8_8,  8,  8); )
CESTER_TEST(dt_sat_low_r04_9_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(0x04, 0, 0)); ASSERT_PIXEL_EQ(DT_SAT_LOW_R04_9_8,  9,  8); )
CESTER_TEST(dt_sat_low_r04_10_8, gpu_raster_phase11, drawCanonicalAt(rgb24(0x04, 0, 0)); ASSERT_PIXEL_EQ(DT_SAT_LOW_R04_10_8, 10, 8); )
CESTER_TEST(dt_sat_low_r04_11_8, gpu_raster_phase11, drawCanonicalAt(rgb24(0x04, 0, 0)); ASSERT_PIXEL_EQ(DT_SAT_LOW_R04_11_8, 11, 8); )

// ============================================================================
// DT_SAT_HIGH: near-max base (R=0xFC). Dither cells that would push
// above 255 must clamp at 31 in 5-bit space.
// ============================================================================

CESTER_TEST(dt_sat_high_rfc_8_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(0xfc, 0, 0)); ASSERT_PIXEL_EQ(DT_SAT_HIGH_RFC_8_8,  8,  8); )
CESTER_TEST(dt_sat_high_rfc_9_8,  gpu_raster_phase11, drawCanonicalAt(rgb24(0xfc, 0, 0)); ASSERT_PIXEL_EQ(DT_SAT_HIGH_RFC_9_8,  9,  8); )
CESTER_TEST(dt_sat_high_rfc_10_8, gpu_raster_phase11, drawCanonicalAt(rgb24(0xfc, 0, 0)); ASSERT_PIXEL_EQ(DT_SAT_HIGH_RFC_10_8, 10, 8); )
CESTER_TEST(dt_sat_high_rfc_11_8, gpu_raster_phase11, drawCanonicalAt(rgb24(0xfc, 0, 0)); ASSERT_PIXEL_EQ(DT_SAT_HIGH_RFC_11_8, 11, 8); )

// ============================================================================
// DT_SAT_CROSS: probes the cells where the Bayer offset would push
// the dithered value across the channel boundary, distinguishing
// clamp-vs-wrap policy.
//
// Cells (0, 0) and (2, 2) have offset -4 - at screen positions (8, 8)
// and (10, 10). Cells (2, 1) and (0, 3) have offset +3 - at screen
// (10, 9) and (8, 11).
// ============================================================================

CESTER_TEST(dt_sat_cross_under_r3_8_8, gpu_raster_phase11,
    /* R=3 at cell offset -4 = -1 raw. Clamp: 0 -> R5=0. Wrap: 255 -> R5=31. */
    drawCanonicalAt(rgb24(0x03, 0, 0));
    ASSERT_PIXEL_EQ(DT_SAT_CROSS_UNDER_R3_8_8, 8, 8);
)
CESTER_TEST(dt_sat_cross_under_r3_10_10, gpu_raster_phase11,
    drawCanonicalAt(rgb24(0x03, 0, 0));
    ASSERT_PIXEL_EQ(DT_SAT_CROSS_UNDER_R3_10_10, 10, 10);
)
CESTER_TEST(dt_sat_cross_land_r4_8_8, gpu_raster_phase11,
    /* R=4 at cell offset -4 = 0. Output R5=0 regardless of policy. */
    drawCanonicalAt(rgb24(0x04, 0, 0));
    ASSERT_PIXEL_EQ(DT_SAT_CROSS_LAND_R4_8_8, 8, 8);
)
CESTER_TEST(dt_sat_cross_over_r255_10_9, gpu_raster_phase11,
    /* R=255 at cell offset +3 = 258 raw. Clamp: 255 -> R5=31. Wrap: 2 -> R5=0. */
    drawCanonicalAt(rgb24(0xff, 0, 0));
    ASSERT_PIXEL_EQ(DT_SAT_CROSS_OVER_R255_10_9, 10, 9);
)
CESTER_TEST(dt_sat_cross_over_r255_8_11, gpu_raster_phase11,
    drawCanonicalAt(rgb24(0xff, 0, 0));
    ASSERT_PIXEL_EQ(DT_SAT_CROSS_OVER_R255_8_11, 8, 11);
)
CESTER_TEST(dt_sat_cross_land_r252_10_9, gpu_raster_phase11,
    /* R=252 at cell offset +3 = 255 exactly. Output R5=31 regardless. */
    drawCanonicalAt(rgb24(0xfc, 0, 0));
    ASSERT_PIXEL_EQ(DT_SAT_CROSS_LAND_R252_10_9, 10, 9);
)
