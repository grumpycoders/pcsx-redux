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

// ABR mode matrix. The four PS1 semi-trans modes are:
//   ABR=0: B/2 + F/2 (average)
//   ABR=1: B + F     (additive, clamp at max)
//   ABR=2: B - F     (subtractive, clamp at 0)
//   ABR=3: B + F/4   (add quarter, clamp at max)
//
// where B is the existing VRAM pixel ("background") and F is the
// incoming foreground from the primitive. Per psx-spx the blend runs
// in 8-bit channel space: VRAM 5-bit B is conceptually shifted up by
// 3 to form B8, blended with the 8-bit F, then truncated back to 5
// bits for VRAM. We use 5-bit-boundary-aligned channel values (R5 *
// 8) so the round-trip is exact and the captured 5-bit output maps
// cleanly to the documented formulas.

CESTER_BODY(

// Convenience: build an R-only 24-bit command color from R5 (5-bit
// value 0..31). Foreground sent to the GPU as 8-bit; we put R8 = R5
// * 8 in the low byte. G and B are zero so the test focuses on R.
static inline uint32_t cmdR5(uint8_t r5) {
    return (uint32_t)(r5 & 0x1f) << 3;
}

// Pre-fill the test region with an R-only background. b5 is the
// 5-bit R channel; the rest is zero (which equals 0 in VRAM 5:5:5).
static inline void fillR(int16_t x, int16_t y, int16_t w, int16_t h,
                         uint8_t b5) {
    uint16_t pixel = rasterVram555((uint8_t)(b5 & 0x1f), 0, 0);
    rasterFillRect(x, y, w, h, pixel);
}

// Draw a 12x12 semi-trans triangle of color F at (0, 0). The
// triangle is wide enough that probing the deep interior at (4, 4)
// captures a pixel that's far from the top-left edge artifacts.
static void drawAbrTri(uint8_t b5, uint8_t f5, uint8_t abr) {
    rasterReset();
    fillR(0, 0, 32, 32, b5);
    rasterSetAbr(abr);
    rasterFlatTriSemi(cmdR5(f5),
                      0,  0,
                      11, 0,
                      0,  11);
    rasterFlushPrimitive();
    rasterSetAbr(0);  /* restore default for next test */
}

static void drawAbrQuad(uint8_t b5, uint8_t f5, uint8_t abr) {
    rasterReset();
    fillR(0, 0, 32, 32, b5);
    rasterSetAbr(abr);
    rasterFlatQuadSemi(cmdR5(f5),
                       0,  0,
                       11, 0,
                       0,  11,
                       11, 11);
    rasterFlushPrimitive();
    rasterSetAbr(0);
}

static void drawAbrRect(uint8_t b5, uint8_t f5, uint8_t abr) {
    rasterReset();
    fillR(0, 0, 32, 32, b5);
    rasterSetAbr(abr);
    rasterFlatRectSemi(cmdR5(f5), 0, 0, 12, 12);
    rasterFlushPrimitive();
    rasterSetAbr(0);
}

static void drawAbrLine(uint8_t b5, uint8_t f5, uint8_t abr) {
    rasterReset();
    fillR(0, 0, 32, 8, b5);
    rasterSetAbr(abr);
    rasterFlatLineSemi(cmdR5(f5), 0, 4, 11, 4);
    rasterFlushPrimitive();
    rasterSetAbr(0);
}

// GP0(0x26) semi-trans textured triangle. The texpage's ABR field
// would normally drive blend, but tests set E1 ABR explicitly via
// rasterSetAbr right before the draw - the soft renderer reads ABR
// from the cached texpage state set most recently via E1 or via the
// last textured primitive's embedded tpage word.
static inline void rasterTexTriSemi(uint32_t cmdColor,
                                    int16_t x0, int16_t y0, uint8_t u0, uint8_t v0,
                                    int16_t x1, int16_t y1, uint8_t u1, uint8_t v1,
                                    int16_t x2, int16_t y2, uint8_t u2, uint8_t v2,
                                    uint16_t clut_field, uint16_t tpage_field) {
    waitGPU();
    GPU_DATA = 0x26000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y0 << 16) | (uint32_t)(uint16_t)x0;
    GPU_DATA = ((uint32_t)clut_field << 16) |
               ((uint32_t)v0 << 8) | (uint32_t)u0;
    GPU_DATA = ((uint32_t)(uint16_t)y1 << 16) | (uint32_t)(uint16_t)x1;
    GPU_DATA = ((uint32_t)tpage_field << 16) |
               ((uint32_t)v1 << 8) | (uint32_t)u1;
    GPU_DATA = ((uint32_t)(uint16_t)y2 << 16) | (uint32_t)(uint16_t)x2;
    GPU_DATA = (0u << 16) | ((uint32_t)v2 << 8) | (uint32_t)u2;
}

// Draw a textured semi-trans triangle using the masked CLUT (every
// entry has bit-15 set). Probe pixel (4, 2) samples texel (4, 2) -
// 4-bit CLUT entry [4] = vram555(4, 27, 0) | 0x8000.
static void drawAbrTexTriMasked(uint8_t b5, uint8_t abr) {
    rasterReset();
    fillR(0, 0, 32, 16, b5);
    /* Build texpage with the requested ABR field embedded so the GPU
       sees the right blend mode even if E1 wasn't re-set. */
    uint16_t tpage = (uint16_t)((TEX4_TX & 0xf) | ((TEX4_TY & 1) << 4)
                                | ((abr & 3) << 5) | (0u << 7));
    setTexpage(TEX4_TX, TEX4_TY, 0);
    rasterSetAbr(abr);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTriSemi(TEX_MOD_NEUTRAL,
                     0, 0,   0, 0,
                     11, 0,  11, 0,
                     0, 8,   0, 8,
                     CLUT4_FIELD, tpage);
    rasterFlushPrimitive();
    rasterSetAbr(0);
}

// Semi-trans triangle with E6 SET-MASK enabled. Output should be the
// blended value with bit-15 OR'd in.
static void drawAbrTriSetMask(uint8_t b5, uint8_t f5, uint8_t abr) {
    rasterReset();
    fillR(0, 0, 32, 32, b5);
    rasterSetAbr(abr);
    rasterSetMaskCtrl(1, 0);
    rasterFlatTriSemi(cmdR5(f5),
                      0, 0, 11, 0, 0, 11);
    rasterFlushPrimitive();
    rasterSetMaskCtrl(0, 0);
    rasterSetAbr(0);
}

// Semi-trans triangle with E6 CHECK-MASK enabled. Background pre-fill
// has bit-15 set so the check-mask SKIPS those pixels (no blend
// applied, sentinel-ish stays).
static void drawAbrTriCheckMask(uint8_t b5, uint8_t f5, uint8_t abr) {
    rasterReset();
    /* Pre-fill with bit-15 already set */
    uint16_t bg = (uint16_t)(rasterVram555((uint8_t)(b5 & 0x1f), 0, 0) | 0x8000u);
    rasterFillRect(0, 0, 32, 32, bg);
    rasterSetAbr(abr);
    rasterSetMaskCtrl(0, 1);
    rasterFlatTriSemi(cmdR5(f5),
                      0, 0, 11, 0, 0, 11);
    rasterFlushPrimitive();
    rasterSetMaskCtrl(0, 0);
    rasterSetAbr(0);
}

)  // CESTER_BODY

// ============================================================================
// ABR_TRI: math sweep across the 4 modes and 9 (B, F) pairs.
// All probes at (4, 4) - interior of the 12x12 semi-trans tri.
// B, F values chosen on 5-bit boundaries: 0, 16, 31 (8-bit: 0, 128,
// 248). 9 pairs cover (0,0), (0,16), (0,31), (16,0), (16,16),
// (16,31), (31,0), (31,16), (31,31). Each pair tested in all 4 modes
// = 36 tests.
// ============================================================================

CESTER_TEST(abr0_tri_b00_f00, gpu_raster_phase12, drawAbrTri(0,  0,  0); ASSERT_PIXEL_EQ(ABR0_B00_F00, 4, 4); )
CESTER_TEST(abr0_tri_b00_f16, gpu_raster_phase12, drawAbrTri(0,  16, 0); ASSERT_PIXEL_EQ(ABR0_B00_F16, 4, 4); )
CESTER_TEST(abr0_tri_b00_f31, gpu_raster_phase12, drawAbrTri(0,  31, 0); ASSERT_PIXEL_EQ(ABR0_B00_F31, 4, 4); )
CESTER_TEST(abr0_tri_b16_f00, gpu_raster_phase12, drawAbrTri(16, 0,  0); ASSERT_PIXEL_EQ(ABR0_B16_F00, 4, 4); )
CESTER_TEST(abr0_tri_b16_f16, gpu_raster_phase12, drawAbrTri(16, 16, 0); ASSERT_PIXEL_EQ(ABR0_B16_F16, 4, 4); )
CESTER_TEST(abr0_tri_b16_f31, gpu_raster_phase12, drawAbrTri(16, 31, 0); ASSERT_PIXEL_EQ(ABR0_B16_F31, 4, 4); )
CESTER_TEST(abr0_tri_b31_f00, gpu_raster_phase12, drawAbrTri(31, 0,  0); ASSERT_PIXEL_EQ(ABR0_B31_F00, 4, 4); )
CESTER_TEST(abr0_tri_b31_f16, gpu_raster_phase12, drawAbrTri(31, 16, 0); ASSERT_PIXEL_EQ(ABR0_B31_F16, 4, 4); )
CESTER_TEST(abr0_tri_b31_f31, gpu_raster_phase12, drawAbrTri(31, 31, 0); ASSERT_PIXEL_EQ(ABR0_B31_F31, 4, 4); )

CESTER_TEST(abr1_tri_b00_f00, gpu_raster_phase12, drawAbrTri(0,  0,  1); ASSERT_PIXEL_EQ(ABR1_B00_F00, 4, 4); )
CESTER_TEST(abr1_tri_b00_f16, gpu_raster_phase12, drawAbrTri(0,  16, 1); ASSERT_PIXEL_EQ(ABR1_B00_F16, 4, 4); )
CESTER_TEST(abr1_tri_b00_f31, gpu_raster_phase12, drawAbrTri(0,  31, 1); ASSERT_PIXEL_EQ(ABR1_B00_F31, 4, 4); )
CESTER_TEST(abr1_tri_b16_f00, gpu_raster_phase12, drawAbrTri(16, 0,  1); ASSERT_PIXEL_EQ(ABR1_B16_F00, 4, 4); )
CESTER_TEST(abr1_tri_b16_f16, gpu_raster_phase12, drawAbrTri(16, 16, 1); ASSERT_PIXEL_EQ(ABR1_B16_F16, 4, 4); )
CESTER_TEST(abr1_tri_b16_f31, gpu_raster_phase12, drawAbrTri(16, 31, 1); ASSERT_PIXEL_EQ(ABR1_B16_F31, 4, 4); )
CESTER_TEST(abr1_tri_b31_f00, gpu_raster_phase12, drawAbrTri(31, 0,  1); ASSERT_PIXEL_EQ(ABR1_B31_F00, 4, 4); )
CESTER_TEST(abr1_tri_b31_f16, gpu_raster_phase12, drawAbrTri(31, 16, 1); ASSERT_PIXEL_EQ(ABR1_B31_F16, 4, 4); )
CESTER_TEST(abr1_tri_b31_f31, gpu_raster_phase12, drawAbrTri(31, 31, 1); ASSERT_PIXEL_EQ(ABR1_B31_F31, 4, 4); )

CESTER_TEST(abr2_tri_b00_f00, gpu_raster_phase12, drawAbrTri(0,  0,  2); ASSERT_PIXEL_EQ(ABR2_B00_F00, 4, 4); )
CESTER_TEST(abr2_tri_b00_f16, gpu_raster_phase12, drawAbrTri(0,  16, 2); ASSERT_PIXEL_EQ(ABR2_B00_F16, 4, 4); )
CESTER_TEST(abr2_tri_b00_f31, gpu_raster_phase12, drawAbrTri(0,  31, 2); ASSERT_PIXEL_EQ(ABR2_B00_F31, 4, 4); )
CESTER_TEST(abr2_tri_b16_f00, gpu_raster_phase12, drawAbrTri(16, 0,  2); ASSERT_PIXEL_EQ(ABR2_B16_F00, 4, 4); )
CESTER_TEST(abr2_tri_b16_f16, gpu_raster_phase12, drawAbrTri(16, 16, 2); ASSERT_PIXEL_EQ(ABR2_B16_F16, 4, 4); )
CESTER_TEST(abr2_tri_b16_f31, gpu_raster_phase12, drawAbrTri(16, 31, 2); ASSERT_PIXEL_EQ(ABR2_B16_F31, 4, 4); )
CESTER_TEST(abr2_tri_b31_f00, gpu_raster_phase12, drawAbrTri(31, 0,  2); ASSERT_PIXEL_EQ(ABR2_B31_F00, 4, 4); )
CESTER_TEST(abr2_tri_b31_f16, gpu_raster_phase12, drawAbrTri(31, 16, 2); ASSERT_PIXEL_EQ(ABR2_B31_F16, 4, 4); )
CESTER_TEST(abr2_tri_b31_f31, gpu_raster_phase12, drawAbrTri(31, 31, 2); ASSERT_PIXEL_EQ(ABR2_B31_F31, 4, 4); )

CESTER_TEST(abr3_tri_b00_f00, gpu_raster_phase12, drawAbrTri(0,  0,  3); ASSERT_PIXEL_EQ(ABR3_B00_F00, 4, 4); )
CESTER_TEST(abr3_tri_b00_f16, gpu_raster_phase12, drawAbrTri(0,  16, 3); ASSERT_PIXEL_EQ(ABR3_B00_F16, 4, 4); )
CESTER_TEST(abr3_tri_b00_f31, gpu_raster_phase12, drawAbrTri(0,  31, 3); ASSERT_PIXEL_EQ(ABR3_B00_F31, 4, 4); )
CESTER_TEST(abr3_tri_b16_f00, gpu_raster_phase12, drawAbrTri(16, 0,  3); ASSERT_PIXEL_EQ(ABR3_B16_F00, 4, 4); )
CESTER_TEST(abr3_tri_b16_f16, gpu_raster_phase12, drawAbrTri(16, 16, 3); ASSERT_PIXEL_EQ(ABR3_B16_F16, 4, 4); )
CESTER_TEST(abr3_tri_b16_f31, gpu_raster_phase12, drawAbrTri(16, 31, 3); ASSERT_PIXEL_EQ(ABR3_B16_F31, 4, 4); )
CESTER_TEST(abr3_tri_b31_f00, gpu_raster_phase12, drawAbrTri(31, 0,  3); ASSERT_PIXEL_EQ(ABR3_B31_F00, 4, 4); )
CESTER_TEST(abr3_tri_b31_f16, gpu_raster_phase12, drawAbrTri(31, 16, 3); ASSERT_PIXEL_EQ(ABR3_B31_F16, 4, 4); )
CESTER_TEST(abr3_tri_b31_f31, gpu_raster_phase12, drawAbrTri(31, 31, 3); ASSERT_PIXEL_EQ(ABR3_B31_F31, 4, 4); )

// ============================================================================
// ABR_PRIM: same blend math across other untextured primitive types.
// Single representative (B=16, F=16) per ABR mode for each primitive.
// Confirms primitives share blend math.
// ============================================================================

CESTER_TEST(abr0_quad_b16_f16, gpu_raster_phase12, drawAbrQuad(16, 16, 0); ASSERT_PIXEL_EQ(ABR0_PRIM_QUAD, 4, 4); )
CESTER_TEST(abr1_quad_b16_f16, gpu_raster_phase12, drawAbrQuad(16, 16, 1); ASSERT_PIXEL_EQ(ABR1_PRIM_QUAD, 4, 4); )
CESTER_TEST(abr2_quad_b16_f16, gpu_raster_phase12, drawAbrQuad(16, 16, 2); ASSERT_PIXEL_EQ(ABR2_PRIM_QUAD, 4, 4); )
CESTER_TEST(abr3_quad_b16_f16, gpu_raster_phase12, drawAbrQuad(16, 16, 3); ASSERT_PIXEL_EQ(ABR3_PRIM_QUAD, 4, 4); )

CESTER_TEST(abr0_rect_b16_f16, gpu_raster_phase12, drawAbrRect(16, 16, 0); ASSERT_PIXEL_EQ(ABR0_PRIM_RECT, 4, 4); )
CESTER_TEST(abr1_rect_b16_f16, gpu_raster_phase12, drawAbrRect(16, 16, 1); ASSERT_PIXEL_EQ(ABR1_PRIM_RECT, 4, 4); )
CESTER_TEST(abr2_rect_b16_f16, gpu_raster_phase12, drawAbrRect(16, 16, 2); ASSERT_PIXEL_EQ(ABR2_PRIM_RECT, 4, 4); )
CESTER_TEST(abr3_rect_b16_f16, gpu_raster_phase12, drawAbrRect(16, 16, 3); ASSERT_PIXEL_EQ(ABR3_PRIM_RECT, 4, 4); )

CESTER_TEST(abr0_line_b16_f16, gpu_raster_phase12, drawAbrLine(16, 16, 0); ASSERT_PIXEL_EQ(ABR0_PRIM_LINE, 5, 4); )
CESTER_TEST(abr1_line_b16_f16, gpu_raster_phase12, drawAbrLine(16, 16, 1); ASSERT_PIXEL_EQ(ABR1_PRIM_LINE, 5, 4); )
CESTER_TEST(abr2_line_b16_f16, gpu_raster_phase12, drawAbrLine(16, 16, 2); ASSERT_PIXEL_EQ(ABR2_PRIM_LINE, 5, 4); )
CESTER_TEST(abr3_line_b16_f16, gpu_raster_phase12, drawAbrLine(16, 16, 3); ASSERT_PIXEL_EQ(ABR3_PRIM_LINE, 5, 4); )

// ============================================================================
// ABR_TEX_MASKED: textured semi-trans tri at 4-bit with masked CLUT.
// CLUT entry [4] has bit-15 set so the semi-trans gate fires. Probe
// (4, 2) which samples texel u=4, CLUT[4] = vram555(4, 27, 0)|0x8000.
// Then blend formula applies. Capture for all 4 ABR modes.
// ============================================================================

CESTER_TEST(abr0_tex_masked_b16, gpu_raster_phase12, drawAbrTexTriMasked(16, 0); ASSERT_PIXEL_EQ(ABR0_TEX_MASKED, 4, 2); )
CESTER_TEST(abr1_tex_masked_b16, gpu_raster_phase12, drawAbrTexTriMasked(16, 1); ASSERT_PIXEL_EQ(ABR1_TEX_MASKED, 4, 2); )
CESTER_TEST(abr2_tex_masked_b16, gpu_raster_phase12, drawAbrTexTriMasked(16, 2); ASSERT_PIXEL_EQ(ABR2_TEX_MASKED, 4, 2); )
CESTER_TEST(abr3_tex_masked_b16, gpu_raster_phase12, drawAbrTexTriMasked(16, 3); ASSERT_PIXEL_EQ(ABR3_TEX_MASKED, 4, 2); )

// ============================================================================
// ABR_MASKBIT: set-mask and check-mask interactions.
// Set-mask: output should be blended value with bit-15 forced to 1.
// Check-mask: pre-fill has bit-15 set, so writes are SKIPPED - read
// returns the pre-fill value unchanged.
// ============================================================================

CESTER_TEST(abr0_setmask_b16_f16, gpu_raster_phase12, drawAbrTriSetMask(16, 16, 0); ASSERT_PIXEL_EQ(ABR0_SETMASK, 4, 4); )
CESTER_TEST(abr1_setmask_b16_f16, gpu_raster_phase12, drawAbrTriSetMask(16, 16, 1); ASSERT_PIXEL_EQ(ABR1_SETMASK, 4, 4); )
CESTER_TEST(abr2_setmask_b16_f16, gpu_raster_phase12, drawAbrTriSetMask(16, 16, 2); ASSERT_PIXEL_EQ(ABR2_SETMASK, 4, 4); )
CESTER_TEST(abr3_setmask_b16_f16, gpu_raster_phase12, drawAbrTriSetMask(16, 16, 3); ASSERT_PIXEL_EQ(ABR3_SETMASK, 4, 4); )

CESTER_TEST(abr0_checkmask_b16_f16, gpu_raster_phase12, drawAbrTriCheckMask(16, 16, 0); ASSERT_PIXEL_EQ(ABR0_CHECKMASK, 4, 4); )
CESTER_TEST(abr1_checkmask_b16_f16, gpu_raster_phase12, drawAbrTriCheckMask(16, 16, 1); ASSERT_PIXEL_EQ(ABR1_CHECKMASK, 4, 4); )
CESTER_TEST(abr2_checkmask_b16_f16, gpu_raster_phase12, drawAbrTriCheckMask(16, 16, 2); ASSERT_PIXEL_EQ(ABR2_CHECKMASK, 4, 4); )
CESTER_TEST(abr3_checkmask_b16_f16, gpu_raster_phase12, drawAbrTriCheckMask(16, 16, 3); ASSERT_PIXEL_EQ(ABR3_CHECKMASK, 4, 4); )
