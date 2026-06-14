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

// Phase-8 4-vert flat textured quad tests. Each draw uses the texture
// fixtures uploaded by uploadAllTextureFixtures(); fixture textures
// are content-addressed (texel value = f(u, v)) so the test can read
// back the VRAM pixel and assert it matches the expected texel-CLUT
// lookup. Vertex/UV layouts target three concerns:
//
//   - Baseline UV interpolation across non-trivial quad shapes.
//   - Terminal-odd-pixel sampler behavior (audit finding #8: 4-vert
//     paths use posY + difY at the terminal, hardware truth is among
//     what this captures).
//   - Semi-trans opcode (0x2E) path correctness.

CESTER_BODY(

// ---- Axis-aligned quads, UV 1:1 with screen ------------------------------

static void drawQFA4(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 16);
    setTexpage(TEX4_TX, TEX4_TY, 0);
    setTextureWindow(0, 0, 0, 0);
    /* 16-wide x 8-tall axis-aligned quad, UV matching screen. */
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      0,  0,  0,  0,
                      15, 0,  15, 0,
                      0,  7,  0,  7,
                      15, 7,  15, 7,
                      CLUT4_FIELD, TEX4_TPAGE);
    rasterFlushPrimitive();
}

static void drawQFA8(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 48, 16);
    setTexpage(TEX8_TX, TEX8_TY, 1);
    setTextureWindow(0, 0, 0, 0);
    /* 32-wide x 8-tall - more 8-bit texels per row. */
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      0,  0,  0,  0,
                      31, 0,  31, 0,
                      0,  7,  0,  7,
                      31, 7,  31, 7,
                      CLUT8_FIELD, TEX8_TPAGE);
    rasterFlushPrimitive();
}

static void drawQFA15(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 16);
    setTexpage(TEX15_TX, TEX15_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      0,  0,  0,  0,
                      15, 0,  15, 0,
                      0,  7,  0,  7,
                      15, 7,  15, 7,
                      CLUT15_FIELD, TEX15_TPAGE);
    rasterFlushPrimitive();
}

// ---- Skewed parallelogram quads (non-rectangular UV interpolation) -------

static void drawQFD4(void) {
    /* Parallelogram: bottom edge shifted +4 in X. Top vertices at
       (0,0) and (15,0); bottom at (4,7) and (19,7). UV is still
       0..15 across the width at each row, so the per-row UV
       interpolation has to interpolate U from 0 to 15 across a
       row whose pixel-extent shifts with Y. */
    rasterReset();
    rasterClearTestRegion(0, 0, 28, 16);
    setTexpage(TEX4_TX, TEX4_TY, 0);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      0,  0,  0,  0,
                      15, 0,  15, 0,
                      4,  7,  0,  7,
                      19, 7,  15, 7,
                      CLUT4_FIELD, TEX4_TPAGE);
    rasterFlushPrimitive();
}

static void drawQFD15(void) {
    /* Same shape, 15-bit texture - UV reads back as direct pixel. */
    rasterReset();
    rasterClearTestRegion(0, 0, 28, 16);
    setTexpage(TEX15_TX, TEX15_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      0,  0,  0,  0,
                      15, 0,  15, 0,
                      4,  7,  0,  7,
                      19, 7,  15, 7,
                      CLUT15_FIELD, TEX15_TPAGE);
    rasterFlushPrimitive();
}

// ---- Odd-width row terminal probes (audit finding #8) --------------------
//
// 5x4 axis-aligned quad: each row covers 5 pixels (xmin=0..xmax=4),
// odd width -> terminal sampler fires at j=4. UV matching screen so
// terminal pixel "should" sample texel (4, row). Capture what
// hardware actually returns at each terminal pixel.

static void drawQFO4(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    setTexpage(TEX4_TX, TEX4_TY, 0);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      0, 0, 0, 0,
                      4, 0, 4, 0,
                      0, 3, 0, 3,
                      4, 3, 4, 3,
                      CLUT4_FIELD, TEX4_TPAGE);
    rasterFlushPrimitive();
}

static void drawQFO8(void) {
    /* Same 5x4 shape, 8-bit texture. Terminal pixel samples texel
       (4, row) -> CLUT8[4] = expectedClut8Color(4). */
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    setTexpage(TEX8_TX, TEX8_TY, 1);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      0, 0, 0, 0,
                      4, 0, 4, 0,
                      0, 3, 0, 3,
                      4, 3, 4, 3,
                      CLUT8_FIELD, TEX8_TPAGE);
    rasterFlushPrimitive();
}

static void drawQFO15(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    setTexpage(TEX15_TX, TEX15_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      0, 0, 0, 0,
                      4, 0, 4, 0,
                      0, 3, 0, 3,
                      4, 3, 4, 3,
                      CLUT15_FIELD, TEX15_TPAGE);
    rasterFlushPrimitive();
}

// ---- Semi-trans (GP0(0x2E)) variants -------------------------------------
//
// drawPoly4TEx*_S paths. The terminal sampler at j==xmax is the same
// asymmetry as opaque. Pre-fill the test region with a known opaque
// color so the semi-trans blend produces a deterministic result we
// can capture.

static void drawQFS4(void) {
    rasterReset();
    /* Pre-fill with VRAM red so semi-trans has a non-sentinel
       background to blend against. */
    rasterFillRect(0, 0, 32, 16, RASTER_VRAM_RED);
    setTexpage(TEX4_TX, TEX4_TY, 0);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuadSemi(TEX_MOD_NEUTRAL,
                          0,  0,  0,  0,
                          15, 0,  15, 0,
                          0,  7,  0,  7,
                          15, 7,  15, 7,
                          CLUT4_FIELD, TEX4_TPAGE);
    rasterFlushPrimitive();
}

static void drawQFS8(void) {
    rasterReset();
    rasterFillRect(0, 0, 48, 16, RASTER_VRAM_RED);
    setTexpage(TEX8_TX, TEX8_TY, 1);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuadSemi(TEX_MOD_NEUTRAL,
                          0,  0,  0,  0,
                          31, 0,  31, 0,
                          0,  7,  0,  7,
                          31, 7,  31, 7,
                          CLUT8_FIELD, TEX8_TPAGE);
    rasterFlushPrimitive();
}

// ---- Degenerate quad: v3 coincident with v2 ------------------------------
//
// Effective triangle. The 4-vert path should produce identical pixels
// to a 3-vert path drawn with the first three vertices.

static void drawQFDeg(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 16);
    setTexpage(TEX4_TX, TEX4_TY, 0);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      0,  0,  0, 0,
                      15, 0,  15, 0,
                      0,  7,  0, 7,
                      0,  7,  0, 7,   /* v3 == v2 */
                      CLUT4_FIELD, TEX4_TPAGE);
    rasterFlushPrimitive();
}

// Reference 3-vert path matching QFDeg's first three vertices.
static void drawQFDegRef(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 16);
    setTexpage(TEX4_TX, TEX4_TY, 0);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 0,  0,  0, 0,
                 15, 0,  15, 0,
                 0,  7,  0, 7,
                 CLUT4_FIELD, TEX4_TPAGE);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// ============================================================================
// QFA4: axis-aligned 16x8 4-bit quad
// ============================================================================

CESTER_TEST(qfa4_corner_0_0, gpu_raster_phase8,
    drawQFA4();
    /* (0,0) samples texel u=0 -> CLUT4[0]. */
    ASSERT_PIXEL_EQ(QFA4_0_0, 0, 0);
)
CESTER_TEST(qfa4_corner_14_0, gpu_raster_phase8,
    drawQFA4();
    /* (14,0) samples texel u=14 -> CLUT4[14]. */
    ASSERT_PIXEL_EQ(QFA4_14_0, 14, 0);
)
CESTER_TEST(qfa4_corner_0_6, gpu_raster_phase8,
    drawQFA4();
    ASSERT_PIXEL_EQ(QFA4_0_6, 0, 6);
)
CESTER_TEST(qfa4_corner_14_6, gpu_raster_phase8,
    drawQFA4();
    ASSERT_PIXEL_EQ(QFA4_14_6, 14, 6);
)
CESTER_TEST(qfa4_interior_7_3, gpu_raster_phase8,
    drawQFA4();
    ASSERT_PIXEL_EQ(QFA4_7_3, 7, 3);
)
CESTER_TEST(qfa4_interior_3_5, gpu_raster_phase8,
    drawQFA4();
    ASSERT_PIXEL_EQ(QFA4_3_5, 3, 5);
)

// ============================================================================
// QFA8: axis-aligned 32x8 8-bit quad
// ============================================================================

CESTER_TEST(qfa8_corner_0_0, gpu_raster_phase8,
    drawQFA8();
    ASSERT_PIXEL_EQ(QFA8_0_0, 0, 0);
)
CESTER_TEST(qfa8_corner_30_0, gpu_raster_phase8,
    drawQFA8();
    ASSERT_PIXEL_EQ(QFA8_30_0, 30, 0);
)
CESTER_TEST(qfa8_corner_0_6, gpu_raster_phase8,
    drawQFA8();
    ASSERT_PIXEL_EQ(QFA8_0_6, 0, 6);
)
CESTER_TEST(qfa8_corner_30_6, gpu_raster_phase8,
    drawQFA8();
    ASSERT_PIXEL_EQ(QFA8_30_6, 30, 6);
)
CESTER_TEST(qfa8_interior_15_3, gpu_raster_phase8,
    drawQFA8();
    ASSERT_PIXEL_EQ(QFA8_15_3, 15, 3);
)
CESTER_TEST(qfa8_interior_22_5, gpu_raster_phase8,
    drawQFA8();
    ASSERT_PIXEL_EQ(QFA8_22_5, 22, 5);
)

// ============================================================================
// QFA15: axis-aligned 16x8 15-bit quad
// ============================================================================

CESTER_TEST(qfa15_corner_0_0, gpu_raster_phase8,
    drawQFA15();
    ASSERT_PIXEL_EQ(QFA15_0_0, 0, 0);
)
CESTER_TEST(qfa15_corner_14_0, gpu_raster_phase8,
    drawQFA15();
    ASSERT_PIXEL_EQ(QFA15_14_0, 14, 0);
)
CESTER_TEST(qfa15_corner_0_6, gpu_raster_phase8,
    drawQFA15();
    ASSERT_PIXEL_EQ(QFA15_0_6, 0, 6);
)
CESTER_TEST(qfa15_corner_14_6, gpu_raster_phase8,
    drawQFA15();
    ASSERT_PIXEL_EQ(QFA15_14_6, 14, 6);
)
CESTER_TEST(qfa15_interior_7_3, gpu_raster_phase8,
    drawQFA15();
    ASSERT_PIXEL_EQ(QFA15_7_3, 7, 3);
)
CESTER_TEST(qfa15_interior_3_5, gpu_raster_phase8,
    drawQFA15();
    ASSERT_PIXEL_EQ(QFA15_3_5, 3, 5);
)

// ============================================================================
// QFD4: parallelogram-skewed 4-bit quad. UV per pixel depends on the
// per-row interpolation across the slanted edges - non-trivial.
// ============================================================================

CESTER_TEST(qfd4_top_0_0, gpu_raster_phase8,
    drawQFD4();
    ASSERT_PIXEL_EQ(QFD4_0_0, 0, 0);
)
CESTER_TEST(qfd4_top_8_0, gpu_raster_phase8,
    drawQFD4();
    ASSERT_PIXEL_EQ(QFD4_8_0, 8, 0);
)
CESTER_TEST(qfd4_mid_4_3, gpu_raster_phase8,
    drawQFD4();
    /* Mid-row interior. */
    ASSERT_PIXEL_EQ(QFD4_4_3, 4, 3);
)
CESTER_TEST(qfd4_mid_10_3, gpu_raster_phase8,
    drawQFD4();
    ASSERT_PIXEL_EQ(QFD4_10_3, 10, 3);
)
CESTER_TEST(qfd4_bottom_4_6, gpu_raster_phase8,
    drawQFD4();
    ASSERT_PIXEL_EQ(QFD4_4_6, 4, 6);
)
CESTER_TEST(qfd4_bottom_14_6, gpu_raster_phase8,
    drawQFD4();
    ASSERT_PIXEL_EQ(QFD4_14_6, 14, 6);
)

/* Per-row UV drift probes for QFD4 parallelogram. The left edge slope
   is 4/7 per row, so frac(leftX) cycles 0/0.57/0.14/0.71/0.29/0.86/0.43.
   Predicted: rows where frac(leftX) lands in (0, 0.5] sample U one LSB
   higher than rows where it lands in (0.5, 1) - the half-pixel-bias is
   what the inner loop's posX init currently elides. */
CESTER_TEST(qfd4_row1_4, gpu_raster_phase8,
    drawQFD4();
    ASSERT_PIXEL_EQ(QFD4_4_1, 4, 1);
)
CESTER_TEST(qfd4_row1_10, gpu_raster_phase8,
    drawQFD4();
    ASSERT_PIXEL_EQ(QFD4_10_1, 10, 1);
)
CESTER_TEST(qfd4_row2_4, gpu_raster_phase8,
    drawQFD4();
    ASSERT_PIXEL_EQ(QFD4_4_2, 4, 2);
)
CESTER_TEST(qfd4_row2_10, gpu_raster_phase8,
    drawQFD4();
    ASSERT_PIXEL_EQ(QFD4_10_2, 10, 2);
)
CESTER_TEST(qfd4_row4_4, gpu_raster_phase8,
    drawQFD4();
    ASSERT_PIXEL_EQ(QFD4_4_4, 4, 4);
)
CESTER_TEST(qfd4_row4_10, gpu_raster_phase8,
    drawQFD4();
    ASSERT_PIXEL_EQ(QFD4_10_4, 10, 4);
)
CESTER_TEST(qfd4_row5_4, gpu_raster_phase8,
    drawQFD4();
    ASSERT_PIXEL_EQ(QFD4_4_5, 4, 5);
)
CESTER_TEST(qfd4_row5_10, gpu_raster_phase8,
    drawQFD4();
    ASSERT_PIXEL_EQ(QFD4_10_5, 10, 5);
)

// ============================================================================
// QFD15: parallelogram-skewed 15-bit quad
// ============================================================================

CESTER_TEST(qfd15_top_0_0, gpu_raster_phase8,
    drawQFD15();
    ASSERT_PIXEL_EQ(QFD15_0_0, 0, 0);
)
CESTER_TEST(qfd15_top_8_0, gpu_raster_phase8,
    drawQFD15();
    ASSERT_PIXEL_EQ(QFD15_8_0, 8, 0);
)
CESTER_TEST(qfd15_mid_4_3, gpu_raster_phase8,
    drawQFD15();
    ASSERT_PIXEL_EQ(QFD15_4_3, 4, 3);
)
CESTER_TEST(qfd15_mid_10_3, gpu_raster_phase8,
    drawQFD15();
    ASSERT_PIXEL_EQ(QFD15_10_3, 10, 3);
)
CESTER_TEST(qfd15_bottom_4_6, gpu_raster_phase8,
    drawQFD15();
    ASSERT_PIXEL_EQ(QFD15_4_6, 4, 6);
)
CESTER_TEST(qfd15_bottom_14_6, gpu_raster_phase8,
    drawQFD15();
    ASSERT_PIXEL_EQ(QFD15_14_6, 14, 6);
)

/* Direct-15 mirror of the QFD4 per-row UV drift probes. Same geometry,
   same per-row leftX slope, but 15-bit direct texel lookup so the U and
   V values are both observable in the returned color word. */
CESTER_TEST(qfd15_row1_4, gpu_raster_phase8,
    drawQFD15();
    ASSERT_PIXEL_EQ(QFD15_4_1, 4, 1);
)
CESTER_TEST(qfd15_row1_10, gpu_raster_phase8,
    drawQFD15();
    ASSERT_PIXEL_EQ(QFD15_10_1, 10, 1);
)
CESTER_TEST(qfd15_row2_4, gpu_raster_phase8,
    drawQFD15();
    ASSERT_PIXEL_EQ(QFD15_4_2, 4, 2);
)
CESTER_TEST(qfd15_row2_10, gpu_raster_phase8,
    drawQFD15();
    ASSERT_PIXEL_EQ(QFD15_10_2, 10, 2);
)
CESTER_TEST(qfd15_row4_4, gpu_raster_phase8,
    drawQFD15();
    ASSERT_PIXEL_EQ(QFD15_4_4, 4, 4);
)
CESTER_TEST(qfd15_row4_10, gpu_raster_phase8,
    drawQFD15();
    ASSERT_PIXEL_EQ(QFD15_10_4, 10, 4);
)
CESTER_TEST(qfd15_row5_4, gpu_raster_phase8,
    drawQFD15();
    ASSERT_PIXEL_EQ(QFD15_4_5, 4, 5);
)
CESTER_TEST(qfd15_row5_10, gpu_raster_phase8,
    drawQFD15();
    ASSERT_PIXEL_EQ(QFD15_10_5, 10, 5);
)

// ============================================================================
// QFO4: 5x4 odd-width-row quad. Terminal pixel of each row reveals
//       the audit-finding-#8 sampler behavior on real hardware.
// ============================================================================

CESTER_TEST(qfo4_terminal_4_0, gpu_raster_phase8,
    drawQFO4();
    /* Top-row terminal pixel. */
    ASSERT_PIXEL_EQ(QFO4_TERMINAL_4_0, 4, 0);
)
CESTER_TEST(qfo4_terminal_4_1, gpu_raster_phase8,
    drawQFO4();
    ASSERT_PIXEL_EQ(QFO4_TERMINAL_4_1, 4, 1);
)
CESTER_TEST(qfo4_terminal_4_2, gpu_raster_phase8,
    drawQFO4();
    ASSERT_PIXEL_EQ(QFO4_TERMINAL_4_2, 4, 2);
)
CESTER_TEST(qfo4_interior_2_1, gpu_raster_phase8,
    drawQFO4();
    /* Non-terminal interior - paired loop covers it. */
    ASSERT_PIXEL_EQ(QFO4_INTERIOR_2_1, 2, 1);
)
CESTER_TEST(qfo4_interior_3_2, gpu_raster_phase8,
    drawQFO4();
    ASSERT_PIXEL_EQ(QFO4_INTERIOR_3_2, 3, 2);
)

// ============================================================================
// QFO8: 5x4 8-bit odd-width
// ============================================================================

CESTER_TEST(qfo8_terminal_4_0, gpu_raster_phase8,
    drawQFO8();
    ASSERT_PIXEL_EQ(QFO8_TERMINAL_4_0, 4, 0);
)
CESTER_TEST(qfo8_terminal_4_1, gpu_raster_phase8,
    drawQFO8();
    ASSERT_PIXEL_EQ(QFO8_TERMINAL_4_1, 4, 1);
)
CESTER_TEST(qfo8_terminal_4_2, gpu_raster_phase8,
    drawQFO8();
    ASSERT_PIXEL_EQ(QFO8_TERMINAL_4_2, 4, 2);
)
CESTER_TEST(qfo8_interior_2_1, gpu_raster_phase8,
    drawQFO8();
    ASSERT_PIXEL_EQ(QFO8_INTERIOR_2_1, 2, 1);
)

// ============================================================================
// QFO15: 5x4 15-bit odd-width
// ============================================================================

CESTER_TEST(qfo15_terminal_4_0, gpu_raster_phase8,
    drawQFO15();
    ASSERT_PIXEL_EQ(QFO15_TERMINAL_4_0, 4, 0);
)
CESTER_TEST(qfo15_terminal_4_1, gpu_raster_phase8,
    drawQFO15();
    ASSERT_PIXEL_EQ(QFO15_TERMINAL_4_1, 4, 1);
)
CESTER_TEST(qfo15_terminal_4_2, gpu_raster_phase8,
    drawQFO15();
    ASSERT_PIXEL_EQ(QFO15_TERMINAL_4_2, 4, 2);
)
CESTER_TEST(qfo15_interior_2_1, gpu_raster_phase8,
    drawQFO15();
    ASSERT_PIXEL_EQ(QFO15_INTERIOR_2_1, 2, 1);
)

// ============================================================================
// QFS4: semi-trans 4-bit quad (drawPoly4TEx4_S path)
// Pre-fill background is VRAM red (0x001f).
// ============================================================================

CESTER_TEST(qfs4_corner_0_0, gpu_raster_phase8,
    drawQFS4();
    ASSERT_PIXEL_EQ(QFS4_0_0, 0, 0);
)
CESTER_TEST(qfs4_interior_7_3, gpu_raster_phase8,
    drawQFS4();
    ASSERT_PIXEL_EQ(QFS4_7_3, 7, 3);
)
CESTER_TEST(qfs4_corner_14_6, gpu_raster_phase8,
    drawQFS4();
    ASSERT_PIXEL_EQ(QFS4_14_6, 14, 6);
)

// ============================================================================
// QFS8: semi-trans 8-bit quad (drawPoly4TEx8_S path)
// ============================================================================

CESTER_TEST(qfs8_corner_0_0, gpu_raster_phase8,
    drawQFS8();
    ASSERT_PIXEL_EQ(QFS8_0_0, 0, 0);
)
CESTER_TEST(qfs8_interior_15_3, gpu_raster_phase8,
    drawQFS8();
    ASSERT_PIXEL_EQ(QFS8_15_3, 15, 3);
)
CESTER_TEST(qfs8_corner_30_6, gpu_raster_phase8,
    drawQFS8();
    ASSERT_PIXEL_EQ(QFS8_30_6, 30, 6);
)

// ============================================================================
// QFDeg: degenerate quad collapses to triangle. Compare against the
// 3-vert reference draw via ASSERT_PIXEL_EQ on captured oracle values.
// ============================================================================

CESTER_TEST(qfdeg_0_0, gpu_raster_phase8,
    drawQFDeg();
    ASSERT_PIXEL_EQ(QFDEG_0_0, 0, 0);
)
CESTER_TEST(qfdeg_7_3, gpu_raster_phase8,
    drawQFDeg();
    ASSERT_PIXEL_EQ(QFDEG_7_3, 7, 3);
)
CESTER_TEST(qfdeg_3_5, gpu_raster_phase8,
    drawQFDeg();
    ASSERT_PIXEL_EQ(QFDEG_3_5, 3, 5);
)

CESTER_TEST(qfdeg_ref_0_0, gpu_raster_phase8,
    drawQFDegRef();
    /* Same oracle value - 3-vert reference should match the
       degenerate-quad output at every interior pixel. */
    ASSERT_PIXEL_EQ(QFDEG_REF_0_0, 0, 0);
)
CESTER_TEST(qfdeg_ref_7_3, gpu_raster_phase8,
    drawQFDegRef();
    ASSERT_PIXEL_EQ(QFDEG_REF_7_3, 7, 3);
)
CESTER_TEST(qfdeg_ref_3_5, gpu_raster_phase8,
    drawQFDegRef();
    ASSERT_PIXEL_EQ(QFDEG_REF_3_5, 3, 5);
)
