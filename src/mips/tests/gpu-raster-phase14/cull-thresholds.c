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

// Cull-threshold probes. Naming:
//   CT_<prim>_OK_<dim>     -- primitive rendered as expected
//   CT_<prim>_DROP_<dim>   -- primitive culled, anchor reads sentinel
//   CT_<prim>_DROPMECH_*   -- silent-drop verification

CESTER_BODY(

// Probe-anchor pixel for all tests: (5, 3). The 32x32 sentinel-fill
// region is plenty large for this anchor.
#define ANCHOR_X 5
#define ANCHOR_Y 3

// ---- Flat untextured triangle (GP0 0x20) ---------------------------------

static void drawTriOk(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    /* In-limit: dx max = 100, dy max = 20. Anchor (5, 3) covered. */
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 100, 0, 0, 20);
    rasterFlushPrimitive();
}

static void drawTriEdgeDx(int16_t dx) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    /* dx = v2.x - v1.x = dx. v1-v3 dx = 0. Worst-edge dx = `dx`. */
    rasterFlatTri(RASTER_CMD_RED, 0, 0, (int16_t)dx, 0, 0, 20);
    rasterFlushPrimitive();
}

static void drawTriEdgeDy(int16_t dy) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    /* dy = v3.y - v1.y = dy. Worst-edge dy = `dy`. */
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 20, 0, 0, (int16_t)dy);
    rasterFlushPrimitive();
}

// ---- Gouraud triangle (GP0 0x30) -----------------------------------------

static void drawGTriOk(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    rasterGouraudTri(RASTER_CMD_RED, 0, 0,
                     RASTER_CMD_RED, 100, 0,
                     RASTER_CMD_RED, 0, 20);
    rasterFlushPrimitive();
}

static void drawGTriEdgeDx(int16_t dx) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    rasterGouraudTri(RASTER_CMD_RED, 0, 0,
                     RASTER_CMD_RED, dx, 0,
                     RASTER_CMD_RED, 0, 20);
    rasterFlushPrimitive();
}

// ---- Flat textured triangle (GP0 0x24) -----------------------------------

static void drawTexTriOk(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    setTexpage(TEX15_TX, TEX15_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 0, 0,    0, 0,
                 100, 0,  15, 0,
                 0, 20,   0, 15,
                 CLUT15_FIELD, TEX15_TPAGE);
    rasterFlushPrimitive();
}

static void drawTexTriEdgeDx(int16_t dx) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    setTexpage(TEX15_TX, TEX15_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterTexTri(TEX_MOD_NEUTRAL,
                 0, 0,    0, 0,
                 dx, 0,   15, 0,
                 0, 20,   0, 15,
                 CLUT15_FIELD, TEX15_TPAGE);
    rasterFlushPrimitive();
}

// ---- Flat untextured quad (GP0 0x28) -------------------------------------

static void drawQuadOk(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    rasterFlatQuad(RASTER_CMD_GREEN, 0, 0, 100, 0, 0, 20, 100, 20);
    rasterFlushPrimitive();
}

static void drawQuadEdgeDx(int16_t dx) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    /* Largest edge dx = `dx`. */
    rasterFlatQuad(RASTER_CMD_GREEN, 0, 0, dx, 0, 0, 20, dx, 20);
    rasterFlushPrimitive();
}

static void drawQuadEdgeDy(int16_t dy) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    rasterFlatQuad(RASTER_CMD_GREEN, 0, 0, 20, 0, 0, dy, 20, dy);
    rasterFlushPrimitive();
}

// ---- Flat textured quad (GP0 0x2C) ---------------------------------------

static void drawTexQuadOk(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    setTexpage(TEX15_TX, TEX15_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      0, 0,    0, 0,
                      100, 0,  15, 0,
                      0, 20,   0, 15,
                      100, 20, 15, 15,
                      CLUT15_FIELD, TEX15_TPAGE);
    rasterFlushPrimitive();
}

static void drawTexQuadEdgeDx(int16_t dx) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    setTexpage(TEX15_TX, TEX15_TY, 2);
    setTextureWindow(0, 0, 0, 0);
    rasterFlatTexQuad(TEX_MOD_NEUTRAL,
                      0, 0,    0, 0,
                      dx, 0,   15, 0,
                      0, 20,   0, 15,
                      dx, 20,  15, 15,
                      CLUT15_FIELD, TEX15_TPAGE);
    rasterFlushPrimitive();
}

// ---- Line (GP0 0x40) -----------------------------------------------------

static void drawLineEdgeDx(int16_t dx) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    /* Line at y=ANCHOR_Y crossing x=ANCHOR_X if dx is large enough.
       Line endpoint at (dx, 3) - if line drops, anchor is sentinel. */
    rasterFlatLine(RASTER_CMD_BLUE, 0, 3, dx, 3);
    rasterFlushPrimitive();
}

// ---- Variable-size rect (GP0 0x60) ---------------------------------------

static void drawRectSize(int16_t w, int16_t h) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    rasterFlatRect(RASTER_CMD_WHITE, 0, 0, w, h);
    rasterFlushPrimitive();
}

// ---- Drop-mechanism probe ------------------------------------------------
//
// Submit an oversized triangle (suspected to drop) followed by a
// known-good small triangle at a clearly different anchor (10, 10).
// If hardware silently drops the first and proceeds with the second,
// pixel (10, 10) reads RASTER_VRAM_GREEN. If the drop corrupts the
// command stream, pixel (10, 10) reads sentinel.

static void drawDropMechProbe(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    /* Oversized tri (dx=2047 - way over limit). */
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 2047, 0, 0, 20);
    /* Small good tri whose interior includes (10, 10). */
    rasterFlatTri(RASTER_CMD_GREEN, 8, 8, 14, 8, 8, 14);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// ============================================================================
// Baseline + threshold tests per primitive type
// ============================================================================

// ---- Triangle (GP0 0x20) ----

CESTER_TEST(ct_tri_baseline, gpu_raster_phase14,
    drawTriOk();
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_tri_dx_1023_ok, gpu_raster_phase14,
    drawTriEdgeDx(1023);
    /* In-limit per psx-spx. Should render. */
    ASSERT_PIXEL_EQ(CT_TRI_DX_1023, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_tri_dx_1024_drop, gpu_raster_phase14,
    drawTriEdgeDx(1024);
    /* Suspected drop boundary. */
    ASSERT_PIXEL_EQ(CT_TRI_DX_1024, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_tri_dx_1025_drop, gpu_raster_phase14,
    drawTriEdgeDx(1025);
    ASSERT_PIXEL_EQ(CT_TRI_DX_1025, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_tri_dx_2047_drop, gpu_raster_phase14,
    drawTriEdgeDx(2047);
    /* Way over limit. */
    ASSERT_PIXEL_EQ(CT_TRI_DX_2047, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_tri_dy_511_ok, gpu_raster_phase14,
    drawTriEdgeDy(511);
    ASSERT_PIXEL_EQ(CT_TRI_DY_511, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_tri_dy_512_drop, gpu_raster_phase14,
    drawTriEdgeDy(512);
    ASSERT_PIXEL_EQ(CT_TRI_DY_512, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_tri_dy_513_drop, gpu_raster_phase14,
    drawTriEdgeDy(513);
    ASSERT_PIXEL_EQ(CT_TRI_DY_513, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_tri_dy_1023_drop, gpu_raster_phase14,
    drawTriEdgeDy(1023);
    ASSERT_PIXEL_EQ(CT_TRI_DY_1023, ANCHOR_X, ANCHOR_Y);
)

// ---- Gouraud triangle (GP0 0x30) ----

CESTER_TEST(ct_gtri_baseline, gpu_raster_phase14,
    drawGTriOk();
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_gtri_dx_1023_ok, gpu_raster_phase14,
    drawGTriEdgeDx(1023);
    ASSERT_PIXEL_EQ(CT_GTRI_DX_1023, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_gtri_dx_1024_drop, gpu_raster_phase14,
    drawGTriEdgeDx(1024);
    ASSERT_PIXEL_EQ(CT_GTRI_DX_1024, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_gtri_dx_2047_drop, gpu_raster_phase14,
    drawGTriEdgeDx(2047);
    ASSERT_PIXEL_EQ(CT_GTRI_DX_2047, ANCHOR_X, ANCHOR_Y);
)

// ---- Textured triangle (GP0 0x24) ----

CESTER_TEST(ct_textri_baseline, gpu_raster_phase14,
    drawTexTriOk();
    /* Anchor (5, 3) samples texel u=15*5/100=0 (UV interpolation,
       roughly). Just verify it's NOT sentinel. */
    int16_t v = (int16_t)rasterReadPixel(ANCHOR_X, ANCHOR_Y);
    ramsyscall_printf("OBS x=%d y=%d val=0x%04x expect=NOT-SENTINEL\n",
                      ANCHOR_X, ANCHOR_Y, (unsigned)v);
    cester_assert_uint_ne((unsigned)RASTER_SENTINEL, (unsigned)v);
)

CESTER_TEST(ct_textri_dx_1023_ok, gpu_raster_phase14,
    drawTexTriEdgeDx(1023);
    int16_t v = (int16_t)rasterReadPixel(ANCHOR_X, ANCHOR_Y);
    ramsyscall_printf("OBS x=%d y=%d val=0x%04x expect=CT_TEXTRI_DX_1023\n",
                      ANCHOR_X, ANCHOR_Y, (unsigned)v);
    cester_assert_uint_eq((unsigned)CT_TEXTRI_DX_1023, (unsigned)v);
)

CESTER_TEST(ct_textri_dx_1024_drop, gpu_raster_phase14,
    drawTexTriEdgeDx(1024);
    ASSERT_PIXEL_EQ(CT_TEXTRI_DX_1024, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_textri_dx_2047_drop, gpu_raster_phase14,
    drawTexTriEdgeDx(2047);
    ASSERT_PIXEL_EQ(CT_TEXTRI_DX_2047, ANCHOR_X, ANCHOR_Y);
)

// ---- Quad (GP0 0x28) ----

CESTER_TEST(ct_quad_baseline, gpu_raster_phase14,
    drawQuadOk();
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_quad_dx_1023_ok, gpu_raster_phase14,
    drawQuadEdgeDx(1023);
    ASSERT_PIXEL_EQ(CT_QUAD_DX_1023, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_quad_dx_1024_drop, gpu_raster_phase14,
    drawQuadEdgeDx(1024);
    ASSERT_PIXEL_EQ(CT_QUAD_DX_1024, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_quad_dx_2047_drop, gpu_raster_phase14,
    drawQuadEdgeDx(2047);
    ASSERT_PIXEL_EQ(CT_QUAD_DX_2047, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_quad_dy_511_ok, gpu_raster_phase14,
    drawQuadEdgeDy(511);
    ASSERT_PIXEL_EQ(CT_QUAD_DY_511, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_quad_dy_512_drop, gpu_raster_phase14,
    drawQuadEdgeDy(512);
    ASSERT_PIXEL_EQ(CT_QUAD_DY_512, ANCHOR_X, ANCHOR_Y);
)

// ---- Textured quad (GP0 0x2C) ----

CESTER_TEST(ct_texquad_baseline, gpu_raster_phase14,
    drawTexQuadOk();
    int16_t v = (int16_t)rasterReadPixel(ANCHOR_X, ANCHOR_Y);
    ramsyscall_printf("OBS x=%d y=%d val=0x%04x expect=NOT-SENTINEL\n",
                      ANCHOR_X, ANCHOR_Y, (unsigned)v);
    cester_assert_uint_ne((unsigned)RASTER_SENTINEL, (unsigned)v);
)

CESTER_TEST(ct_texquad_dx_1023_ok, gpu_raster_phase14,
    drawTexQuadEdgeDx(1023);
    int16_t v = (int16_t)rasterReadPixel(ANCHOR_X, ANCHOR_Y);
    ramsyscall_printf("OBS x=%d y=%d val=0x%04x expect=CT_TEXQUAD_DX_1023\n",
                      ANCHOR_X, ANCHOR_Y, (unsigned)v);
    cester_assert_uint_eq((unsigned)CT_TEXQUAD_DX_1023, (unsigned)v);
)

CESTER_TEST(ct_texquad_dx_1024_drop, gpu_raster_phase14,
    drawTexQuadEdgeDx(1024);
    ASSERT_PIXEL_EQ(CT_TEXQUAD_DX_1024, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_texquad_dx_2047_drop, gpu_raster_phase14,
    drawTexQuadEdgeDx(2047);
    ASSERT_PIXEL_EQ(CT_TEXQUAD_DX_2047, ANCHOR_X, ANCHOR_Y);
)

// ---- Line (GP0 0x40) ----
//
// Lines don't really have "edges" in the polygon sense; the cull
// concept is about the endpoint delta. Per psx-spx GPU registers the
// line endpoint delta is limited to ±1023 horizontally / ±511
// vertically; oversized lines are dropped.

CESTER_TEST(ct_line_dx_100_baseline, gpu_raster_phase14,
    drawLineEdgeDx(100);
    /* Line should render through (5, 3). */
    ASSERT_PIXEL_EQ(RASTER_VRAM_BLUE, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_line_dx_1023_ok, gpu_raster_phase14,
    drawLineEdgeDx(1023);
    ASSERT_PIXEL_EQ(CT_LINE_DX_1023, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_line_dx_1024_drop, gpu_raster_phase14,
    drawLineEdgeDx(1024);
    ASSERT_PIXEL_EQ(CT_LINE_DX_1024, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_line_dx_2047_drop, gpu_raster_phase14,
    drawLineEdgeDx(2047);
    ASSERT_PIXEL_EQ(CT_LINE_DX_2047, ANCHOR_X, ANCHOR_Y);
)

// ---- Variable-size rect (GP0 0x60) ----
//
// Rectangles have their own "size" command word. psx-spx documents
// the rectangle width as masked to ((W-1) & 0x3FF) + 1 = max 1024.
// So w=1024 wraps to 0 (no draw); w=1025 wraps to 1; etc. Verify.

CESTER_TEST(ct_rect_w16_baseline, gpu_raster_phase14,
    drawRectSize(16, 16);
    ASSERT_PIXEL_EQ(RASTER_VRAM_WHITE, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_rect_w1023, gpu_raster_phase14,
    drawRectSize(1023, 16);
    /* Hardware should fill - 1023 within mask range. */
    ASSERT_PIXEL_EQ(CT_RECT_W_1023, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_rect_w1024, gpu_raster_phase14,
    drawRectSize(1024, 16);
    /* psx-spx: ((1024-1)&0x3FF)+1 = 1024. Renders. */
    ASSERT_PIXEL_EQ(CT_RECT_W_1024, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_rect_w1025, gpu_raster_phase14,
    drawRectSize(1025, 16);
    /* ((1025-1)&0x3FF)+1 = 1. Renders only 1 pixel wide; anchor
       (5, 3) is outside that single-column rect -> sentinel. */
    ASSERT_PIXEL_EQ(CT_RECT_W_1025, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_rect_h511, gpu_raster_phase14,
    drawRectSize(16, 511);
    ASSERT_PIXEL_EQ(CT_RECT_H_511, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_rect_h512, gpu_raster_phase14,
    drawRectSize(16, 512);
    /* ((512-1)&0x1FF)+1 = 512. Renders. */
    ASSERT_PIXEL_EQ(CT_RECT_H_512, ANCHOR_X, ANCHOR_Y);
)

CESTER_TEST(ct_rect_h513, gpu_raster_phase14,
    drawRectSize(16, 513);
    /* ((513-1)&0x1FF)+1 = 1. Wraps to height 1; anchor (5, 3) is
       outside the single-row rect -> sentinel. */
    ASSERT_PIXEL_EQ(CT_RECT_H_513, ANCHOR_X, ANCHOR_Y);
)

// ---- Drop-mechanism probe ----

CESTER_TEST(ct_drop_mech_second_renders, gpu_raster_phase14,
    drawDropMechProbe();
    /* If the oversized first tri was silently dropped, the second
       tri rendered and pixel (10, 10) is green. If the drop
       corrupted the command stream, (10, 10) reads sentinel. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 10, 10);
)

CESTER_TEST(ct_drop_mech_oversized_not_rendered, gpu_raster_phase14,
    drawDropMechProbe();
    /* The first oversized tri at (0, 0)-(2047, 0)-(0, 20) was
       dropped. Anchor (5, 3) - inside that tri's intended bounds
       but outside the second tri's bounds - should be sentinel. */
    ASSERT_PIXEL_UNTOUCHED(ANCHOR_X, ANCHOR_Y);
)

// ---- Per-vertex absolute coordinate test ----
//
// Triangle with one vertex at a high absolute X but small edge dx
// between the other two vertices. Per-edge rule predicts render;
// per-vertex-abs rule predicts drop.

CESTER_TEST(ct_tri_vertex_abs_just_low_edges, gpu_raster_phase14,
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    /* v1 = (0, 0), v2 = (1024, 0), v3 = (1024, 20). Edges:
       v1-v2 dx=1024 (over limit if dx>1023).
       v2-v3 dx=0.
       v1-v3 dx=1024 (over limit).
       So this test triangle has TWO edges over - it's a control
       confirming over-limit cull, not strictly a per-vertex-abs
       isolation. */
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 1024, 0, 1024, 20);
    rasterFlushPrimitive();
    ASSERT_PIXEL_EQ(CT_TRI_VERTEX_ABS_OVER, ANCHOR_X, ANCHOR_Y);
)

/* Pre-truncation per-vertex absolute coord probes. The GP0 vertex
   format stores x/y as int16 but the rasterizer interprets only the
   low 11 bits as signed. We can test whether hardware enforces an
   independent per-vertex absolute-coord rule BEFORE the 11-bit
   truncation by sending the same effective post-truncation triangle
   in two ways: one with all coords in the 11-bit range, one with a
   vertex coord that has bits set above bit 10 but produces the same
   low-11-bit result. If both render identically, no pre-truncation
   rule. If the probe drops (sentinel at anchor), there IS one.
   Baseline geometry: (0,0)-(20,0)-(0,20). Anchor (5,3) is inside
   the post-truncation triangle in both cases. */
CESTER_TEST(ct_tri_pretrunc_baseline, gpu_raster_phase14,
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    /* All low-11-bit vertices; should render at anchor. */
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 20, 0, 0, 20);
    rasterFlushPrimitive();
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, ANCHOR_X, ANCHOR_Y);
)
CESTER_TEST(ct_tri_pretrunc_bit11, gpu_raster_phase14,
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    /* Same effective triangle - v2.x = 2068 = 0x814 truncates to
       low 11 bits = 0x14 = 20. If hardware truncates first then
       checks per-edge, this renders identically to the baseline.
       If a pre-truncation per-vertex absolute rule fires on |x| >
       1023, the polygon drops and anchor is sentinel. */
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 2068, 0, 0, 20);
    rasterFlushPrimitive();
    ASSERT_PIXEL_EQ(CT_TRI_PRETRUNC_BIT11, ANCHOR_X, ANCHOR_Y);
)
CESTER_TEST(ct_tri_pretrunc_bit15, gpu_raster_phase14,
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 32);
    /* v2.x = -32748 = 0x8014 in 16-bit two's complement. Low 11
       bits = 0x014 = 20. Maximum bit-pattern divergence from the
       11-bit truncated value: every high bit set. If any per-vertex
       rule fires above 11-bit range, this drops. */
    rasterFlatTri(RASTER_CMD_RED, 0, 0, (int16_t)0x8014, 0, 0, 20);
    rasterFlushPrimitive();
    ASSERT_PIXEL_EQ(CT_TRI_PRETRUNC_BIT15, ANCHOR_X, ANCHOR_Y);
)
