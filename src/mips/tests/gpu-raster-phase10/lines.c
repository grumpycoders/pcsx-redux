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

// Exhaustive line probes. Naming convention:
//   LS_<oct>  flat shallow line in octant <oct> (1..8)
//   LT_<oct>  flat steep line in octant <oct>
//   LR_<axis> reverse-direction (right-to-left or bottom-to-top)
//   LC_<dir>  clipped at draw-area edge
//   LZ_<n>   zero-length at position n
//   LG       gouraud line
//   LP       polyline 3-vertex
//   LST      semi-trans line
//
// Octant numbering (standard):
//   1: dx > 0, dy > 0, |dx| > |dy| (shallow down-right)
//   2: dx > 0, dy > 0, |dy| > |dx| (steep down-right)
//   3: dx < 0, dy > 0, |dy| > |dx| (steep down-left)
//   4: dx < 0, dy > 0, |dx| > |dy| (shallow down-left)
//   5: dx < 0, dy < 0, |dx| > |dy| (shallow up-left)
//   6: dx < 0, dy < 0, |dy| > |dx| (steep up-left)
//   7: dx > 0, dy < 0, |dy| > |dx| (steep up-right)
//   8: dx > 0, dy < 0, |dx| > |dy| (shallow up-right)
//
// Phase-2 already covered octant 1 (lineShallow) and the D45/DN45 axis
// boundaries. Phase-10 fills 2-8 plus polylines / gouraud / semi-trans.

CESTER_BODY(

// Octant 2: steep down-right (dx>0, dy>0, dy > dx). (0,0) -> (3, 10).
static void drawLS_oct2(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatLine(RASTER_CMD_RED, 0, 0, 3, 10);
    rasterFlushPrimitive();
}

// Octant 3: steep down-left (dx<0, dy>0, dy > |dx|). (10,0) -> (7, 10).
static void drawLS_oct3(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatLine(RASTER_CMD_GREEN, 10, 0, 7, 10);
    rasterFlushPrimitive();
}

// Octant 4: shallow down-left. (10, 0) -> (0, 3).
static void drawLS_oct4(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 8);
    rasterFlatLine(RASTER_CMD_BLUE, 10, 0, 0, 3);
    rasterFlushPrimitive();
}

// Octant 5: shallow up-left. (10, 10) -> (0, 7).
static void drawLS_oct5(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatLine(RASTER_CMD_WHITE, 10, 10, 0, 7);
    rasterFlushPrimitive();
}

// Octant 6: steep up-left. (10, 10) -> (7, 0).
static void drawLS_oct6(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatLine(RASTER_CMD_RED, 10, 10, 7, 0);
    rasterFlushPrimitive();
}

// Octant 7: steep up-right. (0, 10) -> (3, 0).
static void drawLS_oct7(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatLine(RASTER_CMD_GREEN, 0, 10, 3, 0);
    rasterFlushPrimitive();
}

// Octant 8: shallow up-right. (0, 3) -> (10, 0).
static void drawLS_oct8(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 8);
    rasterFlatLine(RASTER_CMD_BLUE, 0, 3, 10, 0);
    rasterFlushPrimitive();
}

// Reverse-direction horizontal: (10, 5) -> (5, 5).
static void drawLR_horiz(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 8);
    rasterFlatLine(RASTER_CMD_RED, 10, 5, 5, 5);
    rasterFlushPrimitive();
}

// Reverse-direction vertical: (5, 10) -> (5, 5).
static void drawLR_vert(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 8, 16);
    rasterFlatLine(RASTER_CMD_GREEN, 5, 10, 5, 5);
    rasterFlushPrimitive();
}

// Clipped right: line extends past draw-area X (1024). Draw area is
// the default 1024x512 - so clip at X=1023 implicitly. We narrow the
// draw area to test clipping at a closer boundary.
static void drawLC_right(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 24, 8);
    setDrawingArea(0, 0, 12, 8);  /* draw-X clipped at 12 (exclusive) */
    rasterFlatLine(RASTER_CMD_WHITE, 0, 4, 20, 4);
    rasterFlushPrimitive();
    /* Restore default draw area for subsequent tests. */
    setDrawingArea(RASTER_DRAW_AREA_X1, RASTER_DRAW_AREA_Y1,
                   RASTER_DRAW_AREA_X2, RASTER_DRAW_AREA_Y2);
}

// Clipped bottom: line extends past draw-area Y.
static void drawLC_bottom(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 8, 24);
    setDrawingArea(0, 0, 8, 12);
    rasterFlatLine(RASTER_CMD_BLUE, 4, 0, 4, 20);
    rasterFlushPrimitive();
    setDrawingArea(RASTER_DRAW_AREA_X1, RASTER_DRAW_AREA_Y1,
                   RASTER_DRAW_AREA_X2, RASTER_DRAW_AREA_Y2);
}

// Zero-length lines at different positions.
static void drawLZ_at(int16_t x, int16_t y) {
    rasterReset();
    rasterClearTestRegion(0, 0, 32, 16);
    rasterFlatLine(RASTER_CMD_RED, x, y, x, y);
    rasterFlushPrimitive();
}

// Gouraud line: red -> blue over 10 pixels horizontally.
static void drawLG(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 8);
    rasterGouraudLine(RASTER_CMD_RED, 0, 5,
                      RASTER_CMD_BLUE, 10, 5);
    rasterFlushPrimitive();
}

// Polyline 3-vertex: (0, 0) -> (5, 5) -> (10, 0). Two diagonal
// segments meeting at the apex.
static void drawLP(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatPolyline3(RASTER_CMD_GREEN,
                        0,  0,
                        5,  5,
                        10, 0);
    rasterFlushPrimitive();
}

// Semi-trans line: GP0(0x42) over a red-filled background.
static void drawLST(void) {
    rasterReset();
    rasterFillRect(0, 0, 16, 8, RASTER_VRAM_RED);
    rasterFlatLineSemi(RASTER_CMD_GREEN, 0, 4, 10, 4);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// ==========================================================================
// Octant 2: steep down-right. (0, 0) -> (3, 10).
// Hardware steps Y the longer axis; X advances every ~3.33 rows.
// ==========================================================================

CESTER_TEST(ls_oct2_start, gpu_raster_phase10,
    drawLS_oct2();
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 0, 0);
)
CESTER_TEST(ls_oct2_mid_y5, gpu_raster_phase10,
    drawLS_oct2();
    /* At y=5, x ~ 0 + 5*(3/10) = 1.5 -> Bresenham picks 1 or 2. */
    ASSERT_PIXEL_EQ(LS_OCT2_Y5_X1, 1, 5);
)
CESTER_TEST(ls_oct2_mid_y5_x2, gpu_raster_phase10,
    drawLS_oct2();
    ASSERT_PIXEL_EQ(LS_OCT2_Y5_X2, 2, 5);
)
CESTER_TEST(ls_oct2_end, gpu_raster_phase10,
    drawLS_oct2();
    ASSERT_PIXEL_EQ(LS_OCT2_END, 3, 10);
)

// ==========================================================================
// Octant 3: steep down-left. (10, 0) -> (7, 10).
// ==========================================================================

CESTER_TEST(ls_oct3_start, gpu_raster_phase10,
    drawLS_oct3();
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 10, 0);
)
CESTER_TEST(ls_oct3_mid, gpu_raster_phase10,
    drawLS_oct3();
    ASSERT_PIXEL_EQ(LS_OCT3_MID, 9, 5);
)
CESTER_TEST(ls_oct3_end, gpu_raster_phase10,
    drawLS_oct3();
    ASSERT_PIXEL_EQ(LS_OCT3_END, 7, 10);
)

// ==========================================================================
// Octant 4: shallow down-left. (10, 0) -> (0, 3).
// ==========================================================================

CESTER_TEST(ls_oct4_start, gpu_raster_phase10,
    drawLS_oct4();
    ASSERT_PIXEL_EQ(RASTER_VRAM_BLUE, 10, 0);
)
CESTER_TEST(ls_oct4_mid, gpu_raster_phase10,
    drawLS_oct4();
    ASSERT_PIXEL_EQ(LS_OCT4_MID, 5, 1);
)
CESTER_TEST(ls_oct4_end, gpu_raster_phase10,
    drawLS_oct4();
    ASSERT_PIXEL_EQ(LS_OCT4_END, 0, 3);
)

// ==========================================================================
// Octant 5: shallow up-left. (10, 10) -> (0, 7).
// ==========================================================================

CESTER_TEST(ls_oct5_start, gpu_raster_phase10,
    drawLS_oct5();
    ASSERT_PIXEL_EQ(RASTER_VRAM_WHITE, 10, 10);
)
CESTER_TEST(ls_oct5_mid, gpu_raster_phase10,
    drawLS_oct5();
    ASSERT_PIXEL_EQ(LS_OCT5_MID, 5, 9);
)
CESTER_TEST(ls_oct5_end, gpu_raster_phase10,
    drawLS_oct5();
    ASSERT_PIXEL_EQ(LS_OCT5_END, 0, 7);
)

// ==========================================================================
// Octant 6: steep up-left. (10, 10) -> (7, 0).
// ==========================================================================

CESTER_TEST(ls_oct6_start, gpu_raster_phase10,
    drawLS_oct6();
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 10, 10);
)
CESTER_TEST(ls_oct6_mid, gpu_raster_phase10,
    drawLS_oct6();
    ASSERT_PIXEL_EQ(LS_OCT6_MID, 9, 5);
)
CESTER_TEST(ls_oct6_end, gpu_raster_phase10,
    drawLS_oct6();
    ASSERT_PIXEL_EQ(LS_OCT6_END, 7, 0);
)

// ==========================================================================
// Octant 7: steep up-right. (0, 10) -> (3, 0).
// ==========================================================================

CESTER_TEST(ls_oct7_start, gpu_raster_phase10,
    drawLS_oct7();
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 0, 10);
)
CESTER_TEST(ls_oct7_mid, gpu_raster_phase10,
    drawLS_oct7();
    ASSERT_PIXEL_EQ(LS_OCT7_MID, 1, 5);
)
CESTER_TEST(ls_oct7_end, gpu_raster_phase10,
    drawLS_oct7();
    ASSERT_PIXEL_EQ(LS_OCT7_END, 3, 0);
)

// ==========================================================================
// Octant 8: shallow up-right. (0, 3) -> (10, 0).
// ==========================================================================

CESTER_TEST(ls_oct8_start, gpu_raster_phase10,
    drawLS_oct8();
    ASSERT_PIXEL_EQ(RASTER_VRAM_BLUE, 0, 3);
)
CESTER_TEST(ls_oct8_mid, gpu_raster_phase10,
    drawLS_oct8();
    ASSERT_PIXEL_EQ(LS_OCT8_MID, 5, 2);
)
CESTER_TEST(ls_oct8_end, gpu_raster_phase10,
    drawLS_oct8();
    ASSERT_PIXEL_EQ(LS_OCT8_END, 10, 0);
)

// ==========================================================================
// Reverse-direction lines. Hardware should draw the same pixel set as
// the forward-direction equivalent.
// ==========================================================================

CESTER_TEST(lr_horiz_start_10_5, gpu_raster_phase10,
    drawLR_horiz();
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 10, 5);
)
CESTER_TEST(lr_horiz_end_5_5, gpu_raster_phase10,
    drawLR_horiz();
    /* End vertex of a reverse-direction line - drawn or excluded? */
    ASSERT_PIXEL_EQ(LR_HORIZ_END, 5, 5);
)
CESTER_TEST(lr_horiz_mid_7_5, gpu_raster_phase10,
    drawLR_horiz();
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 7, 5);
)

CESTER_TEST(lr_vert_start_5_10, gpu_raster_phase10,
    drawLR_vert();
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 5, 10);
)
CESTER_TEST(lr_vert_end_5_5, gpu_raster_phase10,
    drawLR_vert();
    ASSERT_PIXEL_EQ(LR_VERT_END, 5, 5);
)
CESTER_TEST(lr_vert_mid_5_7, gpu_raster_phase10,
    drawLR_vert();
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 5, 7);
)

// ==========================================================================
// Clipping at draw-area edges.
// ==========================================================================

CESTER_TEST(lc_right_inside_8, gpu_raster_phase10,
    drawLC_right();
    /* Pixel inside the clipped draw area. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_WHITE, 8, 4);
)
CESTER_TEST(lc_right_just_inside_edge_11, gpu_raster_phase10,
    drawLC_right();
    /* x=11 - last column inside draw-area (X1=12 exclusive)? */
    ASSERT_PIXEL_EQ(LC_RIGHT_JUST_INSIDE, 11, 4);
)
CESTER_TEST(lc_right_clipped_15, gpu_raster_phase10,
    drawLC_right();
    /* x=15 - past draw-area, must not be drawn. */
    ASSERT_PIXEL_UNTOUCHED(15, 4);
)

CESTER_TEST(lc_bottom_inside_8, gpu_raster_phase10,
    drawLC_bottom();
    ASSERT_PIXEL_EQ(RASTER_VRAM_BLUE, 4, 8);
)
CESTER_TEST(lc_bottom_just_inside_edge_11, gpu_raster_phase10,
    drawLC_bottom();
    ASSERT_PIXEL_EQ(LC_BOTTOM_JUST_INSIDE, 4, 11);
)
CESTER_TEST(lc_bottom_clipped_15, gpu_raster_phase10,
    drawLC_bottom();
    ASSERT_PIXEL_UNTOUCHED(4, 15);
)

// ==========================================================================
// Zero-length at different positions. Should be exactly one pixel.
// ==========================================================================

CESTER_TEST(lz_at_origin, gpu_raster_phase10,
    drawLZ_at(0, 0);
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 0, 0);
)
CESTER_TEST(lz_at_origin_neighbor, gpu_raster_phase10,
    drawLZ_at(0, 0);
    ASSERT_PIXEL_UNTOUCHED(1, 0);
)
CESTER_TEST(lz_at_5_5, gpu_raster_phase10,
    drawLZ_at(5, 5);
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 5, 5);
)
CESTER_TEST(lz_at_5_5_neighbor, gpu_raster_phase10,
    drawLZ_at(5, 5);
    ASSERT_PIXEL_UNTOUCHED(6, 5);
)

// ==========================================================================
// Gouraud line: red -> blue across 10 pixels at y=5.
// Per-pixel color interpolation along the Bresenham step.
// ==========================================================================

CESTER_TEST(lg_start_pure_red, gpu_raster_phase10,
    drawLG();
    ASSERT_PIXEL_EQ(LG_START, 0, 5);
)
CESTER_TEST(lg_mid_5, gpu_raster_phase10,
    drawLG();
    ASSERT_PIXEL_EQ(LG_MID, 5, 5);
)
CESTER_TEST(lg_end_10, gpu_raster_phase10,
    drawLG();
    ASSERT_PIXEL_EQ(LG_END, 10, 5);
)

// ==========================================================================
// Polyline: 3 vertices, 2 segments. Apex (5, 5) is shared between
// segments - must be drawn exactly once, not double-written or skipped.
// ==========================================================================

CESTER_TEST(lp_first_segment_start, gpu_raster_phase10,
    drawLP();
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 0, 0);
)
CESTER_TEST(lp_first_segment_mid, gpu_raster_phase10,
    drawLP();
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 3, 3);
)
CESTER_TEST(lp_apex, gpu_raster_phase10,
    drawLP();
    /* Shared vertex between segment 1 and segment 2. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 5, 5);
)
CESTER_TEST(lp_second_segment_mid, gpu_raster_phase10,
    drawLP();
    ASSERT_PIXEL_EQ(RASTER_VRAM_GREEN, 8, 2);
)
CESTER_TEST(lp_second_segment_end, gpu_raster_phase10,
    drawLP();
    ASSERT_PIXEL_EQ(LP_END, 10, 0);
)

// ==========================================================================
// Semi-trans line: GP0(0x42). Per psx-spx the line mask gating is the
// drawing-area mask bit (E6), not the per-pixel texel mask. Lines have
// no texture so the semi-trans always applies the blend equation.
// ==========================================================================

CESTER_TEST(lst_mid_blended, gpu_raster_phase10,
    drawLST();
    /* Semi-trans green over red background. Hardware truth captured;
       likely a 0.5*red + 0.5*green blend = (R=15, G=15, B=0)
       approximately = vram555(15, 15, 0) = 0x01ef. */
    ASSERT_PIXEL_EQ(LST_MID, 5, 4);
)
CESTER_TEST(lst_neighbor_unblended, gpu_raster_phase10,
    drawLST();
    /* Outside the line - background red preserved. */
    ASSERT_PIXEL_EQ(RASTER_VRAM_RED, 5, 5);
)
