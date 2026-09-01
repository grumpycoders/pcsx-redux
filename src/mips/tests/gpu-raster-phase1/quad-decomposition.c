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

// Quad decomposition suite. The PS1 GPU decomposes 4-vertex polygons
// into two triangles internally; the audit at soft.cc:2493-2496 says
// the soft renderer splits as (1,3,2) + (0,1,2). Hardware truth here
// determines:
//   - Whether the diagonal seam pixel is drawn once, twice, or not at all.
//   - Whether the second triangle's edge rule sees the seam edge as
//     top-or-bottom (depends on winding).
//   - Whether 4-vertex coordinate ordering changes the fill set for
//     otherwise-identical destination geometry.

CESTER_BODY(

// Quad Q: 4x4 axis-aligned square, vertices in scan order
// (0,0),(4,0),(0,4),(4,4), BLUE.
static void rasterDrawQuadQ(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatQuad(RASTER_CMD_BLUE, 0, 0, 4, 0, 0, 4, 4, 4);
    rasterFlushPrimitive();
}

// Quad R: same square but with vertices in reversed winding -
// (4,4),(0,4),(4,0),(0,0). The destination geometry is identical but the
// rasterizer's decomposition sees a different triangle pair. Captures
// whether winding affects the fill set on hardware.
static void rasterDrawQuadR(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatQuad(RASTER_CMD_BLUE, 4, 4, 0, 4, 4, 0, 0, 0);
    rasterFlushPrimitive();
}

// Quad S: 4-vertex polygon where the 4th vertex creates a non-convex
// shape (the second-triangle decomposition draws OUTSIDE the apparent
// quad). Vertices (0,0),(4,0),(0,4),(2,2). The two-triangle split
// produces tri (4,0)-(2,2)-(0,4) (smaller, interior) and tri
// (0,0)-(4,0)-(0,4) (large, full upper-left). Documents what hardware
// does with degenerate-concave 4-vertex input.
static void rasterDrawQuadS(void) {
    rasterReset();
    rasterClearTestRegion(0, 0, 16, 16);
    rasterFlatQuad(RASTER_CMD_GREEN, 0, 0, 4, 0, 0, 4, 2, 2);
    rasterFlushPrimitive();
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// Quad Q: 4x4 axis-aligned, scan-order winding
// --------------------------------------------------------------------------

CESTER_TEST(quadQ_pixel_0_0, gpu_raster_phase1,
    rasterDrawQuadQ();
    ASSERT_PIXEL_EQ(EXPECT_QUAD_Q_PIXEL_0_0, 0, 0);
)

CESTER_TEST(quadQ_pixel_3_0_top_right, gpu_raster_phase1,
    rasterDrawQuadQ();
    ASSERT_PIXEL_EQ(EXPECT_QUAD_Q_PIXEL_3_0, 3, 0);
)

CESTER_TEST(quadQ_pixel_4_0_right_edge, gpu_raster_phase1,
    rasterDrawQuadQ();
    ASSERT_PIXEL_EQ(EXPECT_QUAD_Q_PIXEL_4_0, 4, 0);
)

CESTER_TEST(quadQ_pixel_0_3_bottom_left, gpu_raster_phase1,
    rasterDrawQuadQ();
    ASSERT_PIXEL_EQ(EXPECT_QUAD_Q_PIXEL_0_3, 0, 3);
)

CESTER_TEST(quadQ_pixel_3_3_interior_corner, gpu_raster_phase1,
    rasterDrawQuadQ();
    ASSERT_PIXEL_EQ(EXPECT_QUAD_Q_PIXEL_3_3, 3, 3);
)

CESTER_TEST(quadQ_pixel_4_4_outside_bottom_right, gpu_raster_phase1,
    rasterDrawQuadQ();
    ASSERT_PIXEL_EQ(EXPECT_QUAD_Q_PIXEL_4_4, 4, 4);
)

CESTER_TEST(quadQ_pixel_0_4_bottom_edge, gpu_raster_phase1,
    rasterDrawQuadQ();
    ASSERT_PIXEL_EQ(EXPECT_QUAD_Q_PIXEL_0_4, 0, 4);
)

CESTER_TEST(quadQ_pixel_2_2_diagonal_seam, gpu_raster_phase1,
    rasterDrawQuadQ();
    ASSERT_PIXEL_EQ(EXPECT_QUAD_Q_PIXEL_2_2, 2, 2);
)

// --------------------------------------------------------------------------
// Quad R: same destination geometry, reversed winding
// --------------------------------------------------------------------------
//
// Expected: identical fill set to Quad Q if hardware is winding-agnostic
// for flat untextured. If results differ, the rasterizer is reading
// winding for fill-rule purposes.

CESTER_TEST(quadR_reversed_winding_pixel_0_0, gpu_raster_phase1,
    rasterDrawQuadR();
    ASSERT_PIXEL_EQ(EXPECT_QUAD_Q_PIXEL_0_0, 0, 0);
)

CESTER_TEST(quadR_reversed_winding_pixel_3_3, gpu_raster_phase1,
    rasterDrawQuadR();
    ASSERT_PIXEL_EQ(EXPECT_QUAD_Q_PIXEL_3_3, 3, 3);
)

CESTER_TEST(quadR_reversed_winding_pixel_2_2_seam, gpu_raster_phase1,
    rasterDrawQuadR();
    ASSERT_PIXEL_EQ(EXPECT_QUAD_Q_PIXEL_2_2, 2, 2);
)

CESTER_TEST(quadR_reversed_winding_pixel_4_4_outside, gpu_raster_phase1,
    rasterDrawQuadR();
    ASSERT_PIXEL_EQ(EXPECT_QUAD_Q_PIXEL_4_4, 4, 4);
)

// --------------------------------------------------------------------------
// Quad S: non-convex 4-vertex (4th vertex inside triangle of first three)
// --------------------------------------------------------------------------
//
// Pure characterization: no EXPECT macros (added once hardware run lands).
// Reads back a 5x5 grid; emits OBS lines for every pixel. cester assertions
// are absent here because the behavior is fully undefined by psx-spx and
// the test exists only to capture ground truth.

CESTER_TEST(quadS_nonconvex_dump_5x5, gpu_raster_phase1,
    rasterDrawQuadS();
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            uint16_t v = rasterReadPixel((int16_t)x, (int16_t)y);
            ramsyscall_printf("OBS quadS x=%d y=%d val=0x%04x\n",
                              x, y, (unsigned)v);
        }
    }
    // Assert at least one pixel is non-sentinel so the test fails if
    // the GPU drew nothing at all (which would itself be a finding).
    cester_assert_uint_ne((unsigned)RASTER_SENTINEL,
                          (unsigned)rasterReadPixel(0, 0));
)
