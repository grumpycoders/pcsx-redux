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

// Mask-bit suite. GP0(E6) sets two bits of GPU state:
//   bit 0: set-mask     - drawn pixels have VRAM bit 15 forced to 1
//   bit 1: check-mask   - skip writes to VRAM pixels with bit 15 == 1
//
// Tests:
//   1. set-mask only: drawn pixels should be 0x801f (RED + mask bit).
//   2. set-mask then check-mask overlay: mask-set pixels preserved,
//      non-mask pixels overwritten.
//
// SENTINEL OVERRIDE: the default RASTER_SENTINEL (0xDEAD) has bit 15
// set. Check-mask would skip writes to pixels containing the sentinel,
// which conflates "rasterizer chose to skip" with "sentinel collided".
// Per the documented mitigation in raster-helpers.h, this suite uses a
// local mask-clear sentinel.

#define MASK_SUITE_SENTINEL  0x5555u  /* R=21,G=10,B=21,mask=0 - no bit 15 */

CESTER_BODY(

// Set-mask + draw RED triangle (same as triangle A but with E6=0x01).
static void rasterDrawMaskSet(void) {
    rasterReset();
    // Use the local mask-clear sentinel so absence-tests work even
    // though check-mask is not active in this draw - keeps the suite
    // internally consistent.
    rasterFillRect(0, 0, 16, 16, MASK_SUITE_SENTINEL);
    // GP0(E6): set bit 0 (set-mask). Pixels drawn after this command
    // get VRAM bit 15 forced to 1.
    sendGPUData(0xe6000001u);
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 4, 0, 0, 4);
    rasterFlushPrimitive();
}

// Set-mask first triangle, then check-mask second overlapping triangle.
// Geometry: tri A (0,0)(4,0)(0,4) RED with set-mask, then tri (4,0)(8,0)(4,4)
// GREEN with check-mask. They overlap on the shared edge from (4,0)
// down; mask-set RED pixels should preserve, non-overlap GREEN pixels
// should fill.
static void rasterDrawMaskCheck(void) {
    rasterReset();
    rasterFillRect(0, 0, 16, 16, MASK_SUITE_SENTINEL);

    // First pass: RED tri with set-mask, no check.
    sendGPUData(0xe6000001u);
    rasterFlatTri(RASTER_CMD_RED, 0, 0, 4, 0, 0, 4);
    rasterFlushPrimitive();

    // Second pass: GREEN tri with check-mask, no set.
    sendGPUData(0xe6000002u);
    rasterFlatTri(RASTER_CMD_GREEN, 4, 0, 8, 0, 4, 4);
    rasterFlushPrimitive();

    // Restore mask state to default for subsequent tests.
    sendGPUData(0xe6000000u);
}

)  // CESTER_BODY

// --------------------------------------------------------------------------
// Set-mask: drawn pixels have bit 15 forced
// --------------------------------------------------------------------------

CESTER_TEST(maskSet_origin_has_mask_bit, gpu_raster_phase2,
    rasterDrawMaskSet();
    ASSERT_PIXEL_EQ(EXPECT_MASK_SET_PIXEL_0_0, 0, 0);
)

CESTER_TEST(maskSet_interior_has_mask_bit, gpu_raster_phase2,
    rasterDrawMaskSet();
    ASSERT_PIXEL_EQ(EXPECT_MASK_SET_PIXEL_2_1, 2, 1);
)

CESTER_TEST(maskSet_right_edge_excluded, gpu_raster_phase2,
    rasterDrawMaskSet();
    // Note: this suite uses MASK_SUITE_SENTINEL (0x5555) not RASTER_SENTINEL.
    // The macro in raster-expected-phase2.h still references the global
    // RASTER_SENTINEL for absence cases; we override locally here.
    ASSERT_PIXEL_EQ((unsigned)MASK_SUITE_SENTINEL, 4, 0);
)

// --------------------------------------------------------------------------
// Check-mask: pixels already masked are preserved
// --------------------------------------------------------------------------

CESTER_TEST(maskCheck_preserves_red_at_overlap_1_0, gpu_raster_phase2,
    rasterDrawMaskCheck();
    // (1, 0) is in both triangles. First pass (RED + set-mask) writes
    // 0x801f. Second pass (GREEN + check-mask) should see bit 15 set
    // and skip, preserving 0x801f.
    ASSERT_PIXEL_EQ(EXPECT_MASK_CHECK_PIXEL_1_0_preserved, 1, 0);
)

CESTER_TEST(maskCheck_fills_green_in_non_overlap_5_0, gpu_raster_phase2,
    rasterDrawMaskCheck();
    // (5, 0) is in GREEN tri only and the local sentinel 0x5555 has bit
    // 15 clear, so check-mask should allow the write. Expect GREEN.
    ASSERT_PIXEL_EQ(EXPECT_MASK_CHECK_PIXEL_5_0_filled, 5, 0);
)
