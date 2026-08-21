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

// Overflow probes. Each test draws one oversized 8-bit textured rect
// based at the test origin (0,0) with a chosen base UV, then reads
// back a column (U sweep, row v=0) or row (V sweep, col u=0). The
// fixture is texel(u,v) = (u+v)&0xff, so the texel sampled at
// primitive-offset k from base b is ((b + k) & 0xff) iff the texel
// coordinate wraps mod 256. Each expectation is therefore
// expectedClut8Color((base + offset) & 0xff).

CESTER_BODY(

    // Draw an 8-bit textured rect at the origin with the given base UV and
    // size. Clears the rect footprint to the sentinel first so any pixel
    // that did NOT draw (e.g. a coordinate sampling transparent CLUT[0])
    // is distinguishable from a wrapped fetch.
    static void drawTex8Rect(uint8_t u0, uint8_t v0, int16_t w, int16_t h) {
        rasterReset();
        rasterClearTestRegion(0, 0, (int16_t)((w + 1) & ~1), h);
        setTexpage(TEX8_TX, TEX8_TY, 1);
        setTextureWindow(0, 0, 0, 0);
        rasterTexRect(TEX_MOD_NEUTRAL, 0, 0, u0, v0, w, h, CLUT8_FIELD);
        rasterFlushPrimitive();
    }

    )  // CESTER_BODY

// ============================================================================
// U overflow. Wide rect (264 px) based at u=0. Columns 0..255 map to
// u=0..255 (in range); columns 256..263 must wrap to u=0..7.
// ============================================================================

CESTER_TEST(ovf_u_base0_c5, gpu_raster_phase21, drawTex8Rect(0, 0, 264, 2);
            /* Control: in-range column, no overflow. u=5. */
            ASSERT_PIXEL_EQ(expectedClut8Color(5), 5, 0);)

CESTER_TEST(ovf_u_base0_c200, gpu_raster_phase21, drawTex8Rect(0, 0, 264, 2);
            /* Control: deep in-range column. u=200. */
            ASSERT_PIXEL_EQ(expectedClut8Color(200), 200, 0);)

CESTER_TEST(ovf_u_base0_c255, gpu_raster_phase21, drawTex8Rect(0, 0, 264, 2);
            /* Last in-range column. u=255. */
            ASSERT_PIXEL_EQ(expectedClut8Color(255), 255, 0);)

CESTER_TEST(ovf_u_base0_c256, gpu_raster_phase21, drawTex8Rect(0, 0, 264, 2);
            /* First overflow column: u counter hits 256 -> wraps to 0. */
            ASSERT_PIXEL_EQ(expectedClut8Color(256 & 0xff), 256, 0);)

CESTER_TEST(ovf_u_base0_c257, gpu_raster_phase21, drawTex8Rect(0, 0, 264, 2);
            /* Overflow -> u=1. */
            ASSERT_PIXEL_EQ(expectedClut8Color(257 & 0xff), 257, 0);)

CESTER_TEST(ovf_u_base0_c263, gpu_raster_phase21, drawTex8Rect(0, 0, 264, 2);
            /* Overflow -> u=7. */
            ASSERT_PIXEL_EQ(expectedClut8Color(263 & 0xff), 263, 0);)

// ============================================================================
// U overflow with a non-zero base. Base u=200, width 64 -> the wrap
// happens mid-rect at column 56 (200+56 = 256 -> 0).
// ============================================================================

CESTER_TEST(ovf_u_base200_c55, gpu_raster_phase21, drawTex8Rect(200, 0, 64, 2);
            /* u = 200+55 = 255, last before wrap. */
            ASSERT_PIXEL_EQ(expectedClut8Color((200 + 55) & 0xff), 55, 0);)

CESTER_TEST(ovf_u_base200_c56, gpu_raster_phase21, drawTex8Rect(200, 0, 64, 2);
            /* u = 200+56 = 256 -> wraps to 0. */
            ASSERT_PIXEL_EQ(expectedClut8Color((200 + 56) & 0xff), 56, 0);)

CESTER_TEST(ovf_u_base200_c57, gpu_raster_phase21, drawTex8Rect(200, 0, 64, 2);
            /* u -> 1. */
            ASSERT_PIXEL_EQ(expectedClut8Color((200 + 57) & 0xff), 57, 0);)

// ============================================================================
// V overflow. Tall rect (264 px) based at v=0, sampled at col u=0.
// Rows 0..255 map to v=0..255 (in range); rows 256..263 must wrap.
// ============================================================================

CESTER_TEST(ovf_v_base0_r5, gpu_raster_phase21, drawTex8Rect(0, 0, 2, 264);
            /* Control: in-range row. v=5 -> texel(0,5)=5. */
            ASSERT_PIXEL_EQ(expectedClut8Color(5), 0, 5);)

CESTER_TEST(ovf_v_base0_r255, gpu_raster_phase21, drawTex8Rect(0, 0, 2, 264);
            /* Last in-range row. v=255. */
            ASSERT_PIXEL_EQ(expectedClut8Color(255), 0, 255);)

CESTER_TEST(ovf_v_base0_r256, gpu_raster_phase21, drawTex8Rect(0, 0, 2, 264);
            /* First overflow row: v counter hits 256 -> wraps to 0. */
            ASSERT_PIXEL_EQ(expectedClut8Color(256 & 0xff), 0, 256);)

CESTER_TEST(ovf_v_base0_r257, gpu_raster_phase21, drawTex8Rect(0, 0, 2, 264);
            /* Overflow -> v=1. */
            ASSERT_PIXEL_EQ(expectedClut8Color(257 & 0xff), 0, 257);)
