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

#pragma once

// Phase-17 dedicated 15-bit signature texture for affine UV characterization.
//
// Lives in its own texpage cell at (tx=11, ty=0) -> VRAM base (704, 0),
// disjoint from the phase-4 TEX4/TEX8/TEX15 fixtures. The 32x32 texture
// encodes texel(u, v) = vram555(u & 31, v & 31, ((u + v) & 31) | 1) so:
//
//   - Red channel = u (5-bit, unique for u in [0, 32)).
//   - Green channel = v (5-bit, unique for v in [0, 32)).
//   - Blue channel = ((u+v)&31) | 1, always odd, in {1, 3, ..., 31}.
//
// Two properties that matter:
//   (a) Every (u, v) in [0, 32)^2 has a unique signature - if you read
//       back a VRAM pixel, you can decode which UV the rasterizer
//       sampled by masking the red and green channels.
//   (b) No texel is 0x0000. Bit 0 of the blue channel is forced set so
//       even (u=0, v=0) renders. PSX hardware treats texel 0x0000 as
//       transparent (canonical rule, verified in phase-4 - see
//       tex15_pixel_0_0_transparent). Forcing bit 0 of blue prevents
//       any probe from accidentally landing on the transparent cell.
//
// Why a new cell instead of extending TEX15: keeps phase-4/phase-8
// fixtures untouched. The TEX15 fixture (phase-4) is 64-wide x 16-tall
// at (tx=10, ty=0); phase-17 probes need up to v=31 so a fresh cell with
// the right footprint was simpler than trying to merge.

#include "raster-helpers.h"
#include "texture-fixtures.h"

#define TEX17_TX             11u
#define TEX17_TY             0u
#define TEX17_VRAM_BASE_X    (TEX17_TX * 64)   /* 704 */
#define TEX17_VRAM_BASE_Y    (TEX17_TY * 256)  /* 0   */

#define TEX17_WIDTH          32  /* texels per row */
#define TEX17_HEIGHT         32  /* rows */

#define TEX17_TPAGE          texpageField(TEX17_TX, TEX17_TY, 0, 2)
#define TEX17_CLUT_FIELD     0u  /* 15-bit direct ignores CLUT */

// Encode a texel value for position (u, v). Mirrors uploadTex17's
// encoding so tests can predict expected sampled-texel values for any
// (u, v) in [0, 32)^2.
static inline uint16_t expectedTex17Color(uint8_t u, uint8_t v) {
    return rasterVram555((uint8_t)(u & 0x1f),
                         (uint8_t)(v & 0x1f),
                         (uint8_t)(((u + v) & 0x1f) | 1));
}

// Upload the 32x32 signature texture to (TEX17_VRAM_BASE_X,
// TEX17_VRAM_BASE_Y). 32 pixels per row * 32 rows = 1024 pixels = 512
// words. Each VRAM pixel IS a 15-bit texel.
static inline void uploadTex17(void) {
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)TEX17_VRAM_BASE_Y << 16) |
               (uint32_t)(uint16_t)TEX17_VRAM_BASE_X;
    GPU_DATA = ((uint32_t)(uint16_t)TEX17_HEIGHT << 16) |
               (uint32_t)(uint16_t)TEX17_WIDTH;
    int wordIdx = 0;
    for (int v = 0; v < TEX17_HEIGHT; v++) {
        for (int u = 0; u < TEX17_WIDTH; u += 2) {
            uint16_t t0 = expectedTex17Color((uint8_t)u, (uint8_t)v);
            uint16_t t1 = expectedTex17Color((uint8_t)(u + 1), (uint8_t)v);
            rasterStreamPace(wordIdx++);
            GPU_DATA = (uint32_t)t0 | ((uint32_t)t1 << 16);
        }
    }
}

// Quiet pixel-equality assertion. Mirrors ASSERT_PIXEL_EQ from
// raster-helpers.h but does NOT emit the OBS log line - phase-17
// onward relies on cester's existing FAIL output for hardware-truth
// capture instead of a parallel printf channel.
#define PHASE17_ASSERT_PIXEL_EQ(expected, x_, y_)                            \
    do {                                                                    \
        uint16_t _aval = rasterReadPixel((int16_t)(x_), (int16_t)(y_));     \
        cester_assert_uint_eq((unsigned)(expected), (unsigned)_aval);       \
    } while (0)

#define PHASE17_ASSERT_PIXEL_UNTOUCHED(x_, y_) \
    PHASE17_ASSERT_PIXEL_EQ(RASTER_SENTINEL, (x_), (y_))
