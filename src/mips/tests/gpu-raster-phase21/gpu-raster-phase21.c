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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 21.
//
// Texture-coordinate overflow on oversized primitives. UV in a GP0
// command is 8-bit (0..255), but a primitive larger than 256 texels
// in either axis walks its per-pixel U/V counter PAST 255 during
// rasterization. The texel-fetch coordinate on hardware is 8-bit, so
// the counter wraps mod 256 - the texture tiles every 256 texels.
//
// This is the distinct case phase-16 explicitly deferred (see its
// V-wrap comment: "the rasterizer's per-pixel V interpolation could
// exceed 255 if the [primitive] is large; that's a separate concern").
// Phase-16 only probed command-encoded UV in [0,255] via 1x1 rects and
// never overflowed the counter. Phase-21 draws primitives wider/taller
// than 256 and reads back the columns/rows straddling the 256 boundary.
//
// Real-world trigger: a full-screen background drawn as one textured
// sprite wider than 256px (e.g. RPGMaker on PS1). If the sampler keeps
// the high bits of the interpolated coordinate instead of masking to
// 8 bits, those texels index adjacent VRAM and the sprite corrupts.
//
// Fixture: an 8-bit CLUT texture filling the full 256x256 page with
// texel(u, v) = (u + v) & 0xff. That makes both sweeps collapse to one
// predictable form: a pixel sampled at primitive-offset k (from a base
// UV of 0) should read CLUT8[k & 0xff] iff the coordinate wraps mod 256.
//   - along row v=0:  texel(u, 0) = u           -> U sweep
//   - along col u=0:  texel(0, v) = v           -> V sweep

#ifndef PCSX_TESTS
#define PCSX_TESTS 0
#endif

#if PCSX_TESTS
#define CESTER_MAYBE_TEST CESTER_SKIP_TEST
#else
#define CESTER_MAYBE_TEST CESTER_TEST
#endif

#include "common/hardware/dma.h"
#include "common/hardware/gpu.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/irq.h"
#include "common/syscalls/syscalls.h"

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

// clang-format off

#include "raster-helpers.h"
#include "texture-fixtures.h"
#include "raster-expected-phase21.h"

CESTER_BODY(
static int s_interruptsWereEnabled;

// Fill the entire 8-bit texture page (256x256 texels = 128 VRAM pixels
// wide x 256 tall, based at TEX8) with texel(u, v) = (u + v) & 0xff.
// Each 16-bit VRAM pixel packs two 8-bit texels (low byte = even u,
// high byte = odd u); each 32-bit GPU_DATA word writes two VRAM pixels.
static void uploadTex8Overflow(void) {
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)TEX8_VRAM_BASE_Y << 16) |
               (uint32_t)(uint16_t)TEX8_VRAM_BASE_X;
    GPU_DATA = ((uint32_t)(uint16_t)256 << 16) | (uint32_t)(uint16_t)128;
    for (int v = 0; v < 256; v++) {
        for (int px = 0; px < 128; px += 2) {
            /* VRAM pixel column px -> texels u=2*px, 2*px+1 */
            uint32_t lo = (((uint32_t)(2 * px + 0 + v)) & 0xff) |
                          ((((uint32_t)(2 * px + 1 + v)) & 0xff) << 8);
            /* VRAM pixel column px+1 -> texels u=2*px+2, 2*px+3 */
            uint32_t hi = (((uint32_t)(2 * px + 2 + v)) & 0xff) |
                          ((((uint32_t)(2 * px + 3 + v)) & 0xff) << 8);
            rasterStreamPace(px / 2);
            GPU_DATA = (lo & 0xffff) | ((hi & 0xffff) << 16);
        }
    }
}
)

CESTER_BEFORE_ALL(gpu_raster_phase21,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();
    uploadAllTextureFixtures();  /* sets up CLUT8 (256 entries) + others */
    uploadTex8Overflow();        /* overwrite TEX8 page with the (u+v) ramp */

    ramsyscall_printf("\n=== gpu-raster-phase21: oversized-primitive UV overflow ===\n");
    ramsyscall_printf("Draw area: (%d,%d) .. (%d,%d), sentinel=0x%04x\n",
                      RASTER_DRAW_AREA_X1, RASTER_DRAW_AREA_Y1,
                      RASTER_DRAW_AREA_X2 - 1, RASTER_DRAW_AREA_Y2 - 1,
                      (unsigned)RASTER_SENTINEL);
    ramsyscall_printf("Grep '^OBS' to capture hardware-truth values.\n\n");
)

CESTER_AFTER_ALL(gpu_raster_phase21,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "uv-overflow.c"
