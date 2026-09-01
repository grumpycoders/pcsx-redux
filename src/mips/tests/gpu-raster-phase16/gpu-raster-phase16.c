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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 16.
//
// U/V coordinates crossing texture-page boundaries. UV coords in
// primitive commands are 8-bit (0..255). Texpage extent in texel
// coords depends on depth:
//
//   4-bit:  256 wide × 256 tall (UV fully covers the page)
//   8-bit:  128 wide × 256 tall (U > 127 -> off-page)
//   15-bit: 64 wide × 256 tall (U > 63 -> off-page)
//
// psx-spx says "wrap within the page" for off-page UV. Phase-16
// verifies what hardware actually does at the boundary:
//
//   - U at the boundary (depth-dependent)
//   - U past the boundary
//   - V at row 255 vs 256 (wraps mod 256?)

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
#include "raster-expected-phase16.h"

CESTER_BODY(
static int s_interruptsWereEnabled;

// 8-bit texture upload spanning the FULL u=0..255 range. The
// standard uploadTex8() only covers 64 logical texels (u=0..63);
// for the boundary tests we need data across the depth-dependent
// page width. Upload texel(u, v) = u & 0xff across u=0..255 at
// v=0..15. VRAM width for 8-bit = 128 VRAM pixels per row (256
// texels), so we upload a 128-wide x 16-tall block.
static void uploadTex8Full(void) {
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)TEX8_VRAM_BASE_Y << 16) |
               (uint32_t)(uint16_t)TEX8_VRAM_BASE_X;
    GPU_DATA = ((uint32_t)(uint16_t)16 << 16) | (uint32_t)(uint16_t)128;
    for (int v = 0; v < 16; v++) {
        for (int px = 0; px < 128; px += 2) {
            uint32_t lo = ((uint32_t)(px * 2 + 0) & 0xff) |
                          (((uint32_t)(px * 2 + 1) & 0xff) << 8);
            uint32_t hi = ((uint32_t)(px * 2 + 2) & 0xff) |
                          (((uint32_t)(px * 2 + 3) & 0xff) << 8);
            rasterStreamPace(px / 2);
            GPU_DATA = (lo & 0xffff) | ((hi & 0xffff) << 16);
        }
    }
}
)

CESTER_BEFORE_ALL(gpu_raster_phase16,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();
    uploadAllTextureFixtures();
    uploadTex8Full();  /* expand TEX8 to full 256-byte range */
    /* The expanded TEX8 (128 VRAM pixels wide starting at x=576)
       overwrites TEX15 (starting at x=640). Re-upload TEX15 to
       restore the 15-bit fixture data. */
    uploadTex15();

    ramsyscall_printf("\n=== gpu-raster-phase16: U/V page boundary crossing ===\n");
    ramsyscall_printf("Draw area: (%d,%d) .. (%d,%d), sentinel=0x%04x\n",
                      RASTER_DRAW_AREA_X1, RASTER_DRAW_AREA_Y1,
                      RASTER_DRAW_AREA_X2 - 1, RASTER_DRAW_AREA_Y2 - 1,
                      (unsigned)RASTER_SENTINEL);
    ramsyscall_printf("Grep '^OBS' to capture hardware-truth values.\n\n");
)

CESTER_AFTER_ALL(gpu_raster_phase16,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "uv-boundary.c"
