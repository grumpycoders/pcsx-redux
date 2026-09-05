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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 15.
//
// Texture windowing exhaustive. Phase-4b + phase-9 verified the
// window formula across depths but covered only mask_u in {0x01,
// 0x03, 0x07} × offset_u in {0, 0x01, 0x03}. Phase-15 expands the
// parameter space to:
//
//   - Full mask range: 0x00 (identity), 0x07, 0x0F, 0x1F (max).
//   - Combined mask_u × mask_v sweep with offset_u × offset_v.
//   - Offset > mask scenarios (offset bits beyond mask coverage).
//   - Window applied to rect / quad in addition to triangle.
//   - Window × semi-trans (window-filtered texel through ABR blend).
//   - Window × bit-15-mask transparent texels (does transparency
//     fire on the filtered or unfiltered texel?).

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
#include "raster-expected-phase15.h"

CESTER_BODY(
static int s_interruptsWereEnabled;

// Custom 8-bit CLUT with bit-15 set on a single entry (CLUT8[0]).
// Used by the window × transparency test - we want the WINDOWED
// sample to potentially hit CLUT8[0] (transparent) and characterize
// what hardware does.
static void uploadClut8MaskedAt0(void) {
    /* Read the standard CLUT8[0], OR in bit-15, write back. */
    uint16_t entries[256];
    for (int i = 0; i < 256; i++) {
        entries[i] = rasterVram555((uint8_t)(i & 0x1f),
                                   (uint8_t)((255 - i) & 0x1f),
                                   (uint8_t)((i >> 5) & 0x1f));
    }
    entries[0] = (uint16_t)(entries[0] | 0x8000u);
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)CLUT8_VRAM_Y << 16) |
               (uint32_t)(uint16_t)CLUT8_VRAM_X;
    GPU_DATA = ((uint32_t)(uint16_t)1 << 16) | (uint32_t)(uint16_t)256;
    for (int i = 0; i < 128; i++) {
        GPU_DATA = (uint32_t)entries[i * 2] |
                   ((uint32_t)entries[i * 2 + 1] << 16);
    }
}
)

CESTER_BEFORE_ALL(gpu_raster_phase15,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();
    uploadAllTextureFixtures();

    ramsyscall_printf("\n=== gpu-raster-phase15: texture windowing exhaustive ===\n");
    ramsyscall_printf("Draw area: (%d,%d) .. (%d,%d), sentinel=0x%04x\n",
                      RASTER_DRAW_AREA_X1, RASTER_DRAW_AREA_Y1,
                      RASTER_DRAW_AREA_X2 - 1, RASTER_DRAW_AREA_Y2 - 1,
                      (unsigned)RASTER_SENTINEL);
    ramsyscall_printf("Grep '^OBS' to capture hardware-truth values.\n\n");
)

CESTER_AFTER_ALL(gpu_raster_phase15,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "tex-window-exhaustive.c"
