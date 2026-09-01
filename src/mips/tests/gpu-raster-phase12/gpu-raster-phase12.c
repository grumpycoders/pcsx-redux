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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 12.
//
// ABR (semi-transparency) mode matrix. Phase-8 verified the texel-
// mask GATING on textured semi-trans (where bit-15 of the sampled
// texel decides whether to blend); phase-10 verified that lines
// don't carry the gate. Neither phase characterized the actual
// blend MATH. Phase-12 fills that gap.
//
// Coverage:
//
//   ABR_TRI: untextured semi-trans triangle math sweep across the
//       four ABR modes (set via GP0(E1) bits 5-6) at representative
//       (B, F) pairs. R-only color so output is read off the R5
//       channel directly. Each ABR mode x 9 (B, F) pairs.
//
//   ABR_PRIM: same ABR matrix across other untextured semi-trans
//       primitive types (quad GP0 0x2A, rect GP0 0x62, line GP0 0x42).
//       Confirms the blend math is shared across primitives, not
//       primitive-specific.
//
//   ABR_TEX_MASKED: textured semi-trans triangle (GP0 0x26) at 4/8/
//       15-bit, using fixture textures with bit-15 mask SET so the
//       gate fires. Confirms the blend math applies the same when
//       gated.
//
//   ABR_MASKBIT: set-mask and check-mask E6 bits combined with semi-
//       trans. Verifies the interaction.

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
#include "raster-expected-phase12.h"

CESTER_BODY(
static int s_interruptsWereEnabled;

// Upload a 4-bit CLUT with EVERY entry's bit-15 set. Used by ABR_TEX
// tests to fire the semi-trans gate. Same layout as the standard
// CLUT4 at (CLUT4_VRAM_X, CLUT4_VRAM_Y) but with mask bit OR'd in.
static void uploadClut4Masked(void) {
    uint16_t clut[16];
    for (int i = 0; i < 16; i++) {
        clut[i] = (uint16_t)(rasterVram555((uint8_t)i, (uint8_t)(31 - i), 0)
                             | 0x8000u);
    }
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)CLUT4_VRAM_Y << 16) |
               (uint32_t)(uint16_t)CLUT4_VRAM_X;
    GPU_DATA = ((uint32_t)(uint16_t)1 << 16) | (uint32_t)(uint16_t)16;
    for (int i = 0; i < 8; i++) {
        GPU_DATA = (uint32_t)clut[i * 2] |
                   ((uint32_t)clut[i * 2 + 1] << 16);
    }
}
)

CESTER_BEFORE_ALL(gpu_raster_phase12,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();

    /* Phase-12 uses a custom 4-bit CLUT with bit-15 SET on every
       entry. Upload that AFTER the base fixtures so it overrides the
       standard CLUT4 in the same VRAM slot. The 8-bit and 15-bit
       fixtures don't carry mask bits anywhere, so for ABR_TEX_MASKED
       at those depths we'd need separate masked fixtures - skipped
       for this phase (the 4-bit CLUT path is enough to verify the
       gate-fires-then-blend code path). */
    uploadAllTextureFixtures();
    uploadClut4Masked();

    ramsyscall_printf("\n=== gpu-raster-phase12: ABR mode matrix ===\n");
    ramsyscall_printf("Draw area: (%d,%d) .. (%d,%d), sentinel=0x%04x\n",
                      RASTER_DRAW_AREA_X1, RASTER_DRAW_AREA_Y1,
                      RASTER_DRAW_AREA_X2 - 1, RASTER_DRAW_AREA_Y2 - 1,
                      (unsigned)RASTER_SENTINEL);
    ramsyscall_printf("Grep '^OBS' to capture hardware-truth values.\n\n");
)

CESTER_AFTER_ALL(gpu_raster_phase12,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "abr-matrix.c"
