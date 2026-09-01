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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 4.
//
// Phase 4 binary covers textured-triangle behavior at all three texture
// depths (4-bit CLUT, 8-bit CLUT, 15-bit direct):
//
//   - texture-basic.c    Sampling correctness: UV-to-screen 1:1
//                        triangles at each depth.
//   - (future)           Texture window mask state, U/V wrap.
//   - (future)           Terminal-odd-pixel span parity probes.
//
// Companion to the audit's soft.cc:2547 (drawPoly3TEx4 textured 4-bit
// fast vs slow xmax) and finding #8 (pair-sampler posY+difY offset).
// Phases 1-3 exercised untextured rasterizer only - this is the first
// hardware-truth pass on drawPoly3TEx4 / drawPoly3TEx8 / drawPoly3TD.

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
#include "raster-expected-phase4.h"

CESTER_BODY(
static int s_interruptsWereEnabled;
)

CESTER_BEFORE_ALL(gpu_raster_phase4,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();
    /* Upload all texture + CLUT fixtures once. */
    uploadAllTextureFixtures();

    ramsyscall_printf("\n=== gpu-raster-phase4: textured triangles ===\n");
    ramsyscall_printf("Tex4 tpage=(%u,%u) clut=(%u,%u)\n",
                      TEX4_TX, TEX4_TY, CLUT4_VRAM_X, CLUT4_VRAM_Y);
    ramsyscall_printf("Tex8 tpage=(%u,%u) clut=(%u,%u)\n",
                      TEX8_TX, TEX8_TY, CLUT8_VRAM_X, CLUT8_VRAM_Y);
    ramsyscall_printf("Tex15 tpage=(%u,%u) direct\n",
                      TEX15_TX, TEX15_TY);
    ramsyscall_printf("Grep '^OBS' to capture hardware-truth values.\n\n");
)

CESTER_AFTER_ALL(gpu_raster_phase4,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "texture-basic.c"
#include "texture-window.c"
