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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 8.
//
// 4-vertex flat textured quad oracle. The audit flagged finding #8:
// soft.cc's 4-vertex flat-textured pair sampler uses `posY + difY` at
// the terminal odd-pixel sample (drawPoly4TEx4 / drawPoly4TEx8_S sites
// soft.cc:3117 / 3162 / 3249 / 3294), while the 3-vertex sibling
// `drawPoly3TEx4` (soft.cc:2580-2582) uses `posY` at the same site.
// One of those two paths is wrong against hardware. Phase-8 captures
// hardware truth for both odd-width and even-width row terminal pixels
// at all three depths so the refactor can converge to the right rule.
//
// Categories:
//   QFA[4|8|15]  Axis-aligned rectangular quad, UV matching screen 1:1.
//                Baseline correctness across depths.
//   QFD[4|8|15]  Skewed quad (parallelogram). Tests the per-row UV
//                interpolation across non-rectangular shapes - the
//                soft renderer's setupSectionsFlatTextured4 path.
//   QFO[4|8|15]  Odd-width row terminal probes. Quad widths chosen so
//                row pixel-count is odd; the terminal sampler fires
//                and reveals what V the hardware reads at that pixel.
//   QFS[4|8]     Semi-trans variants (GP0(0x2E)). Ensures the
//                drawPoly4TEx*_S paths are also covered, not just the
//                opaque path.
//   QFDeg        Degenerate quad with v3 coincident on v2. Verifies
//                the 4-vert math collapses cleanly to triangle output.

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
#include "raster-expected-phase8.h"

CESTER_BODY(
static int s_interruptsWereEnabled;
)

CESTER_BEFORE_ALL(gpu_raster_phase8,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();

    /* Upload all texture fixtures once. They live outside the test
       draw region so they survive the per-test sentinel clear. */
    uploadAllTextureFixtures();

    ramsyscall_printf("\n=== gpu-raster-phase8: 4-vert textured quad ===\n");
    ramsyscall_printf("Draw area: (%d,%d) .. (%d,%d), sentinel=0x%04x\n",
                      RASTER_DRAW_AREA_X1, RASTER_DRAW_AREA_Y1,
                      RASTER_DRAW_AREA_X2 - 1, RASTER_DRAW_AREA_Y2 - 1,
                      (unsigned)RASTER_SENTINEL);
    ramsyscall_printf("Grep '^OBS' to capture hardware-truth values.\n\n");
)

CESTER_AFTER_ALL(gpu_raster_phase8,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "quad-flat.c"
