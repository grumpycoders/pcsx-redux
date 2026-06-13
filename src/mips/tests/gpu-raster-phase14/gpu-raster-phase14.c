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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 14.
//
// Oversized primitive cull thresholds. psx-spx documents per-edge
// limits of ±1023 horizontal and ±511 vertical for triangle / quad
// primitives - hardware drops the primitive entirely when an edge
// exceeds. Real games sometimes submit oversized geometry expecting
// the cull; soft renderer that clips and renders instead diverges
// from hardware game-compat.
//
// Methodology:
//
//   1. Sentinel-fill an "anchor probe" region the primitive WOULD
//      cover if it rendered (typically a small area near the origin).
//   2. Submit the test primitive with a deliberately oversized edge
//      / vertex / bounding-box.
//   3. Read the anchor pixel:
//        primitive color -> rendered (cull did NOT fire)
//        sentinel        -> dropped (cull fired)
//
//   The dropped-vs-rendered determination at a single pixel is
//   sufficient to identify the threshold. Bisection between known-
//   rendering and known-dropping configurations pins the exact
//   boundary.
//
//   For drop-mechanism characterization, follow an oversized
//   primitive with a small known-good primitive at a different
//   location. If the second renders, the drop is silent (consumes
//   FIFO data and continues); if the second is also dropped, the
//   oversized primitive corrupted the command stream.
//
// Coverage targets per primitive type (untextured tri / gouraud tri
// / textured tri / quad / gouraud quad / textured quad / line / rect):
//
//   - Baseline: small primitive, known-render anchor
//   - Per-edge dx at the suspected threshold (1023 ok, 1024 drop)
//   - Per-edge dy at the suspected threshold (511 ok, 512 drop)
//   - Same edges at way-over thresholds (e.g. dx=2047)
//   - Drop-mechanism probe: oversized followed by small good

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
#include "raster-expected-phase14.h"

CESTER_BODY(
static int s_interruptsWereEnabled;
)

CESTER_BEFORE_ALL(gpu_raster_phase14,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();
    /* Need textures for textured-primitive cull tests. */
    uploadAllTextureFixtures();

    ramsyscall_printf("\n=== gpu-raster-phase14: oversized cull thresholds ===\n");
    ramsyscall_printf("Draw area: (%d,%d) .. (%d,%d), sentinel=0x%04x\n",
                      RASTER_DRAW_AREA_X1, RASTER_DRAW_AREA_Y1,
                      RASTER_DRAW_AREA_X2 - 1, RASTER_DRAW_AREA_Y2 - 1,
                      (unsigned)RASTER_SENTINEL);
    ramsyscall_printf("Grep '^OBS' to capture hardware-truth values.\n\n");
)

CESTER_AFTER_ALL(gpu_raster_phase14,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "cull-thresholds.c"
