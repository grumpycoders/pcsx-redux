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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 7.
//
// Gouraud (per-vertex shaded) color precision oracle. The PS1 GPU
// interpolates per-vertex colors using the same integer-truncation
// accumulator pattern as the rightX edge walker phase-6 oracled. Phase-6
// found `m_deltaRightX = (v2->x - v1->x) << 16 / height` truncates per
// row; the same shape recurs for R, G, B in `setupSectionsShade3` and
// its `shl10idiv` per-row deltas, plus a separate horizontal per-pixel
// delta inside drawPoly3Gi.
//
// Categories:
//   GC1/GC2/GC3  Canonical RGB-vertex triangles at three sizes (8, 32,
//                128). One pure-R apex + pure-G/pure-B base vertices.
//                Probe vertex, mid-edge, centroid, and interior pixels.
//   GV*          R-only vertical gradient (probes left-edge color
//                accumulator). Heights 3, 5, 7, 11 - widths and heights
//                picked to land on classic truncation pairs.
//   GH*          R-only horizontal gradient (probes per-pixel-X color
//                delta). Widths 3, 5, 7, 11.
//   GS*          Near-vertex saturation probes - do per-vertex pixels
//                land exactly at the vertex color, or has accumulator
//                drift slipped them past 0 / past max?
//   GD*          Same canonical 32x32 triangle with dither ON. 4x4 OBS
//                grid to catch the Bayer pattern.
//   GO*          Same canonical 8x8 triangle, six vertex orderings.
//                Hardware should be order-independent.
//
// The deliverable is a complete HW_VERIFIED oracle for the soft-
// renderer delta-precision refactor (paired with phase-6's xmax oracle
// in the same fix family).

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
#include "raster-expected-phase7.h"

CESTER_BODY(
static int s_interruptsWereEnabled;
)

CESTER_BEFORE_ALL(gpu_raster_phase7,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();

    ramsyscall_printf("\n=== gpu-raster-phase7: gouraud color precision ===\n");
    ramsyscall_printf("Draw area: (%d,%d) .. (%d,%d), sentinel=0x%04x\n",
                      RASTER_DRAW_AREA_X1, RASTER_DRAW_AREA_Y1,
                      RASTER_DRAW_AREA_X2 - 1, RASTER_DRAW_AREA_Y2 - 1,
                      (unsigned)RASTER_SENTINEL);
    ramsyscall_printf("Grep '^OBS' to capture hardware-truth values.\n\n");
)

CESTER_AFTER_ALL(gpu_raster_phase7,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "gouraud-color.c"
