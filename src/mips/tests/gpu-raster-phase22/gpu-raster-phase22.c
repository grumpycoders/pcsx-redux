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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 22.
//
// Slanted untextured gouraud color oracle. Closes the coverage gap left
// by the earlier gouraud / slanted phases:
//   phase-7   gouraud color, but AXIS-ALIGNED (apex at origin, one
//             vertical + one horizontal edge).
//   phase-3   SLANTED triangles, but FLAT shaded (color coverage only).
//   phase-17..20  SLANTED triangles, but TEXTURED (affine UV).
// None of them draws a slanted, untextured, gouraud-shaded triangle.
// On such a triangle BOTH the per-row left-edge color seed (at a
// fractional left x) and the horizontal per-pixel delta accumulate
// truncated steps, and those truncations compound across rows - the
// exact case the axis-aligned suite cannot reach.
//
// Categories:
//   SG_AB        Cross-check triangle reused from the libgouraud A/B
//                work, full 8-bit 0xFF command colors. 24 silicon
//                pixels carried over (HW_VERIFIED, dither off).
//   SG1 / SG2    Fresh slanted RGB triangles, two orientations/sizes.
//   SG_R         R-only slanted gradient (single-channel accumulator).
//   SG3          Narrow / steep slanted triangle.
//
// The deliverable is a complete HW_VERIFIED oracle for slanted gouraud
// color so the soft renderer can be checked on the primitive phase-7
// could not exercise.

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
#include "raster-expected-phase22.h"

CESTER_BODY(
static int s_interruptsWereEnabled;
)

CESTER_BEFORE_ALL(gpu_raster_phase22,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();

    ramsyscall_printf("\n=== gpu-raster-phase22: slanted gouraud color ===\n");
    ramsyscall_printf("Draw area: (%d,%d) .. (%d,%d), sentinel=0x%04x\n",
                      RASTER_DRAW_AREA_X1, RASTER_DRAW_AREA_Y1,
                      RASTER_DRAW_AREA_X2 - 1, RASTER_DRAW_AREA_Y2 - 1,
                      (unsigned)RASTER_SENTINEL);
    ramsyscall_printf("Grep '^OBS' to capture hardware-truth values.\n\n");
)

CESTER_AFTER_ALL(gpu_raster_phase22,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "slanted-gouraud.c"
