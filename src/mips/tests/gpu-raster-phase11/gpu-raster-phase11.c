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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 11.
//
// Focused dither characterization. Phase-7's GD probes captured a
// gradient + dither mix at 16 fixed positions and surfaced 8 cells
// with a uniform +1057 LSB residue against Redux. Whether that's a
// rounding tweak or a structural divergence in the dither
// implementation can't be resolved from the phase-7 probes alone -
// they conflate base gradient with dither offset.
//
// Phase-11 isolates the dither table by using CONSTANT-color gouraud
// triangles (all three vertices same color) with dither ON. Input
// color is constant across every pixel; any per-pixel output
// difference is purely the dither table offset at that pixel
// position. From this we can:
//
//   1. Empirically reconstruct the 4x4 Bayer table at one base color.
//   2. Sweep across multiple base colors to confirm offsets are
//      additive and not base-dependent.
//   3. Confirm dither is screen-space-anchored (same pixel position
//      = same offset regardless of which triangle covers it).
//   4. Characterize saturation behavior at the 0/255 boundaries.
//
// Output is the oracle for the future dither-precision refactor (the
// second member of the delta-precision fix family currently
// addressing phase-7's gouraud gradient finding).

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
#include "raster-expected-phase11.h"

CESTER_BODY(
static int s_interruptsWereEnabled;
)

CESTER_BEFORE_ALL(gpu_raster_phase11,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();

    ramsyscall_printf("\n=== gpu-raster-phase11: dither characterization ===\n");
    ramsyscall_printf("Draw area: (%d,%d) .. (%d,%d), sentinel=0x%04x\n",
                      RASTER_DRAW_AREA_X1, RASTER_DRAW_AREA_Y1,
                      RASTER_DRAW_AREA_X2 - 1, RASTER_DRAW_AREA_Y2 - 1,
                      (unsigned)RASTER_SENTINEL);
    ramsyscall_printf("Grep '^OBS' to capture hardware-truth values.\n\n");
)

CESTER_AFTER_ALL(gpu_raster_phase11,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "dither-characterization.c"
