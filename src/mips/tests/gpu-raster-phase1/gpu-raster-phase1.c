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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 1.
//
// Purpose: build a golden oracle for the soft-renderer template refactor.
// Real hardware is ground truth; PCSX-Redux is the device-under-test. Each
// test asserts the exact post-draw VRAM value at one specific pixel
// coordinate. Failures on Redux ARE the deliverable - they enumerate the
// soft-renderer punch-list.
//
// Phase 1 binary covers untextured primitives:
//   - triangle-edges.c        Flat untextured triangles. Fill rule, edge
//                             inclusion, degenerates, xmax==xmin spans.
//   - quad-decomposition.c    Untextured quads. Diagonal seam pixels.
//   - rectangle-clipping.c    GP0(0x60) rectangles. Draw-area clipping.
//   - draw-area.c             Drawing-area + drawing-offset interactions.
//
// Phase 2 binary (separate target) covers:
//   - line-endpoints.c        Bresenham line endpoint convention.
//   - mask-bit.c              Set-mask / check-mask interactions.
//   - texture-window.c        Textured triangles at 4/8/15 bit depths.
//
// The two binaries share raster-helpers.h and raster-expected.h which
// live in this directory; phase 2 includes them via relative path.
//
// Workflow:
//   1. Build TYPE=ps-exe.
//   2. Run on real hardware via Unirom + psxup.py and capture serial output.
//   3. grep `^OBS` on the captured log gives every pixel's actual value.
//   4. Patch raster-expected.h's EXPECT_* macros to match hardware truth.
//   5. Subsequent Redux runs that diverge from those values produce the
//      soft-renderer punch-list as cester FAIL lines ("expected 0xXXXX,
//      received 0xYYYY at file:line").

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
#include "raster-expected.h"

CESTER_BODY(
static int s_interruptsWereEnabled;
)

CESTER_BEFORE_ALL(gpu_raster_phase1,
    // Disable interrupts so VBlank or controller IRQs do not race the
    // tight VRAM transfer loops in raster-helpers.h. The arcade-tests
    // suite established this discipline; gpu.md "Hardware test interrupt
    // discipline" documents why.
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;

    // Full GPU reset once at startup. Subsequent tests use the lighter
    // rasterReset() in their own draw helpers (see triangle-edges.c).
    rasterFullReset();

    ramsyscall_printf("\n=== gpu-raster: PS1 rasterizer edge-behavior suite ===\n");
    ramsyscall_printf("Draw area: (%d,%d) .. (%d,%d), sentinel=0x%04x\n",
                      RASTER_DRAW_AREA_X1, RASTER_DRAW_AREA_Y1,
                      RASTER_DRAW_AREA_X2 - 1, RASTER_DRAW_AREA_Y2 - 1,
                      (unsigned)RASTER_SENTINEL);
    ramsyscall_printf("OBS lines below carry per-pixel hardware-truth values.\n");
    ramsyscall_printf("Grep '^OBS' in the run log to capture expected values.\n\n");
)

CESTER_AFTER_ALL(gpu_raster_phase1,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

// Phase 1 suites: untextured primitives.
#include "triangle-edges.c"
#include "quad-decomposition.c"
#include "rectangle-clipping.c"
#include "draw-area.c"
