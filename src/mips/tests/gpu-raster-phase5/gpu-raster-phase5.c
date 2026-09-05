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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 5.
//
// Phase 5 binary covers cross-primitive mask-bit behavior:
//   - cross-primitive-mask.c  set-mask + check-mask on rectangle,
//                             line, textured rectangle, and textured
//                             triangle at all three depths.
//
// Phases 1-2 only covered untextured triangles. The audit calls out
// mask-bit semantics as embedded in pixel writers, which differ per
// primitive type - so cross-primitive coverage matters for the
// writer-policy refactor track.

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

CESTER_BODY(
static int s_interruptsWereEnabled;
)

CESTER_BEFORE_ALL(gpu_raster_phase5,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();
    uploadAllTextureFixtures();

    ramsyscall_printf("\n=== gpu-raster-phase5: cross-primitive mask-bit ===\n");
    ramsyscall_printf("Grep '^OBS' to capture hardware-truth values.\n\n");
)

CESTER_AFTER_ALL(gpu_raster_phase5,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "cross-primitive-mask.c"
