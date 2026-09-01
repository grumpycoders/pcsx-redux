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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 6.
//
// Edge-walker integer-division precision oracle. Probes configurations
// where soft.cc's `m_deltaRightX = ((v2->x - v1->x) << 16) / height`
// truncation lands at integer-rightX boundary rows, plus integer-
// shifted variants of the same shape. Refactor-unblocking - the
// Phase 4 thread flagged this precision question and needs the oracle.

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

CESTER_BODY(
static int s_interruptsWereEnabled;
)

CESTER_BEFORE_ALL(gpu_raster_phase6,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();

    ramsyscall_printf("\n=== gpu-raster-phase6: edge-walker precision ===\n");
    ramsyscall_printf("Grep '^OBS' to capture hardware-truth values.\n\n");
)

CESTER_AFTER_ALL(gpu_raster_phase6,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "edge-walker-precision.c"
