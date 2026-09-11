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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 20.
//
// Affine UV row-walk drift diagnostic. Phases 17-19 cover bias model
// across magnitude, sign, and cross-axis terms. Phase 20 asks the
// remaining diagnostic question: does the V accumulator drift over
// long Y traversal?
//
// In a 16.16 fixed-point edge walker, each row step adds `dV/dy` to
// the V accumulator. If the per-step value rounds, the rounding
// error can accumulate over many rows. Phases 17-19 walked at most
// 10 rows; phase 20 walks 15 rows and probes V at six Y positions
// to surface any drift.
//
// Triangle T_LONG_K is tall (20 rows), same 10-pixel screen width
// as phase-18 so per-axis stride dU/dx = dV/dy = K/10 is preserved
// and probe values are directly comparable to phase-18:
//
//   A=(5,  5)/(0, 0)  B=(15, 5)/(K, 0)  C=(5, 25)/(0, 2K)
//
// Six probes at x=7 (column 2 from the left edge, fixed under the
// vertical AC edge so row-start X is integer for every row), Y at
// 5, 8, 11, 14, 17, 20. K in {1, 3, 5, 8, 16}. 30 tests total.
//
// Bias model under test (phases 17-19 HARDWARE_VERIFIED):
//   u_sampled = floor(u_real(x, y) + 0.5)  per axis, uniform.
// Predictions seeded under that model. If row-walk drift exists,
// deep probes (y=14, 17, 20) deviate from the model while shallow
// probes (y=5, 8) pass.

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
#include "texture-fixture-phase17.h"
#include "raster-expected-phase20.h"

CESTER_BODY(
static int s_interruptsWereEnabled;
)

CESTER_BEFORE_ALL(gpu_raster_phase20,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();

    uploadTex17();
)

CESTER_AFTER_ALL(gpu_raster_phase20,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "row-walk-drift.c"
