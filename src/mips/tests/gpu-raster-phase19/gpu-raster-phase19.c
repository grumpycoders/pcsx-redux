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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 19.
//
// Affine UV stride-sign + cross-axis diagnostic. Phase-18 confirmed
// the +0x8000 half-LSB bias is uniform across per-axis stride
// magnitude when the stride is positive and axis-aligned. Phase-19
// asks two follow-up questions hardware needs to answer before the
// rasterizer fix can be designed:
//
//   Q1. Does the bias apply symmetrically to NEGATIVE stride
//       (mirrored UV walks)?
//   Q2. Does the bias apply per-axis independently when stride is
//       CROSS-AXIS (rotated UV, dU/dy != 0 or dV/dx != 0)?
//
// Six triangle families, identical 10x10 screen footprint to phase-18
// so the same probe positions (vertex, top-near, left-near, interior,
// top-far) re-use the bias-axis discrimination:
//
//   T_NEG_U_K05:    dU/dx = -0.5  (negative U stride, mild)
//   T_NEG_V_K05:    dV/dy = -0.5  (negative V stride, mild)
//   T_NEG_BOTH_K05: dU/dx = -0.5, dV/dy = -0.5  (both negative)
//   T_NEG_U_K16:    dU/dx = -1.6  (negative U stride, stretched)
//   T_CROSS_45_K05: 45-degree UV rotation, mild
//   T_CROSS_90_K16: 90-degree UV rotation, stretched (dU/dy = dV/dx = 1.6)
//
// Each probed at 5 fixed screen positions (same as phase-18). 30
// tests total. All probes inside the triangle for every family.
// Probe predictions seeded under "uniform +0x8000 bias, independent
// per axis" - hardware run validates or surfaces deviations.

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
#include "raster-expected-phase19.h"

CESTER_BODY(
static int s_interruptsWereEnabled;
)

CESTER_BEFORE_ALL(gpu_raster_phase19,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();

    uploadTex17();
)

CESTER_AFTER_ALL(gpu_raster_phase19,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "stride-sign-cross.c"
