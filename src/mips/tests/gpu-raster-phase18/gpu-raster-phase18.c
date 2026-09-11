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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 18.
//
// Affine UV stride-magnitude diagnostic. Phase-17 found that hardware
// applies a +0x8000 (half-LSB in 16.16) bias before the floor-to-int
// step, and that some failing probes in phase-17 deviate from this
// rule depending on the |dU/dx| / |dV/dy| magnitude. Phase-18 isolates
// that variable: six triangles, identical screen footprint, single
// parameter K controlling the per-axis UV stride. Probes at the same
// screen positions across all K let the hardware data plot directly
// as "(u, v) sampled vs K", revealing which bias model the GPU
// implements.
//
//   T_AXIS_K:  A=(5, 5)/(0, 0)  B=(15, 5)/(K, 0)  C=(5, 15)/(0, K)
//   K in {1, 2, 3, 5, 8, 16}
//
// Axis-aligned UV (no cross-axis stride), equal per-axis magnitude
// so the same probe value validates both the U and V samplers under
// the same K. Cross-axis and negative-stride variants are deferred
// to phase-19 to keep this binary inside cester's per-failure
// memory budget.
//
// Five probes per K, 30 tests total:
//   P_VERTEX     (5, 5)   - vertex A, UV(0, 0)
//   P_TOP_NEAR   (6, 5)   - top edge one step from A, UV(K/10, 0)
//   P_LEFT_NEAR  (5, 6)   - left edge one step from A, UV(0, K/10)
//   P_INTERIOR   (8, 8)   - strict interior, UV(3K/10, 3K/10)
//   P_TOP_FAR    (12, 5)  - top edge far from A, UV(7K/10, 0)
//
// Each probe location is inside the triangle for every K (the
// triangle footprint is fixed; only the vertex UV values change).
// The hypotenuse BC sits at x+y=20, all probes have x+y<=16.
//
// Texture: reuses phase-17's TEX17 32x32 15-bit signature texture
// (texpage cell tx=11, ty=0). Encoding texel(u, v) = vram555(u, v,
// ((u+v)&31)|1) means probe failures decode directly into the
// (u, v) the rasterizer sampled.

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
#include "raster-expected-phase18.h"

CESTER_BODY(
static int s_interruptsWereEnabled;
)

CESTER_BEFORE_ALL(gpu_raster_phase18,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();

    /* Reuse phase-17's TEX17 signature texture. Lives at texpage
       cell (TX=11, TY=0); 32x32 15-bit with texel(u, v) encoding
       (u, v) uniquely in red and green. */
    uploadTex17();
)

CESTER_AFTER_ALL(gpu_raster_phase18,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "stride-sweep.c"
