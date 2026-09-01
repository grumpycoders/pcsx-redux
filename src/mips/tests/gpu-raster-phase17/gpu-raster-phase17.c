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

// PS1 GPU rasterizer edge-behavior characterization suite, phase 17.
//
// Affine UV mapping under arbitrary-shape triangles and quads. PS1 has
// no perspective correction; UV interpolates linearly in screen space,
// and that linear interpolation is the characteristic "PS1 texture
// warp." Prior phases covered axis-aligned-UV cases (phase-4
// triangles, phase-8 quads with a single parallelogram family). This
// phase exercises:
//
//   1. UV rotations relative to screen (90 degrees, 45 degrees, mixed)
//   2. UV-vs-screen scale ratios (compressed, 1:1, stretched)
//   3. Geometries where cross-span UV step dominates vs row edge step
//   4. Arbitrary quads (trapezoids, non-parallelograms) where two-
//      triangle decomposition must match hardware-native triangle
//      interpolation across the seam
//
// The phase-8 work surfaced a dual-mechanism bias bug in the 4-vert
// flat-textured path. Phase 17 widens the net: the triangle suite
// stresses the 3-vert sampler at arbitrary shapes, and the quad suite
// validates whether (1,3,2)+(0,1,2) decomposition matches hardware
// against the parallelogram-seam class (phase-8 found one seam-gap
// pixel on QFD; non-rectangular quads may have more).
//
// Texture: a dedicated 32x32 15-bit signature texture in a fresh
// texpage cell (TX=11). Encoding texel(u, v) = vram555(u, v,
// ((u+v)&31)|1) so every (u, v) has a unique (red, green) signature
// and no texel collapses to the transparent 0x0000 cell. See
// texture-fixture-phase17.h.

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
#include "raster-expected-phase17.h"

CESTER_BODY(
static int s_interruptsWereEnabled;
)

CESTER_BEFORE_ALL(gpu_raster_phase17,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
    rasterFullReset();

    /* Upload the phase-17 signature texture once. Lives at texpage
       cell (TX=11, TY=0) so it does not collide with phase-4/phase-8
       fixtures. */
    uploadTex17();
)

CESTER_AFTER_ALL(gpu_raster_phase17,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "affine-triangles.c"
#include "affine-quads.c"
