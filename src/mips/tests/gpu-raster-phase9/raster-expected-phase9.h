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

#pragma once

// Phase-9 expected hardware-truth values for 8-bit and 15-bit
// texture-window probes. 8-bit tests use expectedClut8Color() inline
// (the CLUT lookup is deterministic from u) so no constants needed
// for them. 15-bit values are precomputed below for cester's macro
// expansion at compile time.
//
// 15-bit texel(u, v) = vram555(u & 0x1f, v & 0x1f, (u + v) & 0x1f).
// At y=0 (so v=0), filtered_u is what matters: vram555(filtered_u,
// 0, filtered_u) = filtered_u | (filtered_u << 10).

#include "raster-helpers.h"
#include "texture-fixtures.h"

// mask_u = 0x01, offset_u = 0 -> bit 3 cleared
//
// HARDWARE FINDING (verified 2026-05-16): texel value 0x0000 in
// textured primitives is treated as TRANSPARENT on PS1 hardware - the
// rasterizer skips the pixel write entirely and the underlying VRAM
// shows through. So filtered_u=0 (which would produce vram555(0,0,0)
// = 0x0000) reads back as sentinel, not 0x0000. This is the PS1's
// "transparent black" texture quirk.
#define TW15_M01_O00_U0_Y0    RASTER_SENTINEL  /* filtered=0 -> texel 0x0000 = transparent */
#define TW15_M01_O00_U7_Y0    0x1c07u          /* filtered=7 -> vram555(7,0,7) */
#define TW15_M01_O00_U8_Y0    RASTER_SENTINEL  /* filtered=0 -> texel 0x0000 = transparent */
#define TW15_M01_O00_U15_Y0   0x1c07u          /* filtered=7 -> vram555(7,0,7) */

// mask_u = 0x01, offset_u = 0x01 -> bit 3 forced set
#define TW15_M01_O01_U0_Y0    0x2008u  /* filtered=8  -> vram555(8,0,8) */
#define TW15_M01_O01_U3_Y0    0x2c0bu  /* filtered=11 -> vram555(11,0,11) */
#define TW15_M01_O01_U8_Y0    0x2008u  /* filtered=8  -> vram555(8,0,8) */

// mask_u = 0x03, offset_u = 0 -> bits 3,4 cleared
#define TW15_M03_O00_U13_Y0   0x1405u  /* filtered=5  -> vram555(5,0,5) */
