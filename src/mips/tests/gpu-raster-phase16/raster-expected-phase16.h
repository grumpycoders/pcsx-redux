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

// Phase-16 expected values. Off-page U values land in undefined VRAM
// regions outside the fixture pages; hardware truth gets captured on
// first run. The captured values tell us whether hardware wraps mod
// page-width or extends into adjacent VRAM.

#include "raster-helpers.h"
#include "texture-fixtures.h"

// 8-bit: page width = 128 in texel coords. Above 127 is off-page
// per psx-spx documentation.
//
// HARDWARE FINDING (verified 2026-05-16): U does NOT wrap at the
// documented page boundary. Hardware reads linearly into adjacent
// VRAM. With the full TEX8 fixture spanning u=0..255 (128 VRAM
// pixels wide starting at x=576), u=128 reads VRAM (640, 0) which
// is just past the 8-bit page extent but still produces a defined
// byte value (overlap with the TEX15 fixture's data).
//
// Values captured below are the byte content at the sampled VRAM
// position, looked up through CLUT8. They confirm hardware does
// not apply any modular wrap on U at the texpage boundary.
//
// psx-spx note worth filing: the "wrap within the page" claim
// doesn't match hardware. The behaviour is "read whatever VRAM
// byte the linear U offset addresses."
#define UV8_U128_V0  0x03e0u  /* reads beyond 128-texel page */
#define UV8_U200_V0  0x0364u
#define UV8_U255_V0  0x0c7cu
#define UV8_U0_V255  0x1c1fu  /* beyond TEX8 v-extent */

// 15-bit: page width = 64. Off-page samples land in uninitialised
// VRAM beyond the fixture upload. Hardware returns whatever value
// happens to be there (which in our tests coincidentally matches
// the test-region sentinel pre-fill 0xDEAD).
#define UV15_U64_V0  RASTER_SENTINEL  /* beyond TEX15 upload */
#define UV15_U128_V0 RASTER_SENTINEL  /* deep off-page */
#define UV15_U255_V0 RASTER_SENTINEL  /* deep off-page */

// 4-bit: page width = 256. Outside the 16-texel fixture pattern
// (u > 15) but still within page. Hardware samples VRAM with
// whatever it finds there.
#define UV4_U16_V0   0x0364u
#define UV4_U255_V0  0x03e0u
