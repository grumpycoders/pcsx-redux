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

// Phase-15 expected values. Most mask×offset tests use inline
// expectedClut8Color() predictions; the macros below cover the
// semi-trans and bit-15-transparency interaction cases where hardware
// truth gets locked in on first run.

#include "raster-helpers.h"
#include "texture-fixtures.h"

// Window × semi-trans with bit-15=0 CLUT entries. Phase-8 polygon
// finding said bit-15=0 -> no blend; phase-13 confirmed same for rect.
// Texel sampled = CLUT8[0] = vram555(0, 31, 0) = 0x03e0 (windowed
// from u=8 via mask_u=0x01).
#define WS_WINDOW_SEMI_NO_BLEND   0x03e0u

// HARDWARE FINDING (verified 2026-05-16): the bit-15 transparency
// gate fires on the WINDOWED texel value, NOT the unfiltered raw u
// value. Window collapses x=8 (and x=0) to filtered_u=0; CLUT8[0]
// has bit-15 set in this test fixture, so the gate fires and ABR
// blend applies. Output = blend of bg (red) and CLUT8[0] (now
// transparent green) at ABR=0:
//   B = vram555(31, 0, 0), F = vram555(0, 31, 0) | 0x8000
//   B8 = (248, 0, 0), F8 = (0, 248, 0)
//   ABR=0: ((248+0)/2, (0+248)/2, 0) = (124, 124, 0) -> (R5=15, G5=15)
//   bit-15 propagated from texel -> output = 0x81ef
// Same result at x=0 (the window collapses both to filtered_u=0).
//
// Implication: the soft renderer's textured rect path must apply
// E2 windowing BEFORE the bit-15 transparency check. A renderer
// that checks bit-15 on the raw u value would miss the gate firing
// here (CLUT8[8] has bit-15=0, would skip blend) and produce wrong
// output.
#define WX_WINDOW_TRANS_ABR0      0x81efu  /* gate fires on windowed CLUT8[0] */
#define WX_WINDOW_TRANS_X0        0x81efu  /* same value: x=0 windows to filtered=0 */

// Out-of-fixture-range window tests. Filtered_u lands beyond the
// 64-byte uploaded TEX8 region; hardware samples whatever VRAM
// contains there. Locking in for regression - not a window-formula
// finding, an artefact of the fixture upload size.
#define WT_MASK0F_OFF0F_X0_HW     0x03e0u  /* HW captured: reads 0 at u=120 */
#define WT_MASK1F_OFF1F_X0_HW     0x007cu  /* HW captured: reads 124 at u=248 */
