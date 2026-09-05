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

// Phase-12 expected ABR blend values. Predictions below use the
// documented psx-spx 8-bit-space formulas:
//   ABR=0: out8 = (B8 + F8) / 2
//   ABR=1: out8 = min(B8 + F8, 255)
//   ABR=2: out8 = max(B8 - F8, 0)
//   ABR=3: out8 = min(B8 + F8/4, 255)
// out5 = out8 >> 3. B8 = B5 << 3 (re-expanded from 5-bit). F8 = F5
// << 3 (the command-color is sent at 5-bit-boundary alignment by
// cmdR5() so F8 = F5 * 8 exactly).
//
// All placeholders HW_TODO; first hardware run captures truth.

#include "raster-helpers.h"

// VRAM 5:5:5 helper for R-only outputs: vram555(R, 0, 0) = R.
#define VR(r5) ((uint16_t)((r5) & 0x1fu))

// ============================================================================
// ABR=0 (B/2 + F/2): out5 = ((B5+F5) >> 1) approximately
// At B5=16, F5=16: out8 = (128+128)/2 = 128 -> out5=16 = 0x10
// At B5=16, F5=31: out8 = (128+248)/2 = 188 -> out5=23 = 0x17
// ============================================================================

#define ABR0_B00_F00   VR(0)   /* (0+0)/2 = 0   -> R5=0  */
#define ABR0_B00_F16   VR(8)   /* (0+128)/2 = 64 -> R5=8 */
#define ABR0_B00_F31   VR(15)  /* (0+248)/2 = 124 -> R5=15 */
#define ABR0_B16_F00   VR(8)   /* (128+0)/2 = 64 -> R5=8 */
#define ABR0_B16_F16   VR(16)  /* (128+128)/2 = 128 -> R5=16 */
#define ABR0_B16_F31   VR(23)  /* (128+248)/2 = 188 -> R5=23 */
#define ABR0_B31_F00   VR(15)  /* (248+0)/2 = 124 -> R5=15 */
#define ABR0_B31_F16   VR(23)  /* (248+128)/2 = 188 -> R5=23 */
#define ABR0_B31_F31   VR(31)  /* (248+248)/2 = 248 -> R5=31 */

// ============================================================================
// ABR=1 (B + F, clamped): out8 = min(B8+F8, 255)
// ============================================================================

#define ABR1_B00_F00   VR(0)
#define ABR1_B00_F16   VR(16)  /* 0+128=128 -> R5=16 */
#define ABR1_B00_F31   VR(31)  /* 0+248=248 -> R5=31 */
#define ABR1_B16_F00   VR(16)
#define ABR1_B16_F16   VR(31)  /* 128+128=256 -> clamp 255 -> R5=31 */
#define ABR1_B16_F31   VR(31)  /* 128+248=376 -> clamp -> R5=31 */
#define ABR1_B31_F00   VR(31)
#define ABR1_B31_F16   VR(31)
#define ABR1_B31_F31   VR(31)  /* sat */

// ============================================================================
// ABR=2 (B - F, clamped at 0): out8 = max(B8-F8, 0)
// ============================================================================

#define ABR2_B00_F00   VR(0)
#define ABR2_B00_F16   VR(0)   /* 0-128=-128 -> clamp 0 */
#define ABR2_B00_F31   VR(0)
#define ABR2_B16_F00   VR(16)  /* 128-0=128 -> R5=16 */
#define ABR2_B16_F16   VR(0)   /* 128-128=0 -> R5=0 */
#define ABR2_B16_F31   VR(0)   /* 128-248=-120 -> 0 */
#define ABR2_B31_F00   VR(31)
#define ABR2_B31_F16   VR(15)  /* 248-128=120 -> R5=15 */
#define ABR2_B31_F31   VR(0)   /* 248-248=0 */

// ============================================================================
// ABR=3 (B + F/4, clamped): out8 = min(B8 + (F8 >> 2), 255)
// ============================================================================

#define ABR3_B00_F00   VR(0)
#define ABR3_B00_F16   VR(4)   /* 0 + 128/4 = 32 -> R5=4 */
#define ABR3_B00_F31   VR(7)   /* 0 + 248/4 = 62 -> R5=7 */
#define ABR3_B16_F00   VR(16)
#define ABR3_B16_F16   VR(20)  /* 128 + 32 = 160 -> R5=20 */
#define ABR3_B16_F31   VR(23)  /* 128 + 62 = 190 -> R5=23 */
#define ABR3_B31_F00   VR(31)
#define ABR3_B31_F16   VR(31)  /* 248 + 32 = 280 -> clamp 255 -> R5=31 */
#define ABR3_B31_F31   VR(31)  /* sat */

// ============================================================================
// ABR_PRIM: same blend math across quad / rect / line at (B=16, F=16)
// ============================================================================

#define ABR0_PRIM_QUAD  ABR0_B16_F16
#define ABR1_PRIM_QUAD  ABR1_B16_F16
#define ABR2_PRIM_QUAD  ABR2_B16_F16
#define ABR3_PRIM_QUAD  ABR3_B16_F16

#define ABR0_PRIM_RECT  ABR0_B16_F16
#define ABR1_PRIM_RECT  ABR1_B16_F16
#define ABR2_PRIM_RECT  ABR2_B16_F16
#define ABR3_PRIM_RECT  ABR3_B16_F16

#define ABR0_PRIM_LINE  ABR0_B16_F16
#define ABR1_PRIM_LINE  ABR1_B16_F16
#define ABR2_PRIM_LINE  ABR2_B16_F16
#define ABR3_PRIM_LINE  ABR3_B16_F16

// ============================================================================
// ABR_TEX_MASKED: textured tri sampling CLUT4[4] = vram555(4, 27, 0) | 0x8000.
// F = (R=4, G=27, B=0) after modulation (neutral). B = (R=16, G=0, B=0).
// R-channel blend math for each ABR:
//   ABR=0: (B_R + F_R)/2 = (16+4)/2 = 10 -> R5=1 (in 8-bit: (128+32)/2 = 80 -> R5=10)
//   Actually F8=4*8=32, B8=16*8=128. (128+32)/2 = 80 -> R5 = 80>>3 = 10.
//   ABR=1: 128+32 = 160 -> R5=20.
//   ABR=2: 128-32 = 96 -> R5=12.
//   ABR=3: 128 + 32/4 = 136 -> R5=17.
// G-channel: B_G=0, F_G=27*8=216.
//   ABR=0: (0+216)/2 = 108 -> G5=13. Output bits: 13<<5 = 0x01A0.
//   Hmm, but B=16 in our pre-fill is R-only (G8=0, B8=0). So the G/B
//   channels start at 0. The texture brings G=27 and B=0 into the
//   mix. Predict each channel separately and compose. This gets
//   complex; HW_TODO placeholders + capture truth.
// ============================================================================

// HARDWARE FINDING (verified 2026-05-16): the texel's bit-15 mask is
// preserved into VRAM even WITHOUT E6 set-mask enabled. Texture-side
// mask-bit propagates through the semi-trans blend - hardware writes
// the blended value with bit-15 = (mask bit of sampled texel). All
// four textured semi-trans outputs below carry the 0x8000 mask bit.
// The R/G/B channel math matches the documented blend formulas:
//   ABR=0: B/2 + F/2  (R=10, G=13, B=0)
//   ABR=1: B + F      (R=20, G=27, B=0)
//   ABR=2: B - F      (R=12, G=0,  B=0)
//   ABR=3: B + F/4    (R=17, G=6,  B=0)
// (B=R5=16 / G5=0 / B5=0 background; F=R5=4 / G5=27 / B5=0 texel.)
#define ABR0_TEX_MASKED   0x81aau  /* (R=10, G=13, B=0) | mask */
#define ABR1_TEX_MASKED   0x8374u  /* (R=20, G=27, B=0) | mask */
#define ABR2_TEX_MASKED   0x800cu  /* (R=12, G=0,  B=0) | mask */
#define ABR3_TEX_MASKED   0x80d1u  /* (R=17, G=6,  B=0) | mask */

// ============================================================================
// ABR_SETMASK: blended value with bit-15 OR'd in.
// (B16, F16, ABR=*) blend per above, then | 0x8000.
// ============================================================================

#define ABR0_SETMASK   (VR(16) | 0x8000u)  /* 0x10 | 0x8000 = 0x8010 */
#define ABR1_SETMASK   (VR(31) | 0x8000u)  /* sat */
#define ABR2_SETMASK   (VR(0)  | 0x8000u)
#define ABR3_SETMASK   (VR(20) | 0x8000u)

// ============================================================================
// ABR_CHECKMASK: pre-fill has bit-15 set, so writes are skipped. The
// pre-fill value (B_R = 16, with bit-15 set) survives untouched.
// ============================================================================

#define ABR0_CHECKMASK   (VR(16) | 0x8000u)
#define ABR1_CHECKMASK   (VR(16) | 0x8000u)
#define ABR2_CHECKMASK   (VR(16) | 0x8000u)
#define ABR3_CHECKMASK   (VR(16) | 0x8000u)
