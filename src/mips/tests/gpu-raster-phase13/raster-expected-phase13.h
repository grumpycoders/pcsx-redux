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

// Phase-13 expected values. Most tests use expectedClut8Color() or
// expectedTex15Color() inline; constants below are for the
// semi-trans/mask cases where the value depends on hardware-specific
// blend math.

#include "raster-helpers.h"
#include "texture-fixtures.h"

// 15-bit semi-trans masked rect over red background (R5=31), F texel
// = vram555(0, 0, 0)|0x8000 = 0x8000 (mask bit set, R/G/B = 0).
// F8 channels: R=0, G=0, B=0. B8 channels: R=248, G=0, B=0.
// All output pixels carry bit-15 due to texel-mask propagation.
//
// ABR=0: (248+0)/2=124 -> R5=15. Output = 0x000f | 0x8000 = 0x800f
// ABR=1: 248+0=248 -> R5=31. Output = 0x001f | 0x8000 = 0x801f
// ABR=2: 248-0=248 -> R5=31. Output = 0x001f | 0x8000 = 0x801f
// ABR=3: 248+0=248 -> R5=31. Output = 0x001f | 0x8000 = 0x801f
#define TR15_SEMI_ABR0_BLEND   0x800fu
#define TR15_SEMI_ABR1_BLEND   0x801fu
#define TR15_SEMI_ABR2_BLEND   0x801fu
#define TR15_SEMI_ABR3_BLEND   0x801fu

// 8-bit set-mask textured rect: CLUT8[0] = vram555(0, 31, 0) = 0x03e0.
// E6 set-mask forces bit 15 on output -> 0x03e0 | 0x8000 = 0x83e0.
#define TR8_SETMASK_OUTPUT     0x83e0u

// 15-bit check-mask: pre-fill (R5=8) | 0x8000 survives = 0x0008 | 0x8000 = 0x8008.
#define TR15_CHECKMASK_PREFILL 0x8008u
