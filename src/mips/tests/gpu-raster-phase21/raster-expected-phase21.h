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

// Phase-21 expected values.
//
// Every probe samples the fixture texel(u,v) = (u+v)&0xff through CLUT8,
// so the expectation for a sample at primitive-offset k from base UV b is
// always expectedClut8Color((b + k) & 0xff) - the assertions compute that
// inline rather than hard-coding constants, because the whole point of the
// test is the `& 0xff`: in-range offsets are the control, offsets >= 256
// are the wrap.
//
// HARDWARE TRUTH (to confirm against silicon OBS on first run):
// The PS1 texel-fetch U/V coordinate is 8-bit, so an oversized primitive's
// per-pixel coordinate counter wraps mod 256 - the texture tiles. This is
// distinct from phase-16's finding that U does NOT wrap at the depth-
// dependent texpage *extent* (128 texels for 8-bit): that boundary sits
// below 256 and is a valid 8-bit address that reads adjacent VRAM
// linearly. The 256 boundary here is the coordinate width itself
// overflowing, which truncates to 8 bits. The two are consistent: linear
// across 0..255, wrap at 256.
//
// If silicon disagrees (OBS shows the >=256 columns/rows reading adjacent
// VRAM instead of the wrapped texel), the soft-GPU sampler's 8-bit mask is
// wrong and this header gets explicit override constants for the affected
// probes. As of authoring, no overrides are needed.

#include "raster-helpers.h"
#include "texture-fixtures.h"
