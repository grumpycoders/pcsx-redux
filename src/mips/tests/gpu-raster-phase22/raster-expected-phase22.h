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

// Phase-22 expected hardware-truth values for SLANTED gouraud color
// interpolation.
//
// Coverage gap closed: phase-7 characterizes gouraud color on
// AXIS-ALIGNED triangles (apex at the origin, one vertical + one
// horizontal edge). phase-3 characterizes SLANTED triangles but only
// FLAT shaded. phase-17..20 characterize SLANTED triangles but only
// TEXTURED. None of them exercises a slanted, untextured, gouraud
// triangle - where the per-row left-edge color seed lands at a
// FRACTIONAL x and the horizontal span delta both accumulate, so their
// truncations compound. That primitive is what this phase oracles.
//
// Naming: SG = Slanted Gouraud. Probe macros are SG<case>_<x>_<y>; the
// few that sit exactly on a drawn vertex are SG<case>_V<k>_<x>_<y>.
// All probes are interior or on a covered vertex - none target a
// top-left-excluded (bottom/right) vertex, which would read sentinel.
//
// Color encoding: VRAM 5:5:5 with R at bits 4:0, G at bits 9:5, B at
// bits 14:10, mask at bit 15. Values below are VRAM-side as read back
// via GP0(0xC0). Dither OFF throughout.
//
// HW_VERIFIED status:
//   All values below are silicon truth, captured by running this
//   .ps-exe on real PS1 hardware via the ps1-hwdev farm and grepping
//   the ^OBS lines (dither off; the dither-off gouraud path agrees
//   across GPU generations). The SG_AB values additionally cross-check
//   the 24 pixels independently measured during the libgouraud A/B work.

// --------------------------------------------------------------------------
// SG_AB - cross-check triangle reused from the libgouraud A/B work.
//   v0=(20,20) R=255, v1=(200,60) G=255, v2=(90,230) B=255.
//   Command colors are full 8-bit 0xFF (NOT the rasterCmdColor
//   5-bit<<3 = 0xF8 idiom the other cases use) so these probes
//   reproduce the exact triangle the 24 silicon pixels were captured
//   from. The two encode the same 5-bit channel at the vertices
//   (0xFF>>3 == 0xF8>>3 == 31) but the gouraud interpolant start value
//   differs (255 vs 248), which can move an interior pixel by the very
//   LSB this phase measures - so the cross-check must use 0xFF.
// --------------------------------------------------------------------------
#define SG_AB_26_22 0x003e
#define SG_AB_24_23 0x001f
#define SG_AB_26_23 0x003e
#define SG_AB_27_24 0x003e
#define SG_AB_30_24 0x003d
#define SG_AB_32_24 0x005d
#define SG_AB_37_24 0x007c
#define SG_AB_27_25 0x003e
#define SG_AB_32_25 0x005d
#define SG_AB_22_26 0x001f
#define SG_AB_27_26 0x003e
#define SG_AB_35_26 0x005d
#define SG_AB_25_27 0x041e
#define SG_AB_28_27 0x003d
#define SG_AB_33_27 0x005d
#define SG_AB_38_27 0x007c
#define SG_AB_41_27 0x007b
#define SG_AB_43_27 0x009b
#define SG_AB_49_27 0x00ba
#define SG_AB_28_28 0x043d
#define SG_AB_29_28 0x043d
#define SG_AB_30_28 0x043d
#define SG_AB_33_28 0x005d
#define SG_AB_49_28 0x00ba

// --------------------------------------------------------------------------
// SG1 - medium slanted RGB triangle.
//   v0=(8,4) R=31, v1=(58,22) G=31, v2=(22,52) B=31. Interior probes.
// --------------------------------------------------------------------------
#define SG1_29_26 0x294a
#define SG1_24_24 0x28ed
#define SG1_36_28 0x29c6
#define SG1_20_20 0x20b1
#define SG1_30_32 0x3926
#define SG1_40_24 0x1a46

// --------------------------------------------------------------------------
// SG2 - flatter slanted RGB triangle, apex-low.
//   v0=(40,6) R=31, v1=(70,48) G=31, v2=(6,40) B=31. v2 is a covered
//   (left) vertex - vertex-exactness probe.
// --------------------------------------------------------------------------
#define SG2_V2_6_40 0x7c00
#define SG2_39_31 0x294a
#define SG2_30_30 0x38ca
#define SG2_48_32 0x15ca
#define SG2_40_20 0x14d3
#define SG2_20_34 0x5466

// --------------------------------------------------------------------------
// SG_R - R-only slanted gradient. Apex R=31, base verts R=0. Isolates a
//   single channel's accumulator on a slanted shape.
//   v0=(6,6) R=31, v1=(54,18) R=0, v2=(18,50) R=0.
// --------------------------------------------------------------------------
#define SGR_8_8 0x001c
#define SGR_26_25 0x000a
#define SGR_16_16 0x0014
#define SGR_22_28 0x000a
#define SGR_31_20 0x000a
#define SGR_13_22 0x0012

// --------------------------------------------------------------------------
// SG3 - narrow / steep slanted triangle.
//   v0=(30,4) R=31, v1=(40,50) G=31, v2=(20,46) B=31. v2 is a covered
//   (left) vertex - vertex-exactness probe.
// --------------------------------------------------------------------------
#define SG3_V2_20_46 0x7c00
#define SG3_30_33 0x294a
#define SG3_30_22 0x18d2
#define SG3_31_40 0x2dc5
#define SG3_28_30 0x30cc
#define SG3_33_38 0x1e07
