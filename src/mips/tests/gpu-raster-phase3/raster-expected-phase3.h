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

// Phase-3 expected hardware-truth values for edge-walker stress tests.
//
// Edge-walker characterization: the soft renderer's setupSections* /
// nextRow* family handles scanline conversion using 16.16 fixed-point
// edge slopes. The audit flagged rounding and longest-edge handling as
// load-bearing for the Phase 4 refactor (soft.cc:1239-1747). Phase-3
// probes specific configurations the audit cited: near-vertical
// degenerate triangles, near-horizontal degenerates, longest-edge
// boundary cases, and slope-fraction sweeps.
//
// Same workflow as phase-1: best-guess placeholders tagged HW_TODO; run
// on hardware via Unirom + psxup.py, grep `^OBS` from the captured log
// for ground truth, patch macros, commit.

#include "raster-helpers.h"

// --------------------------------------------------------------------------
// Near-vertical degenerate triangles (height >> width)
// --------------------------------------------------------------------------
//
// NV1: vertices (0, 0), (1, 0), (0, 10). Height 10, top-row width 1.
// Top-left rule: each y row covers x in [0, right(y)) where right(y)
// linearly interpolates from 1 at y=0 to 0 at y=10. Right(y) crosses
// integer thresholds at multiples of 10. So:
//   y=0: right=1.0, x range [0, 1) -> x=0 only
//   y=1: right=0.9, x range [0, 1) -> x=0 only (Bresenham floor(0.9)=0)
//   y=2..8: same, x=0
//   y=9: right=0.1, x range [0, 1) -> x=0 if rasterizer keeps narrow,
//                                     empty if it drops
//   y=10: bottom edge excluded
// Best-guess: full column x=0 drawn from y=0 to y=9 inclusive.

#define EXPECT_NV1_PIXEL_0_0    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 */
#define EXPECT_NV1_PIXEL_0_5    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 mid-column */
#define EXPECT_NV1_PIXEL_0_9    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 last row */
#define EXPECT_NV1_PIXEL_0_10   RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 bottom excluded */
#define EXPECT_NV1_PIXEL_1_0    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 right edge excluded */

// NV2: vertices (0, 0), (2, 10), (0, 10). Right edge has slope 5
// (10y per 2x). Each row y has right(y) = 2*y/10 = y/5.
//   y=0: right=0.0 -> empty row (single-pixel-or-empty edge case, audit cousin)
//   y=1: right=0.2 -> x=0 if keep-narrow else empty
//   y=5: right=1.0 -> x=0 only
//   y=9: right=1.8 -> x=0..1
//   y=10: bottom excluded
// Audit's xmax==xmin top-row case settled: hardware drops it. So y=0
// should be sentinel; y=1 also if Bresenham floor gives right<1.

#define EXPECT_NV2_PIXEL_0_0    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 top-row apex dropped */
#define EXPECT_NV2_PIXEL_0_1    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 narrow row KEPT (not just top-row) */
#define EXPECT_NV2_PIXEL_0_5    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 mid */
#define EXPECT_NV2_PIXEL_0_9    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 */
#define EXPECT_NV2_PIXEL_1_9    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 widest row */
#define EXPECT_NV2_PIXEL_2_9    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 right edge */

// NV3: 1px wide all the way down. (5, 0), (6, 0), (5, 20). Slope 0
// right edge (vertical). Right edge x=6 ALWAYS, so each row's span is
// [5, 6) -> x=5 only.

#define EXPECT_NV3_PIXEL_5_0    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 */
#define EXPECT_NV3_PIXEL_5_10   RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 */
#define EXPECT_NV3_PIXEL_5_19   RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 last row */
#define EXPECT_NV3_PIXEL_5_20   RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 bottom */
#define EXPECT_NV3_PIXEL_6_0    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 right edge */
#define EXPECT_NV3_PIXEL_4_0    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 before left */

// --------------------------------------------------------------------------
// Near-horizontal degenerate triangles (width >> height)
// --------------------------------------------------------------------------
//
// NH1: vertices (0, 0), (20, 0), (0, 1). Width 20, height 1.
//   y=0: full span x in [0, 20) drawn
//   y=1: bottom excluded
#define EXPECT_NH1_PIXEL_0_0    RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_NH1_PIXEL_10_0   RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_NH1_PIXEL_19_0   RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 last x */
#define EXPECT_NH1_PIXEL_20_0   RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 right edge */
#define EXPECT_NH1_PIXEL_0_1    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 bottom */

// NH2: (0, 0), (20, 1), (0, 1). Width 20, height 1, right edge slopes
// upward from x=20 at y=0... wait, that vertex order has bottom-right
// at (20,1) so right edge is the diagonal. At y=0 right=0 (apex);
// y=1 bottom excluded. Triangle is effectively zero-fill or one-row
// sliver depending on convention.
#define EXPECT_NH2_PIXEL_0_0    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 top-row apex */
#define EXPECT_NH2_PIXEL_10_0   RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 */

// NH3: (0, 0), (40, 0), (20, 1). Top edge length 40, height 1.
// Triangle is a sliver one row thick. y=0 should fill full top edge
// per top-left rule; y=1 excluded.
#define EXPECT_NH3_PIXEL_0_0    RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_NH3_PIXEL_20_0   RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_NH3_PIXEL_39_0   RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 last x */
#define EXPECT_NH3_PIXEL_40_0   RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 right vertex */
#define EXPECT_NH3_PIXEL_20_1   RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 bottom */

// --------------------------------------------------------------------------
// Longest-edge boundary triangles
// --------------------------------------------------------------------------
//
// LE1: roughly-equilateral triangle where edge lengths are within 1 of
// each other. (0, 0), (10, 0), (5, 9). Edge lengths approx 10, 10.3,
// 10.3 (left/right hypotenuses). soft.cc's `longest` choice could swap
// which edge gets the dx > 0 convention.
#define EXPECT_LE1_PIXEL_0_0    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 top-left corner */
#define EXPECT_LE1_PIXEL_5_4    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 interior */
#define EXPECT_LE1_PIXEL_9_0    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 right end of top edge */
#define EXPECT_LE1_PIXEL_10_0   RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 right-vertex top */
#define EXPECT_LE1_PIXEL_5_9    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 apex - bottom convention */

// LE2: triangle where the top edge IS the longest. (0, 0), (20, 0),
// (10, 5). Top edge length 20, side edges ~11.2 each. Top edge sweeps
// horizontally only; sides have moderate slope.
#define EXPECT_LE2_PIXEL_0_0    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 */
#define EXPECT_LE2_PIXEL_19_0   RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 right end of top edge */
#define EXPECT_LE2_PIXEL_10_4   RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 near apex */
#define EXPECT_LE2_PIXEL_10_5   RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 apex - bottom convention */

// LE3: triangle where a side is much longer than top. (0, 0), (3, 0),
// (10, 20). Right edge length ~20.6, top 3, left ~22.4. Left is
// longest. This stresses asymmetric edge-walker setup.
#define EXPECT_LE3_PIXEL_0_0    RASTER_VRAM_WHITE  /* HW_VERIFIED 2026-05-15 */
#define EXPECT_LE3_PIXEL_2_0    RASTER_VRAM_WHITE  /* HW_VERIFIED 2026-05-15 last x on top */
#define EXPECT_LE3_PIXEL_3_0    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 right-vertex of top */
#define EXPECT_LE3_PIXEL_5_10   RASTER_VRAM_WHITE  /* HW_VERIFIED 2026-05-15 mid-interior */
#define EXPECT_LE3_PIXEL_10_20  RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 apex */

// --------------------------------------------------------------------------
// Slope-fraction sweep (sub-pixel accumulator characterization)
// --------------------------------------------------------------------------
//
// SF1: slope 1/3 - right edge moves 1 x per 3 y. (0, 0), (3, 0), (0, 9).
// Right(y) = 3 - y/3.
//   y=0: right=3, x=0..2
//   y=1: right=2.667, x=0..2 (Bresenham floor; or 0..1 if drop-narrow)
//   y=2: right=2.333, x=0..2 (or 0..1)
//   y=3: right=2.0, x=0..1
//   y=4: right=1.667, x=0..1 (or 0..0)
//   y=5: right=1.333, x=0..1 (or 0..0)
//   y=6: right=1.0, x=0..0
//   y=7: right=0.667, x=0 (or empty)
//   y=8: right=0.333, x=0 (or empty)
//   y=9: bottom excluded
//
// Audit settled: xmax==xmin spans get DROPPED. So when right(y) < 1
// AND xmin==xmax==0, the pixel is dropped. y=7,8 likely empty.
#define EXPECT_SF1_PIXEL_0_0    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 */
#define EXPECT_SF1_PIXEL_2_0    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 last x top */
#define EXPECT_SF1_PIXEL_2_1    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 fractional right */
#define EXPECT_SF1_PIXEL_2_2    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 */
#define EXPECT_SF1_PIXEL_2_3    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 right=2 exact, x=2 excluded */
#define EXPECT_SF1_PIXEL_1_3    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 */
#define EXPECT_SF1_PIXEL_1_6    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 right=1 exact, x=1 excluded */
#define EXPECT_SF1_PIXEL_0_6    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 */
#define EXPECT_SF1_PIXEL_0_7    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 narrow rows are KEPT past the apex */
#define EXPECT_SF1_PIXEL_0_8    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 same */

// SF2: slope 1/5 - (0, 0), (1, 0), (0, 5). Width 1, height 5.
// Right(y) = 1 - y/5. Span (0, right(y)). At y=0 span [0,1) -> x=0 only.
// All rows have xmax==xmin==0 except y=0 where right=1 (xmax=1 - 1 = 0
// per slow-path xmax rule, which we settled as canonical).
//
// All five rows should DROP per the xmax==xmin verdict.
// Hardware reality: a 1-pixel-wide triangle KEEPS every row. The
// xmax==xmin apex-drop only fires at the TOP row when right==0
// (genuine zero-width starting condition). Subsequent rows with
// right=1 (=> right>>16 produces 0 or 1) are drawn.
#define EXPECT_SF2_PIXEL_0_0    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 1px column kept */
#define EXPECT_SF2_PIXEL_0_1    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 */
#define EXPECT_SF2_PIXEL_0_4    RASTER_VRAM_RED    /* HW_VERIFIED 2026-05-15 */

// SF3: slope 3/7 - (0, 0), (3, 0), (0, 7). Irregular fractions. Right(y)
// = 3 - 3*y/7.
//   y=0: 3.0, span [0, 3)
//   y=1: 2.571, span [0, 2) or [0, 3)?
//   y=2: 2.143, span [0, 2)
//   y=3: 1.714, [0, 1)
//   y=4: 1.286, [0, 1)
//   y=5: 0.857, [0, 0) -> empty/xmax==xmin
//   y=6: 0.429, empty
#define EXPECT_SF3_PIXEL_0_0    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 */
#define EXPECT_SF3_PIXEL_2_0    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 */
#define EXPECT_SF3_PIXEL_2_1    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 interpolated edge */
#define EXPECT_SF3_PIXEL_2_2    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 right=2.143 -> x=2 KEPT */
#define EXPECT_SF3_PIXEL_1_2    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 */
#define EXPECT_SF3_PIXEL_0_3    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 */
#define EXPECT_SF3_PIXEL_1_3    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 right=1.714 -> x=1 KEPT */
#define EXPECT_SF3_PIXEL_0_5    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 narrow KEPT */

// --------------------------------------------------------------------------
// 4-vertex quad sweep paths (untextured - decompose path)
// --------------------------------------------------------------------------
//
// Even untextured quads exercise the (1,3,2)+(0,1,2) decomposition order
// in setupSectionsFlat3. The two triangles share an edge at vertices 1
// and 2 - pixels on that shared edge should fill exactly once, not
// double-fill (which would be visually invisible for flat but matters
// for semi-transparent quads - not tested here, just verifying the seam
// doesn't drop).

// QS1: skewed quad (0,0), (8,0), (1,8), (9,8). Diagonal seam runs from
// vertex 1 (8,0) to vertex 2 (1,8). Pixels along that seam should be
// drawn exactly once.
#define EXPECT_QS1_PIXEL_0_0    RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 */
#define EXPECT_QS1_PIXEL_7_0    RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 top right interior */
#define EXPECT_QS1_PIXEL_8_0    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 vertex 1 - might be top-right corner */
#define EXPECT_QS1_PIXEL_4_4    RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 mid-quad on seam */
#define EXPECT_QS1_PIXEL_1_7    RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 near vertex 2 */
#define EXPECT_QS1_PIXEL_8_7    RASTER_VRAM_BLUE   /* HW_VERIFIED 2026-05-15 bottom-right interior */
#define EXPECT_QS1_PIXEL_0_7    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 outside-left of seam triangle */
#define EXPECT_QS1_PIXEL_1_8    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 bottom edge */

// QS2: parallelogram quad (0,0), (10,0), (5,10), (15,10). Side edges
// slope at the same angle. Diagonal seam goes from (10,0) to (5,10).
#define EXPECT_QS2_PIXEL_0_0    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 */
#define EXPECT_QS2_PIXEL_5_0    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 */
#define EXPECT_QS2_PIXEL_9_0    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 right-end top */
#define EXPECT_QS2_PIXEL_10_0   RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 vertex */
// Quad QS2 decomposition NOTE: (2,5) reads sentinel - the
// (1,3,2)+(0,1,2) decompose of this parallelogram has a gap on the
// shared seam at (2,5). Visible-shape interior is NOT identical to
// the two-triangle union for parallelogram inputs. This is a hardware
// quirk worth flagging to the refactor.
#define EXPECT_QS2_PIXEL_2_5    RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 seam gap */
#define EXPECT_QS2_PIXEL_12_5   RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 mid-right interior */
#define EXPECT_QS2_PIXEL_5_9    RASTER_VRAM_GREEN  /* HW_VERIFIED 2026-05-15 near vertex 2 */
#define EXPECT_QS2_PIXEL_5_10   RASTER_SENTINEL    /* HW_VERIFIED 2026-05-15 bottom */
