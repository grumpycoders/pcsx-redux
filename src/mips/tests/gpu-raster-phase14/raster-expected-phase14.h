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

// Phase-14 expected values. Predictions follow psx-spx documented
// limits: per-edge dx ±1023, per-edge dy ±511. Tests at boundary +
// over-limit. HW_TODO placeholders for the textured-triangle UV-
// dependent anchor values - hardware-truth captured on first run.

#include "raster-helpers.h"
#include "texture-fixtures.h"

// ---- Triangle (GP0 0x20) ----
#define CT_TRI_DX_1023   RASTER_VRAM_RED   /* HW_TODO renders (in limit) */
#define CT_TRI_DX_1024   RASTER_SENTINEL   /* HW_TODO drop boundary */
#define CT_TRI_DX_1025   RASTER_SENTINEL   /* HW_TODO drop */
#define CT_TRI_DX_2047   RASTER_SENTINEL   /* HW_TODO drop */
#define CT_TRI_DY_511    RASTER_VRAM_RED   /* HW_TODO renders */
#define CT_TRI_DY_512    RASTER_SENTINEL   /* HW_TODO drop boundary */
#define CT_TRI_DY_513    RASTER_SENTINEL   /* HW_TODO drop */
#define CT_TRI_DY_1023   RASTER_SENTINEL   /* HW_TODO drop */

// ---- Gouraud triangle (GP0 0x30) ----
#define CT_GTRI_DX_1023  RASTER_VRAM_RED   /* HW_TODO */
#define CT_GTRI_DX_1024  RASTER_SENTINEL   /* HW_TODO */
#define CT_GTRI_DX_2047  RASTER_SENTINEL   /* HW_TODO */

// ---- Textured triangle (GP0 0x24) ----
// Anchor (5, 3) under UV interpolation across a 1023x20 triangle
// samples at near-degenerate UV. Hardware truth: 0x001f at (5, 3).
#define CT_TEXTRI_DX_1023  0x001fu          /* renders, texture sample */
#define CT_TEXTRI_DX_1024  RASTER_SENTINEL  /* drop */
#define CT_TEXTRI_DX_2047  RASTER_SENTINEL  /* drop */

// ---- Quad (GP0 0x28) ----
#define CT_QUAD_DX_1023  RASTER_VRAM_GREEN  /* HW_TODO */
#define CT_QUAD_DX_1024  RASTER_SENTINEL    /* HW_TODO */
#define CT_QUAD_DX_2047  RASTER_SENTINEL    /* HW_TODO */
#define CT_QUAD_DY_511   RASTER_VRAM_GREEN  /* HW_TODO */
#define CT_QUAD_DY_512   RASTER_SENTINEL    /* HW_TODO */

// ---- Textured quad (GP0 0x2C) ----
// Anchor (5, 3) sample. Hardware truth: 0x03e0.
#define CT_TEXQUAD_DX_1023  0x03e0u         /* renders, texture sample */
#define CT_TEXQUAD_DX_1024  RASTER_SENTINEL  /* drop */
#define CT_TEXQUAD_DX_2047  RASTER_SENTINEL  /* drop */

// ---- Line (GP0 0x40) ----
#define CT_LINE_DX_1023  RASTER_VRAM_BLUE  /* HW_TODO */
#define CT_LINE_DX_1024  RASTER_SENTINEL   /* HW_TODO */
#define CT_LINE_DX_2047  RASTER_SENTINEL   /* HW_TODO */

// ---- Variable-size rect (GP0 0x60) ----
// HARDWARE FINDING (verified 2026-05-16): the actual rect-size mask
// is `dim & 0x3FF` (width) / `dim & 0x1FF` (height), NOT psx-spx's
// `((dim - 1) & mask) + 1`. So:
//   W = 1023 -> effective 1023 (renders)
//   W = 1024 -> effective 0    (drop - no pixels drawn)
//   W = 1025 -> effective 1    (renders single column, anchor outside)
//   H = 511  -> effective 511  (renders)
//   H = 512  -> effective 0    (drop)
//   H = 513  -> effective 1    (single row, anchor outside)
// Both psx-spx formulas overestimate the maximum effective dimension
// by exactly the same +1 amount the documentation's "((W-1) & mask) + 1"
// shape is meant to provide.
#define CT_RECT_W_1023  RASTER_VRAM_WHITE  /* renders, width 1023 */
#define CT_RECT_W_1024  RASTER_SENTINEL    /* effective 0 -> no draw */
#define CT_RECT_W_1025  RASTER_SENTINEL    /* effective 1 -> single column */
#define CT_RECT_H_511   RASTER_VRAM_WHITE  /* renders, height 511 */
#define CT_RECT_H_512   RASTER_SENTINEL    /* effective 0 -> no draw */
#define CT_RECT_H_513   RASTER_SENTINEL    /* effective 1 -> single row */

// ---- Per-vertex absolute coordinate ----
#define CT_TRI_VERTEX_ABS_OVER  RASTER_SENTINEL  /* HW_TODO dropped */

/* Pre-truncation probes. If hardware truncates vertex to 11-bit signed
   first then applies per-edge cull, both probes render identically to
   the baseline at anchor (RASTER_VRAM_RED). If a pre-truncation per-
   vertex absolute-coord rule exists, probes drop and anchor reads
   sentinel. Placeholders use RASTER_VRAM_RED - matches the "no extra
   rule" hypothesis until hardware says otherwise. */
#define CT_TRI_PRETRUNC_BIT11   RASTER_VRAM_RED
#define CT_TRI_PRETRUNC_BIT15   RASTER_VRAM_RED
