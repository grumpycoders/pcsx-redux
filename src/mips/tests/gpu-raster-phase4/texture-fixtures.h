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

// Texture + CLUT fixtures for the gpu-raster phase-4 textured tests.
//
// VRAM layout (lower half draw zone left untouched, textures live to the
// right):
//
//   x=0..256, y=0..256     test draw area (uses RASTER_DRAW_AREA default)
//   x=512..575, y=0..255   4-bit CLUT texpage cell (tx=8, ty=0)
//                          actual VRAM footprint: x=512..527 (16 wide)
//                          carries 16 logical texels per word, 64 logical
//                          texels per row
//   x=576..639, y=0..255   8-bit CLUT texpage cell (tx=9, ty=0)
//                          actual VRAM footprint: x=576..607 (32 wide)
//                          carries 32 logical texels per word
//   x=640..703, y=0..255   15-bit direct texpage cell (tx=10, ty=0)
//                          actual VRAM footprint: x=640..703 (64 wide)
//                          1 logical texel per pixel
//   x=512..527, y=256      4-bit CLUT (16 entries)
//   x=512..767, y=257      8-bit CLUT (256 entries)
//
// Texture data is a U,V coordinate pattern so each texel encodes a
// deterministic function of its address - lets tests assert "this draw
// sampled position (U,V)" by reading back specific VRAM pixels.

#include "raster-helpers.h"

// Texpage cell base coords (in actual VRAM pixels, units of 64).
#define TEX4_TX             8u
#define TEX4_TY             0u
#define TEX4_VRAM_BASE_X    (TEX4_TX * 64)   /* 512 */
#define TEX4_VRAM_BASE_Y    (TEX4_TY * 256)  /* 0   */

#define TEX8_TX             9u
#define TEX8_TY             0u
#define TEX8_VRAM_BASE_X    (TEX8_TX * 64)   /* 576 */
#define TEX8_VRAM_BASE_Y    (TEX8_TY * 256)  /* 0   */

#define TEX15_TX            10u
#define TEX15_TY            0u
#define TEX15_VRAM_BASE_X   (TEX15_TX * 64)  /* 640 */
#define TEX15_VRAM_BASE_Y   (TEX15_TY * 256) /* 0   */

// CLUT locations. CLUT X must be 16-aligned (the CLUT field stores
// CLUT_X >> 4 in bits 0-5 of the textured-primitive command word).
#define CLUT4_VRAM_X        512u
#define CLUT4_VRAM_Y        256u
#define CLUT8_VRAM_X        512u
#define CLUT8_VRAM_Y        257u

// Encode the GP0 CLUT field used in textured-primitive command words.
// bits 0-5 = clut_x >> 4, bits 6-14 = clut_y.
static inline uint16_t clutField(uint16_t cx, uint16_t cy) {
    return (uint16_t)(((cx & 0x3f0) >> 4) | ((cy & 0x1ff) << 6));
}

#define CLUT4_FIELD     clutField(CLUT4_VRAM_X, CLUT4_VRAM_Y)
#define CLUT8_FIELD     clutField(CLUT8_VRAM_X, CLUT8_VRAM_Y)
#define CLUT15_FIELD    0u  /* 15-bit direct ignores CLUT */

// Encode the texpage field used in textured-primitive command words.
// bits 0-3 = tx, bit 4 = ty, bits 5-6 = ABR (semi-trans mode), bits 7-8
// = depth (0=4bit, 1=8bit, 2=15bit), bit 9 = (reserved/dither in E1).
// For the polygon command embedded-texpage field the layout differs
// slightly - see GP0 polygon command word format for the textured
// variant.
//
// We separately issue an explicit GP0(E1) before each draw to set the
// texpage so tests don't depend on stale state.
static inline uint16_t texpageField(uint16_t tx, uint16_t ty,
                                    uint16_t abr, uint16_t depth) {
    return (uint16_t)((tx & 0xf) | ((ty & 1) << 4) |
                      ((abr & 3) << 5) | ((depth & 3) << 7));
}

#define TEX4_TPAGE      texpageField(TEX4_TX, TEX4_TY, 0, 0)
#define TEX8_TPAGE      texpageField(TEX8_TX, TEX8_TY, 0, 1)
#define TEX15_TPAGE     texpageField(TEX15_TX, TEX15_TY, 0, 2)

// Send GP0(E1) to set the current texpage state. abr=0 (opaque), no
// dither, draw-to-display allowed (bit 10 = 1).
static inline void setTexpage(uint16_t tx, uint16_t ty, uint16_t depth) {
    uint32_t cmd = 0xe1000000u |
                   ((tx & 0xf)) |
                   ((ty & 1) << 4) |
                   (0u << 5) |       /* abr = 0 */
                   ((depth & 3) << 7) |
                   (0u << 9) |       /* dither off */
                   (1u << 10);       /* drawing to display area allowed */
    sendGPUData(cmd);
}

// Variant that takes an explicit ABR field. Use for textured-rect
// semi-trans tests where rasterSetAbr() would inadvertently reset the
// texpage to (tx=0, ty=0) - rect commands carry no embedded tpage
// word, so the current E1 state is load-bearing.
static inline void setTexpageAbr(uint16_t tx, uint16_t ty, uint16_t depth,
                                 uint16_t abr) {
    uint32_t cmd = 0xe1000000u |
                   ((tx & 0xf)) |
                   ((ty & 1) << 4) |
                   ((abr & 3) << 5) |
                   ((depth & 3) << 7) |
                   (0u << 9) |
                   (1u << 10);
    sendGPUData(cmd);
}

// Send GP0(E2) to set texture window. mask_x/mask_y are 5-bit "mask
// after >>3" values (so logical mask = mask*8). offset_x/offset_y same.
static inline void setTextureWindow(uint8_t mask_x, uint8_t mask_y,
                                    uint8_t off_x, uint8_t off_y) {
    uint32_t cmd = 0xe2000000u |
                   ((uint32_t)(mask_x & 0x1f)) |
                   ((uint32_t)(mask_y & 0x1f) << 5) |
                   ((uint32_t)(off_x & 0x1f) << 10) |
                   ((uint32_t)(off_y & 0x1f) << 15);
    sendGPUData(cmd);
}

// --------------------------------------------------------------------------
// Fixture upload
// --------------------------------------------------------------------------

// 4-bit CLUT: 16 entries, each entry = 16-bit 5:5:5 VRAM pixel.
// Palette[i] = vram555(i, 31-i, 0) so each index produces a unique
// recognizable color. 0 -> (0, 31, 0) green-ish, 15 -> (15, 16, 0)
// orange-ish.
static inline void uploadClut4(void) {
    uint16_t clut[16];
    for (int i = 0; i < 16; i++) {
        clut[i] = rasterVram555((uint8_t)i, (uint8_t)(31 - i), 0);
    }
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)CLUT4_VRAM_Y << 16) |
               (uint32_t)(uint16_t)CLUT4_VRAM_X;
    GPU_DATA = ((uint32_t)(uint16_t)1 << 16) | (uint32_t)(uint16_t)16;
    /* 16 pixels = 8 words */
    for (int i = 0; i < 8; i++) {
        GPU_DATA = (uint32_t)clut[i * 2] |
                   ((uint32_t)clut[i * 2 + 1] << 16);
    }
}

// 8-bit CLUT: 256 entries. Same palette function but extended:
// palette[i] = vram555(i & 0x1f, (255 - i) & 0x1f, ((i >> 5) & 0x1f)).
static inline void uploadClut8(void) {
    uint16_t clut[256];
    for (int i = 0; i < 256; i++) {
        clut[i] = rasterVram555((uint8_t)(i & 0x1f),
                                (uint8_t)((255 - i) & 0x1f),
                                (uint8_t)((i >> 5) & 0x1f));
    }
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)CLUT8_VRAM_Y << 16) |
               (uint32_t)(uint16_t)CLUT8_VRAM_X;
    GPU_DATA = ((uint32_t)(uint16_t)1 << 16) | (uint32_t)(uint16_t)256;
    for (int i = 0; i < 128; i++) {
        GPU_DATA = (uint32_t)clut[i * 2] |
                   ((uint32_t)clut[i * 2 + 1] << 16);
    }
}

// 4-bit texture upload. The texpage cell at (TEX4_VRAM_BASE_X,
// TEX4_VRAM_BASE_Y) holds 16 VRAM-pixels worth of data per row; each
// VRAM pixel encodes 4 logical 4-bit texels. We upload a small region
// 16 VRAM-pixels wide and 16 rows tall, encoding texel(u, v) = u & 0x0f.
//
// So:
//   u=0..15:  texel = u
//   u=16..31: same pattern repeats (16 texels per VRAM-pixel-pattern)
//
// Width: 16 logical texels means 4 actual VRAM pixels per row.
// We upload a 4-pixel-wide x 16-row block.
static inline void uploadTex4(void) {
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)TEX4_VRAM_BASE_Y << 16) |
               (uint32_t)(uint16_t)TEX4_VRAM_BASE_X;
    GPU_DATA = ((uint32_t)(uint16_t)16 << 16) | (uint32_t)(uint16_t)4;
    /* Each VRAM pixel encodes 4 4-bit texels: bits 0-3 = texel u%4=0,
       bits 4-7 = u%4=1, bits 8-11 = u%4=2, bits 12-15 = u%4=3.
       Pixel at (px, v) encodes texels (px*4..px*4+3, v).
       Texel value = u & 0x0f. So pixel(px, v) = px*4 | ((px*4+1)<<4) |
       ((px*4+2)<<8) | ((px*4+3)<<12) - except all u values are mod 16,
       so for px=0..3 (covering u=0..15) we just get the linear pattern. */
    for (int v = 0; v < 16; v++) {
        /* 4 pixels per row = 2 words */
        /* px=0: u=0,1,2,3 -> 0x3210 */
        /* px=1: u=4,5,6,7 -> 0x7654 */
        GPU_DATA = 0x76543210u;
        /* px=2: u=8..11 -> 0xba98 */
        /* px=3: u=12..15 -> 0xfedc */
        GPU_DATA = 0xfedcba98u;
    }
}

// 8-bit texture upload. Each VRAM pixel encodes 2 logical 8-bit texels.
// We upload a 32-pixel-wide (64 logical texels) x 16-row block, with
// texel(u, v) = u & 0xff.
static inline void uploadTex8(void) {
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)TEX8_VRAM_BASE_Y << 16) |
               (uint32_t)(uint16_t)TEX8_VRAM_BASE_X;
    GPU_DATA = ((uint32_t)(uint16_t)16 << 16) | (uint32_t)(uint16_t)32;
    for (int v = 0; v < 16; v++) {
        for (int px = 0; px < 32; px += 2) {
            /* px maps to u=px*2 and u=px*2+1 in the low byte and high
               byte. Pack two VRAM pixels per word. */
            uint32_t lo_pix = ((uint32_t)(px * 2 + 0) & 0xff) |
                              (((uint32_t)(px * 2 + 1) & 0xff) << 8);
            uint32_t hi_pix = ((uint32_t)(px * 2 + 2) & 0xff) |
                              (((uint32_t)(px * 2 + 3) & 0xff) << 8);
            GPU_DATA = (lo_pix & 0xffff) | ((hi_pix & 0xffff) << 16);
        }
    }
}

// 15-bit texture upload. Each VRAM pixel IS the texel. texel(u, v) =
// vram555(u & 0x1f, v & 0x1f, ((u + v) & 0x1f)) so each texel is a
// recognizable function of its address.
static inline void uploadTex15(void) {
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)TEX15_VRAM_BASE_Y << 16) |
               (uint32_t)(uint16_t)TEX15_VRAM_BASE_X;
    GPU_DATA = ((uint32_t)(uint16_t)16 << 16) | (uint32_t)(uint16_t)64;
    for (int v = 0; v < 16; v++) {
        for (int u = 0; u < 64; u += 2) {
            uint16_t t0 = rasterVram555((uint8_t)(u & 0x1f),
                                        (uint8_t)(v & 0x1f),
                                        (uint8_t)((u + v) & 0x1f));
            uint16_t t1 = rasterVram555((uint8_t)((u + 1) & 0x1f),
                                        (uint8_t)(v & 0x1f),
                                        (uint8_t)((u + 1 + v) & 0x1f));
            GPU_DATA = (uint32_t)t0 | ((uint32_t)t1 << 16);
        }
    }
}

// Bulk fixture upload - call once at BEFORE_ALL.
static inline void uploadAllTextureFixtures(void) {
    uploadClut4();
    uploadClut8();
    uploadTex4();
    uploadTex8();
    uploadTex15();
}

// Expected CLUT-lookup value for an 8-bit/4-bit texture sample at
// logical UV position. Same encoding as the upload functions so tests
// can predict what a textured draw should produce.
static inline uint16_t expectedClut4Color(uint8_t u) {
    return rasterVram555((uint8_t)(u & 0xf),
                         (uint8_t)(31 - (u & 0xf)), 0);
}

static inline uint16_t expectedClut8Color(uint8_t u) {
    return rasterVram555((uint8_t)(u & 0x1f),
                         (uint8_t)((255 - u) & 0x1f),
                         (uint8_t)((u >> 5) & 0x1f));
}

static inline uint16_t expectedTex15Color(uint8_t u, uint8_t v) {
    return rasterVram555((uint8_t)(u & 0x1f),
                         (uint8_t)(v & 0x1f),
                         (uint8_t)((u + v) & 0x1f));
}

// --------------------------------------------------------------------------
// Textured primitive senders
// --------------------------------------------------------------------------

// GP0(0x24) flat textured triangle - opaque, with texture blending.
// command color is the blend modulation (0x80 = neutral, no modulation).
// V0/V1/V2: x,y vertices. U0/V0_uv etc: texture UVs.
// clut_field: encoded CLUT location (use CLUT4_FIELD / CLUT8_FIELD / 0).
// tpage_field: encoded texpage (use TEX4_TPAGE / TEX8_TPAGE / TEX15_TPAGE).
static inline void rasterTexTri(uint32_t cmdColor,
                                int16_t x0, int16_t y0, uint8_t u0, uint8_t v0,
                                int16_t x1, int16_t y1, uint8_t u1, uint8_t v1,
                                int16_t x2, int16_t y2, uint8_t u2, uint8_t v2,
                                uint16_t clut_field, uint16_t tpage_field) {
    waitGPU();
    GPU_DATA = 0x24000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y0 << 16) | (uint32_t)(uint16_t)x0;
    GPU_DATA = ((uint32_t)clut_field << 16) |
               ((uint32_t)v0 << 8) | (uint32_t)u0;
    GPU_DATA = ((uint32_t)(uint16_t)y1 << 16) | (uint32_t)(uint16_t)x1;
    GPU_DATA = ((uint32_t)tpage_field << 16) |
               ((uint32_t)v1 << 8) | (uint32_t)u1;
    GPU_DATA = ((uint32_t)(uint16_t)y2 << 16) | (uint32_t)(uint16_t)x2;
    GPU_DATA = (0u << 16) | ((uint32_t)v2 << 8) | (uint32_t)u2;
}

// Neutral modulation color: 0x808080 makes the textured pixel pass
// through unchanged (texel * 128 / 128 == texel, per the soft
// renderer's modulation formula).
#define TEX_MOD_NEUTRAL  0x808080u

// GP0(0x2C) flat textured opaque quad. Word layout (9 words total):
//   0: 0x2C << 24 | cmdColor
//   1: y0 << 16 | x0
//   2: clut_field << 16 | v0 << 8 | u0
//   3: y1 << 16 | x1
//   4: tpage_field << 16 | v1 << 8 | u1
//   5: y2 << 16 | x2
//   6: 0 | v2 << 8 | u2
//   7: y3 << 16 | x3
//   8: 0 | v3 << 8 | u3
//
// Vertex ordering matters: the GPU draws v0-v1-v2 and v1-v2-v3
// triangles internally (soft renderer's 4-vertex setupSections path
// uses the full quad; hardware's order independence is among the
// things phase-8 characterizes).
static inline void rasterFlatTexQuad(uint32_t cmdColor,
                                     int16_t x0, int16_t y0, uint8_t u0, uint8_t v0,
                                     int16_t x1, int16_t y1, uint8_t u1, uint8_t v1,
                                     int16_t x2, int16_t y2, uint8_t u2, uint8_t v2,
                                     int16_t x3, int16_t y3, uint8_t u3, uint8_t v3,
                                     uint16_t clut_field, uint16_t tpage_field) {
    waitGPU();
    GPU_DATA = 0x2c000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y0 << 16) | (uint32_t)(uint16_t)x0;
    GPU_DATA = ((uint32_t)clut_field << 16) |
               ((uint32_t)v0 << 8) | (uint32_t)u0;
    GPU_DATA = ((uint32_t)(uint16_t)y1 << 16) | (uint32_t)(uint16_t)x1;
    GPU_DATA = ((uint32_t)tpage_field << 16) |
               ((uint32_t)v1 << 8) | (uint32_t)u1;
    GPU_DATA = ((uint32_t)(uint16_t)y2 << 16) | (uint32_t)(uint16_t)x2;
    GPU_DATA = (0u << 16) | ((uint32_t)v2 << 8) | (uint32_t)u2;
    GPU_DATA = ((uint32_t)(uint16_t)y3 << 16) | (uint32_t)(uint16_t)x3;
    GPU_DATA = (0u << 16) | ((uint32_t)v3 << 8) | (uint32_t)u3;
}

// GP0(0x64) variable-size textured opaque rectangle.
//   word 0: 0x64 << 24 | cmdColor (modulation, 0x808080 = neutral)
//   word 1: y << 16 | x (top-left)
//   word 2: clut_field << 16 | v << 8 | u (UV at top-left)
//   word 3: h << 16 | w
// Texture page state must be set via E1 (or recently-issued textured
// primitive) - the rect command does NOT carry a tpage field word.
static inline void rasterTexRect(uint32_t cmdColor,
                                 int16_t x, int16_t y,
                                 uint8_t u, uint8_t v,
                                 int16_t w, int16_t h,
                                 uint16_t clut_field) {
    waitGPU();
    GPU_DATA = 0x64000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)x;
    GPU_DATA = ((uint32_t)clut_field << 16) |
               ((uint32_t)v << 8) | (uint32_t)u;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)w;
}

// GP0(0x66) semi-trans variable-size textured rectangle. Same layout
// as 0x64; ABR blend mode comes from the current E1 tpage state.
static inline void rasterTexRectSemi(uint32_t cmdColor,
                                     int16_t x, int16_t y,
                                     uint8_t u, uint8_t v,
                                     int16_t w, int16_t h,
                                     uint16_t clut_field) {
    waitGPU();
    GPU_DATA = 0x66000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)x;
    GPU_DATA = ((uint32_t)clut_field << 16) |
               ((uint32_t)v << 8) | (uint32_t)u;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)w;
}

// GP0(0x2E) semi-trans flat textured quad. Same layout as 0x2C; only
// the command opcode byte differs. ABR is read from the embedded tpage
// field (bit 5-6 of texpageField).
static inline void rasterFlatTexQuadSemi(uint32_t cmdColor,
                                         int16_t x0, int16_t y0, uint8_t u0, uint8_t v0,
                                         int16_t x1, int16_t y1, uint8_t u1, uint8_t v1,
                                         int16_t x2, int16_t y2, uint8_t u2, uint8_t v2,
                                         int16_t x3, int16_t y3, uint8_t u3, uint8_t v3,
                                         uint16_t clut_field, uint16_t tpage_field) {
    waitGPU();
    GPU_DATA = 0x2e000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y0 << 16) | (uint32_t)(uint16_t)x0;
    GPU_DATA = ((uint32_t)clut_field << 16) |
               ((uint32_t)v0 << 8) | (uint32_t)u0;
    GPU_DATA = ((uint32_t)(uint16_t)y1 << 16) | (uint32_t)(uint16_t)x1;
    GPU_DATA = ((uint32_t)tpage_field << 16) |
               ((uint32_t)v1 << 8) | (uint32_t)u1;
    GPU_DATA = ((uint32_t)(uint16_t)y2 << 16) | (uint32_t)(uint16_t)x2;
    GPU_DATA = (0u << 16) | ((uint32_t)v2 << 8) | (uint32_t)u2;
    GPU_DATA = ((uint32_t)(uint16_t)y3 << 16) | (uint32_t)(uint16_t)x3;
    GPU_DATA = (0u << 16) | ((uint32_t)v3 << 8) | (uint32_t)u3;
}
