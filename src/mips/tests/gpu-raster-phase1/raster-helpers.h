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

// Shared bare-metal helpers for the GPU rasterizer edge-behavior test suite.
//
// VRAM I/O patterns lifted from src/mips/arcade-tests/probe-common.h, adapted
// for cester. The arcade-tests suite was characterizing 573 dual-bank VRAM
// quirks via a custom PROBE_PASS / PROBE_FAIL log format; here we want
// per-pixel cester assertions so failures surface as `expected X, received Y
// at file:line` and feed a soft-renderer punch-list.
//
// IMPORTANT (per ../../../../.. learnings, src/gpu/gpu.md):
//   - GP1(0x00) full reset between tests, not GP1(0x01) FIFO-only.
//   - One waitGPU() before a multi-word GP0 command. Do NOT poll bit 26
//     between sub-words; it goes LOW for the duration of the multi-word
//     transfer.
//   - GP0(0xA0) upload H is silently capped to 511 per the formula
//     ((H-1) & 0x1FF) + 1; for >511-row fills, do multiple passes.
//   - GP0(0x02) fast-fill is DIFFERENT - H & 0x1FF, with H==512 producing
//     no fill. We deliberately do not use fast-fill in our test setup
//     because its own quirks are part of what other tests characterize.
//   - The 24-bit color field in GP0 primitive commands is 8:8:8. The GPU
//     >>3s each channel before composing the VRAM 5:5:5 pixel. To draw VRAM
//     value 0x001F (5:5:5 red) the command color must be 0x0000F8.

#include <stdint.h>

#include "common/hardware/dma.h"
#include "common/hardware/gpu.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/irq.h"
#include "common/syscalls/syscalls.h"

// --------------------------------------------------------------------------
// VRAM region constants
// --------------------------------------------------------------------------

// Tests draw into the lower half of VRAM at known coordinates. The draw
// area covers a full 1024x512 region so primitives can land at extreme
// corners without bumping into clipping unless explicitly testing it.
#define RASTER_DRAW_AREA_X1  0
#define RASTER_DRAW_AREA_Y1  0
#define RASTER_DRAW_AREA_X2  1024
#define RASTER_DRAW_AREA_Y2  512

// Sentinel value VRAM is filled with before each test. Reading back a
// sentinel pixel after drawing means the rasterizer chose NOT to write
// that pixel; reading back any other value means it did.
//
// COLLISION CAVEAT (acknowledged 2026-05-15): 0xDEAD is a VALID VRAM 5:5:5
// pixel value (mask=1, B=27, G=26, R=13). If a test primitive's actual
// rendered color happens to equal 0xDEAD, an absence-test for that
// coordinate produces a false positive (the rasterizer DID write but we
// cannot tell it apart from the untouched sentinel). To avoid this:
//
//   1. The named primaries below (RASTER_VRAM_*) deliberately never
//      encode to 0xDEAD - all-red, all-green, all-blue, all-white are
//      max-channel-or-zero combinations that produce 0x001F, 0x03E0,
//      0x7C00, 0x7FFF respectively. None equal 0xDEAD.
//   2. When writing a test that uses a CUSTOM color (e.g., mask-bit
//      tests that intentionally render a mask-set value), check the
//      VRAM-side value at design time. If it collides with the sentinel,
//      switch THAT suite to a non-colliding sentinel via a local
//      override - do not change RASTER_SENTINEL globally because most
//      tests work fine with 0xDEAD and the diagnostic value is high.
//   3. The OBS log lines emitted by ASSERT_PIXEL_EQ always show actual
//      values, so even a collision is recoverable by reading the log -
//      it only fools the cester pass/fail count.
#define RASTER_SENTINEL  0xDEADu

// --------------------------------------------------------------------------
// Color encoding (5:5:5 VRAM <-> 8:8:8 GP0 command field)
// --------------------------------------------------------------------------

// Command-side color is 8:8:8. The GPU drops the low 3 bits of each channel
// when composing the VRAM 5:5:5 pixel. To draw a specific VRAM color you
// must left-shift each 5-bit channel by 3 before packing the command word.
//
// rasterCmdColor(r5, g5, b5) produces a 24-bit command color field that
// will render as the requested 5:5:5 VRAM pixel.
static inline uint32_t rasterCmdColor(uint8_t r5, uint8_t g5, uint8_t b5) {
    uint32_t r8 = (uint32_t)(r5 & 0x1f) << 3;
    uint32_t g8 = (uint32_t)(g5 & 0x1f) << 3;
    uint32_t b8 = (uint32_t)(b5 & 0x1f) << 3;
    return r8 | (g8 << 8) | (b8 << 16);
}

// rasterVram555(r5, g5, b5) builds the VRAM pixel value the above command
// color will produce.
static inline uint16_t rasterVram555(uint8_t r5, uint8_t g5, uint8_t b5) {
    return (uint16_t)((r5 & 0x1f) | ((g5 & 0x1f) << 5) | ((b5 & 0x1f) << 10));
}

// Named primaries the tests will reach for. Each pair is (command, VRAM)
// chosen so that the VRAM value is recognizable and asymmetric (i.e. not
// confused with the sentinel or with another primary if a single channel
// gets dropped or scrambled).
#define RASTER_CMD_RED    rasterCmdColor(0x1f, 0x00, 0x00)  // command 0x0000F8
#define RASTER_VRAM_RED   rasterVram555(0x1f, 0x00, 0x00)   // VRAM 0x001F
#define RASTER_CMD_GREEN  rasterCmdColor(0x00, 0x1f, 0x00)  // command 0x00F800
#define RASTER_VRAM_GREEN rasterVram555(0x00, 0x1f, 0x00)   // VRAM 0x03E0
#define RASTER_CMD_BLUE   rasterCmdColor(0x00, 0x00, 0x1f)  // command 0xF80000
#define RASTER_VRAM_BLUE  rasterVram555(0x00, 0x00, 0x1f)   // VRAM 0x7C00
#define RASTER_CMD_WHITE  rasterCmdColor(0x1f, 0x1f, 0x1f)  // command 0xF8F8F8
#define RASTER_VRAM_WHITE rasterVram555(0x1f, 0x1f, 0x1f)   // VRAM 0x7FFF

// --------------------------------------------------------------------------
// GPU reset / setup
// --------------------------------------------------------------------------

// Full-fat reset, modeled on src/mips/arcade-tests/probe-common.h.
// Bring the GPU into a known polled-FIFO state so subsequent VRAM transfers
// do not hang on DMA-readiness bits.
static inline void rasterFullReset(void) {
    IMASK = 0;
    IREG = 0;
    for (unsigned i = 0; i < 7; i++) {
        DMA_CTRL[i].CHCR = 0;
        DMA_CTRL[i].BCR = 0;
        DMA_CTRL[i].MADR = 0;
    }
    DPCR = 0x800;
    uint32_t dicr = DICR;
    DICR = dicr;
    DICR = 0;

    // GP1(0x00) full reset (clears all internal latched state).
    GPU_STATUS = 0x00000000;

    // Restore a sane display mode. Not load-bearing for the tests; we just
    // want the GPU out of any weird state Unirom may have left it in.
    struct DisplayModeConfig config = {
        .hResolution = HR_320,
        .vResolution = VR_240,
        .videoMode = VM_NTSC,
        .colorDepth = CD_15BITS,
        .videoInterlace = VI_OFF,
        .hResolutionExtended = HRE_NORMAL,
    };
    setDisplayMode(&config);
    setHorizontalRange(0, 0xa00);
    setVerticalRange(16, 255);
    setDisplayArea(0, 0);

    // GP1(0x04, 1): DMA direction = CPU-to-FIFO polling. Unblocks the
    // status bits that gate VRAM transfers when we write GPU_DATA from
    // the CPU. Without this, GP0(0xA0)/GP0(0xC0) handshake hangs.
    sendGPUStatus(0x04000001u);

    // Drawing area + offset to a clean test default. Individual tests may
    // override these.
    setDrawingArea(RASTER_DRAW_AREA_X1, RASTER_DRAW_AREA_Y1,
                   RASTER_DRAW_AREA_X2, RASTER_DRAW_AREA_Y2);
    setDrawingOffset(0, 0);

    // Texture window = full 256x256 page (offset 0, mask 0). E2 command.
    sendGPUData(0xe2000000u);
    // Mask setting (E6) cleared - no set-mask, no check-mask.
    sendGPUData(0xe6000000u);
    // Dither off, draw to display area enabled, default texpage state.
    // E1 command: texpage 0, semi mode 0, texdepth 0, dither 0, draw 1.
    sendGPUData(0xe1000400u);
}

// Faster inter-test reset that preserves the display mode set in
// rasterFullReset(). Returns the GPU to a clean E1/E2/E3/E5/E6 state and
// re-enables FIFO polling mode. Use in CESTER_BEFORE_EACH; the heavyweight
// rasterFullReset() runs once at BEFORE_ALL.
static inline void rasterReset(void) {
    sendGPUStatus(0x00000000u);  // GP1(0x00) full reset
    sendGPUStatus(0x04000001u);  // GP1(0x04, 1) FIFO mode
    setDrawingArea(RASTER_DRAW_AREA_X1, RASTER_DRAW_AREA_Y1,
                   RASTER_DRAW_AREA_X2, RASTER_DRAW_AREA_Y2);
    setDrawingOffset(0, 0);
    sendGPUData(0xe2000000u);
    sendGPUData(0xe6000000u);
    sendGPUData(0xe1000400u);
}

// --------------------------------------------------------------------------
// VRAM I/O via GP0(0xA0) upload and GP0(0xC0) readback
// --------------------------------------------------------------------------

// Pace large streamed payloads via status bit 25 ("FIFO has room").
// Without pacing, transfers of more than a few hundred words drop or
// deadlock under FIFO mode. See gpu.md "GP0 Streaming Pace Bit".
static inline void rasterStreamPace(int idx) {
    if ((idx & 7) == 0) {
        while ((GPU_STATUS & 0x02000000u) == 0) {
        }
    }
}

// Fill a rectangular VRAM region with a single 16-bit value via GP0(0xA0).
// Width must be even (the GPU consumes data in 32-bit words = 2 pixels).
// Height up to 511 - for larger fills make multiple calls; H==512 is
// clean per the ((H-1)&0x1FF)+1 formula but writing it that way keeps the
// data-phase word count exact.
static inline void rasterFillRect(int16_t x, int16_t y, int16_t w, int16_t h,
                                  uint16_t value) {
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)x;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)w;
    uint32_t doubled = (uint32_t)value | ((uint32_t)value << 16);
    int words = ((int)w * (int)h) >> 1;
    for (int i = 0; i < words; i++) {
        rasterStreamPace(i);
        GPU_DATA = doubled;
    }
}

// Read a single 16-bit pixel at (x, y) via GP0(0xC0).
// The readback uses W=2 H=1 (the smallest natural transfer; one word holds
// two packed 5:5:5 pixels) and returns the low half-word which is the
// pixel at column x. Bit 27 ("VRAM-to-CPU ready") gates the read; under
// FIFO mode 0x04000001 it advances correctly.
static inline uint16_t rasterReadPixel(int16_t x, int16_t y) {
    waitGPU();
    GPU_DATA = 0xc0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)x;
    GPU_DATA = ((uint32_t)(uint16_t)1 << 16) | (uint32_t)(uint16_t)2;
    while ((GPU_STATUS & 0x08000000u) == 0) {
    }
    uint32_t word = GPU_DATA;
    return (uint16_t)(word & 0xffff);
}

// Read a horizontal strip of |w| pixels starting at (x, y). |w| must be
// even (round caller-side if odd). Output is written to |dst| as raw
// 16-bit values in left-to-right order.
static inline void rasterReadStrip(int16_t x, int16_t y, int16_t w,
                                   uint16_t* dst) {
    waitGPU();
    GPU_DATA = 0xc0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)x;
    GPU_DATA = ((uint32_t)(uint16_t)1 << 16) | (uint32_t)(uint16_t)w;
    int words = (w + 1) >> 1;
    for (int i = 0; i < words; i++) {
        while ((GPU_STATUS & 0x08000000u) == 0) {
        }
        uint32_t word = GPU_DATA;
        dst[i * 2] = (uint16_t)(word & 0xffff);
        if (i * 2 + 1 < w) dst[i * 2 + 1] = (uint16_t)(word >> 16);
    }
}

// Fill the working test rectangle with the sentinel before each draw. This
// is just rasterFillRect with the named sentinel; kept as a separate name
// so tests document intent.
static inline void rasterClearTestRegion(int16_t x, int16_t y, int16_t w,
                                         int16_t h) {
    rasterFillRect(x, y, w, h, RASTER_SENTINEL);
}

// --------------------------------------------------------------------------
// Primitive senders (flat shading, untextured first - simplest oracle)
// --------------------------------------------------------------------------

// GP0(0x20) flat untextured triangle. Verts are sign-extended 11-bit on the
// silicon; we pass them as int16_t and let the GPU mask.
static inline void rasterFlatTri(uint32_t cmdColor, int16_t x0, int16_t y0,
                                 int16_t x1, int16_t y1, int16_t x2,
                                 int16_t y2) {
    waitGPU();
    GPU_DATA = 0x20000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y0 << 16) | (uint32_t)(uint16_t)x0;
    GPU_DATA = ((uint32_t)(uint16_t)y1 << 16) | (uint32_t)(uint16_t)x1;
    GPU_DATA = ((uint32_t)(uint16_t)y2 << 16) | (uint32_t)(uint16_t)x2;
}

// GP0(0x22) semi-trans flat untextured triangle. Same layout as 0x20.
// Blend mode comes from the current E1 ABR field (bits 5-6).
static inline void rasterFlatTriSemi(uint32_t cmdColor, int16_t x0, int16_t y0,
                                     int16_t x1, int16_t y1, int16_t x2,
                                     int16_t y2) {
    waitGPU();
    GPU_DATA = 0x22000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y0 << 16) | (uint32_t)(uint16_t)x0;
    GPU_DATA = ((uint32_t)(uint16_t)y1 << 16) | (uint32_t)(uint16_t)x1;
    GPU_DATA = ((uint32_t)(uint16_t)y2 << 16) | (uint32_t)(uint16_t)x2;
}

// GP0(0x2A) semi-trans flat untextured quad.
static inline void rasterFlatQuadSemi(uint32_t cmdColor, int16_t x0, int16_t y0,
                                      int16_t x1, int16_t y1, int16_t x2,
                                      int16_t y2, int16_t x3, int16_t y3) {
    waitGPU();
    GPU_DATA = 0x2a000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y0 << 16) | (uint32_t)(uint16_t)x0;
    GPU_DATA = ((uint32_t)(uint16_t)y1 << 16) | (uint32_t)(uint16_t)x1;
    GPU_DATA = ((uint32_t)(uint16_t)y2 << 16) | (uint32_t)(uint16_t)x2;
    GPU_DATA = ((uint32_t)(uint16_t)y3 << 16) | (uint32_t)(uint16_t)x3;
}

// GP0(0x62) semi-trans variable-size rect.
static inline void rasterFlatRectSemi(uint32_t cmdColor, int16_t x, int16_t y,
                                      int16_t w, int16_t h) {
    waitGPU();
    GPU_DATA = 0x62000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)x;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)w;
}

// Set the current ABR (semi-trans blend mode) via E1. ABR is bits 5-6;
// other E1 fields preserved at the test-default state.
//   0 = B/2 + F/2 (average)
//   1 = B + F     (additive)
//   2 = B - F     (subtractive)
//   3 = B + F/4   (add quarter)
static inline void rasterSetAbr(uint8_t abr) {
    uint32_t e1 = 0xe1000400u | ((uint32_t)(abr & 3) << 5);
    sendGPUData(e1);
}

// Set the E6 mask control bits.
//   set_mask = 1 -> bit 15 of every drawn pixel is forced to 1
//   check_mask = 1 -> pixels with bit 15 already set in VRAM are not
//                     overwritten (semi-trans bypassed for those pixels)
static inline void rasterSetMaskCtrl(int set_mask, int check_mask) {
    uint32_t e6 = 0xe6000000u |
                  ((uint32_t)(set_mask & 1)) |
                  ((uint32_t)(check_mask & 1) << 1);
    sendGPUData(e6);
}

// GP0(0x28) flat untextured quad. Vertex order matters - the GPU
// decomposes 0,1,2 + 1,2,3 internally (or so the soft renderer believes;
// hardware truth is among the things this suite characterizes).
static inline void rasterFlatQuad(uint32_t cmdColor, int16_t x0, int16_t y0,
                                  int16_t x1, int16_t y1, int16_t x2,
                                  int16_t y2, int16_t x3, int16_t y3) {
    waitGPU();
    GPU_DATA = 0x28000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y0 << 16) | (uint32_t)(uint16_t)x0;
    GPU_DATA = ((uint32_t)(uint16_t)y1 << 16) | (uint32_t)(uint16_t)x1;
    GPU_DATA = ((uint32_t)(uint16_t)y2 << 16) | (uint32_t)(uint16_t)x2;
    GPU_DATA = ((uint32_t)(uint16_t)y3 << 16) | (uint32_t)(uint16_t)x3;
}

// GP0(0x40) flat untextured line.
static inline void rasterFlatLine(uint32_t cmdColor, int16_t x0, int16_t y0,
                                  int16_t x1, int16_t y1) {
    waitGPU();
    GPU_DATA = 0x40000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y0 << 16) | (uint32_t)(uint16_t)x0;
    GPU_DATA = ((uint32_t)(uint16_t)y1 << 16) | (uint32_t)(uint16_t)x1;
}

// GP0(0x42) semi-trans flat line.
static inline void rasterFlatLineSemi(uint32_t cmdColor,
                                      int16_t x0, int16_t y0,
                                      int16_t x1, int16_t y1) {
    waitGPU();
    GPU_DATA = 0x42000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y0 << 16) | (uint32_t)(uint16_t)x0;
    GPU_DATA = ((uint32_t)(uint16_t)y1 << 16) | (uint32_t)(uint16_t)x1;
}

// GP0(0x50) gouraud line (per-vertex color).
static inline void rasterGouraudLine(uint32_t c0, int16_t x0, int16_t y0,
                                     uint32_t c1, int16_t x1, int16_t y1) {
    waitGPU();
    GPU_DATA = 0x50000000u | (c0 & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y0 << 16) | (uint32_t)(uint16_t)x0;
    GPU_DATA = (c1 & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y1 << 16) | (uint32_t)(uint16_t)x1;
}

// GP0(0x48) flat polyline. 3-vertex variant (single 0x55555555
// terminator after the third vertex). Higher-vertex polylines follow
// the same pattern; we expose a 3-vertex form for the tests.
static inline void rasterFlatPolyline3(uint32_t cmdColor,
                                       int16_t x0, int16_t y0,
                                       int16_t x1, int16_t y1,
                                       int16_t x2, int16_t y2) {
    waitGPU();
    GPU_DATA = 0x48000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y0 << 16) | (uint32_t)(uint16_t)x0;
    GPU_DATA = ((uint32_t)(uint16_t)y1 << 16) | (uint32_t)(uint16_t)x1;
    GPU_DATA = ((uint32_t)(uint16_t)y2 << 16) | (uint32_t)(uint16_t)x2;
    GPU_DATA = 0x55555555u;  /* polyline terminator */
}

// GP0(0x60) flat variable-size rectangle.
static inline void rasterFlatRect(uint32_t cmdColor, int16_t x, int16_t y,
                                  int16_t w, int16_t h) {
    waitGPU();
    GPU_DATA = 0x60000000u | (cmdColor & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)x;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)w;
}

// GP0(0x30) gouraud (per-vertex shaded) untextured triangle. The
// command-color of vertex 0 is packed into the leading word; vertices 1
// and 2 each have their own 24-bit color words preceding their position
// words. Each cN argument is a 24-bit 8:8:8 command-color (use
// rasterCmdColor() to build one with VRAM-friendly channel values).
//
// Word layout (six 32-bit words total):
//   0: 0x30 << 24 | c0_24bit
//   1: y0 << 16 | x0
//   2: 0x00 << 24 | c1_24bit
//   3: y1 << 16 | x1
//   4: 0x00 << 24 | c2_24bit
//   5: y2 << 16 | x2
static inline void rasterGouraudTri(uint32_t c0, int16_t x0, int16_t y0,
                                    uint32_t c1, int16_t x1, int16_t y1,
                                    uint32_t c2, int16_t x2, int16_t y2) {
    waitGPU();
    GPU_DATA = 0x30000000u | (c0 & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y0 << 16) | (uint32_t)(uint16_t)x0;
    GPU_DATA = (c1 & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y1 << 16) | (uint32_t)(uint16_t)x1;
    GPU_DATA = (c2 & 0x00ffffffu);
    GPU_DATA = ((uint32_t)(uint16_t)y2 << 16) | (uint32_t)(uint16_t)x2;
}

// Toggle dither bit (E1, bit 9). Other E1 fields preserved at the test-
// default state set by rasterReset/rasterFullReset. Test-cycle pattern:
//   rasterReset();
//   rasterSetDither(true);
//   ... draw ...
//   rasterSetDither(false);   // restore for next test
static inline void rasterSetDither(int on) {
    // E1 base: texpage 0, semi 0, depth 0, draw-to-display on (bit 10).
    uint32_t e1 = 0xe1000400u;
    if (on) e1 |= 0x00000200u;
    sendGPUData(e1);
}

// Wait for the GPU to drain after a primitive. Used before reading back
// VRAM so we know the rasterizer has finished writing.
static inline void rasterFlushPrimitive(void) { waitGPU(); }

// --------------------------------------------------------------------------
// Observation logging (ground-truth capture)
// --------------------------------------------------------------------------

// Every test that asserts a pixel value also logs the observed value via
// ramsyscall_printf. Cester reports failures as "expected X, received Y at
// file:line", which is the per-pixel diff signal; OBS lines provide
// ground-truth capture regardless of pass/fail so a hardware run produces
// a complete dump that can be greppped to patch raster-expected.h.
//
// Usage: ASSERT_PIXEL_EQ(EXPECT_FOO_x_y, x, y);
#define ASSERT_PIXEL_EQ(expected, x_, y_)                                   \
    do {                                                                    \
        int16_t _ax = (int16_t)(x_);                                        \
        int16_t _ay = (int16_t)(y_);                                        \
        uint16_t _aval = rasterReadPixel(_ax, _ay);                         \
        ramsyscall_printf("OBS x=%d y=%d val=0x%04x expect=0x%04x\n",       \
                          (int)_ax, (int)_ay, (unsigned)_aval,              \
                          (unsigned)(expected));                            \
        cester_assert_uint_eq((unsigned)(expected), (unsigned)_aval);       \
    } while (0)

// When the expected value is a sentinel (the test is asserting NOTHING
// drew at that pixel), use this for clarity at the call site.
#define ASSERT_PIXEL_UNTOUCHED(x_, y_) \
    ASSERT_PIXEL_EQ(RASTER_SENTINEL, (x_), (y_))
