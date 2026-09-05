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

// Shared bare-metal helpers for the 573 VRAM test binaries.
//
// Each test binary is a standalone PS-EXE that initializes the GPU itself
// (no PSYQo runtime, no snitch harness), runs one topic's worth of probes,
// prints RESULT lines over Unirom's TTY, and idles. We deliberately stay
// raw because the whole point of the suite is to characterize what the
// silicon does with edge-case GP0/GP1 inputs without any library helpfully
// clamping them on the way through.

#include <stdint.h>

#include "common/hardware/dma.h"
#include "common/hardware/gpu.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/irq.h"
#include "common/syscalls/syscalls.h"

// Bring the GPU into a known polled-FIFO state. Modeled on the reset()
// in src/mips/tests/gpu/gpu.c so subsequent transfers do not hang on
// bits that only advance under DMA.
static inline void probeReset(void) {
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

    // GP1(0x00): full GPU reset.
    GPU_STATUS = 0x00000000;

    // Restore a sane retail-shaped display mode. None of these settings are
    // load-bearing for the probe itself - we just want the GPU out of any
    // weird mode Unirom may have left it in.
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
    setDrawingArea(0, 0, 320, 240);

    // GP1(0x04, 1): DMA direction = FIFO. This is what unblocks the
    // status bits that gate VRAM transfers when we are writing GPU_DATA
    // from the CPU. Without this the GP0(0xA0)/GP0(0xC0) handshake hangs.
    sendGPUStatus(0x04000001);
}

// GP1(0x09) - on retail this is "Texture Disable"; on arcade boards with a
// second VRAM bank it is repurposed as the upper-bank gate. The polarity is
// what we are characterizing, so the helper deliberately does not name the
// bit "enable" or "disable" - caller passes the literal value.
static inline void gp1_09(uint32_t value) { sendGPUStatus(0x09000000 | (value & 0xff)); }

// GP1(0x01): clear the GPU command FIFO. Note this only flushes the FIFO
// behind GP0; it does NOT reset the GPU's internal register state. For
// inter-iteration cleanup that returns the GPU to a fully known state,
// prefer gpuFullResetWithGate() below, which does a real GP1(0x00).
static inline void resetCommandBuffer(void) { sendGPUStatus(0x01000000); }

// Full GPU reset between test iterations. GP1 (port 1) is unbuffered so
// GP1(0x00) reaches the GPU immediately and clears every internal register
// (texpage, drawing area, mode bits, etc) without touching VRAM contents.
// We then restore just the two settings every test relies on:
//   - GP1(0x04, 1) FIFO mode so polled CPU transfers advance bit 25
//   - GP1(0x09) bank gate at the requested polarity
// This is faster than full probeReset() and avoids re-touching display
// timing registers that don't matter for the test outcome.
static inline void gpuFullResetWithGate(uint32_t gate_value) {
    sendGPUStatus(0x00000000);                  // GP1(0x00): full reset
    sendGPUStatus(0x04000001);                  // GP1(0x04): FIFO mode
    sendGPUStatus(0x09000000 | (gate_value & 0xff));
}

// Per psx-spx GPU section "Masking for COPY Commands parameters":
//   Xsiz_eff = ((Xsiz - 1) AND 3FFh) + 1   ;range 1..1024
//   Ysiz_eff = ((Ysiz - 1) AND 1FFh) + 1   ;range 1..512
// These give the actual number of pixels/rows the GPU will transfer for
// GP0(0xA0) CPU->VRAM, GP0(0xC0) VRAM->CPU, and GP0(0x80) VRAM->VRAM.
// Sending more than this in the data phase overflows into the command
// stream and crashes the GPU. Sending fewer stalls the GPU forever
// waiting for the rest. Use these helpers to send exactly the right
// number of words.
static inline int copyWidthEff(int w) { return (((w - 1) & 0x3ff) + 1); }
static inline int copyHeightEff(int h) { return (((h - 1) & 0x1ff) + 1); }

// Per psx-spx, fast-fill (GP0 0x02) has different masking:
//   Ysiz_eff = Ysiz AND 1FFh   ;range 0..1FFh, 0 = NO FILL
// So multiples of 512 are silently rejected (Ysiz=0 effective).
static inline int fastFillHeightEff(int h) {
    int eff = h & 0x1ff;
    return eff;  // 0 means "no fill at all"
}

// Multi-word GPU commands need exactly one waitGPU() at the start; bit 26
// goes LOW after the first word and only returns high after the entire
// transfer completes, so polling between sub-words hangs forever. This
// matches the pattern in src/mips/tests/gpu/gpu.c::sendOnePolygon.
//
// All coordinate fields are passed through unmodified - we do NOT mask to
// 16/9 bits because the masking behavior is part of what we are observing.

// Write a single 16-bit pixel at (x, y). GP0(0xA0) consumes one full 32-bit
// word per (1, 1) transfer; we set width=2 so the second pixel is filled
// with a recognizable padding value, then do not care about it.
static inline void writePixel(int16_t x, int16_t y, uint16_t value) {
    waitGPU();
    GPU_DATA = 0xa0000000;
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)x;
    GPU_DATA = ((uint32_t)(uint16_t)1 << 16) | (uint32_t)(uint16_t)2;
    GPU_DATA = (uint32_t)value | ((uint32_t)0xdead << 16);
}

// Read a single 16-bit pixel at (x, y). After the GP0(0xC0) header words
// we wait for status bit 27 ("Ready to send VRAM to CPU") before reading -
// bit 26 is "ready to take a command word" which goes high BEFORE any
// data is actually in the readback FIFO.
static inline uint16_t readPixel(int16_t x, int16_t y) {
    waitGPU();
    GPU_DATA = 0xc0000000;
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)x;
    GPU_DATA = ((uint32_t)(uint16_t)1 << 16) | (uint32_t)(uint16_t)2;
    while ((GPU_STATUS & 0x08000000) == 0) {
    }
    uint32_t word = GPU_DATA;
    return (uint16_t)(word & 0xffff);
}

// Read N pixels from a horizontal strip starting at (x, y). |w| must be
// even (so the readback word count is an integer). |dst| receives the
// raw 16-bit words.
static inline void readStrip(int16_t x, int16_t y, int16_t w, uint16_t* dst) {
    waitGPU();
    GPU_DATA = 0xc0000000;
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)x;
    GPU_DATA = ((uint32_t)(uint16_t)1 << 16) | (uint32_t)(uint16_t)w;
    int words = (w + 1) >> 1;
    for (int i = 0; i < words; i++) {
        while ((GPU_STATUS & 0x08000000) == 0) {
        }
        uint32_t word = GPU_DATA;
        dst[i * 2] = (uint16_t)(word & 0xffff);
        if (i * 2 + 1 < w) dst[i * 2 + 1] = (uint16_t)(word >> 16);
    }
}

// Pace large streamed payloads so the CPU does not outrun the GPU's
// command-FIFO drain rate. Bit 25 ("DMA / Data Request") under DMA
// direction = 1 (FIFO mode) means "FIFO has room". Without pacing,
// transfers of more than a few hundred words deadlock or drop writes.
static inline void streamPace(int idx) {
    if ((idx & 7) == 0) {
        while ((GPU_STATUS & 0x02000000) == 0) {
        }
    }
}

// Fill a rectangular region with a single 16-bit value via GP0(0xA0). Slow
// but works at any (Y, H) including across Y=512 - we deliberately do NOT
// use GP0(0x02) fast-fill here because that command's behavior is itself
// what other tests are characterizing, and we need a known-good fill in
// our test setup. Width must be even.
static inline void fillRectViaUpload(int16_t x, int16_t y, int16_t w, int16_t h,
                                     uint16_t value) {
    waitGPU();
    GPU_DATA = 0xa0000000;
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)x;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)w;
    uint32_t doubled = (uint32_t)value | ((uint32_t)value << 16);
    int words = ((int)w * (int)h) >> 1;
    for (int i = 0; i < words; i++) {
        streamPace(i);
        GPU_DATA = doubled;
    }
}

// Fill the full Y=0..1023 range of a vertical column. GP0(0xA0) silently
// caps height at 511 rows on at least some configurations (matches the
// limit spicyjpeg observed for GP0(0x02) fast-fill); doing it as two
// half-bank passes is the safe pattern.
static inline void fillColumn(int16_t x, int16_t w, uint16_t value) {
    fillRectViaUpload(x, 0, w, 256, value);
    fillRectViaUpload(x, 256, w, 256, value);
    fillRectViaUpload(x, 512, w, 256, value);
    fillRectViaUpload(x, 768, w, 256, value);
}

// Compute a cheap 32-bit hash of a row of |n| 16-bit pixels. Useful for
// quick "is this row what we expected" checks without dumping every byte.
static inline uint32_t hashRow(const uint16_t* row, int n) {
    uint32_t h = 0x811c9dc5u;  // FNV-1a init
    for (int i = 0; i < n; i++) {
        h ^= row[i];
        h *= 0x01000193u;
    }
    return h;
}

// Lightweight pass/fail accounting. Each test binary calls reportResult()
// per observation, then reportSummary() at the end. We do not abort on
// failure - characterization tests should record every observation, not
// stop at the first surprise.
typedef struct {
    int passed;
    int failed;
    int info;
} ProbeStats;

static inline void probeStatsInit(ProbeStats* s) {
    s->passed = 0;
    s->failed = 0;
    s->info = 0;
}

#define PROBE_PASS(stats, fmt, ...)                            \
    do {                                                       \
        (stats)->passed++;                                     \
        ramsyscall_printf("PASS " fmt "\n", ##__VA_ARGS__);    \
    } while (0)

#define PROBE_FAIL(stats, fmt, ...)                            \
    do {                                                       \
        (stats)->failed++;                                     \
        ramsyscall_printf("FAIL " fmt "\n", ##__VA_ARGS__);    \
    } while (0)

#define PROBE_INFO(stats, fmt, ...)                            \
    do {                                                       \
        (stats)->info++;                                       \
        ramsyscall_printf("INFO " fmt "\n", ##__VA_ARGS__);    \
    } while (0)

#define PROBE_RESULT(fmt, ...)                                 \
    do {                                                       \
        ramsyscall_printf("RESULT " fmt "\n", ##__VA_ARGS__);  \
    } while (0)

static inline void probeStatsSummary(const ProbeStats* s, const char* name) {
    ramsyscall_printf("SUMMARY name=%s passed=%d failed=%d info=%d\n", name, s->passed,
                      s->failed, s->info);
    // Marker line for log-capture tools (psxup.py looks for this exact string
    // to terminate its read loop).
    ramsyscall_printf("=== Done ===\n");
}
