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

// Test 11: GP0(0xA0) upload and GP0(0x80) blit H-boundary
// characterization.
//
// First-pass tests crashed at H=513. Rough hypothesis: the GPU accepts H
// in the header but caps the actual data phase at some smaller value;
// our CPU writes overflow into the command stream and corrupt the GPU
// state. This binary uses resetCommandBuffer() between every transfer so
// the test can survive any individual quirky H value, then reports what
// actually got written.
//
// For each H in {509..520, 768, 1023, 1024}, do an upload at Y=0 with a
// per-row signature, then read back the column to find which rows
// actually received our pattern. Same sweep for blit.

#include "probe-common.h"

#define UP_X     0
#define BLIT_DST_X 256
#define COL_W    32
#define BG_COLOR 0x7fffu

static uint16_t encodeRow(int y) { return (uint16_t)((y * 0x97) ^ 0xa55a) | 1; }

// Upload at (Y=0, h) and report which rows got our pattern. We send
// exactly copyHeightEff(h) rows of data so the GPU's data phase consumes
// every word and we never overflow into the command stream.
static void uploadPass(int16_t h) {
    gpuFullResetWithGate(1);
    fillColumn(UP_X, COL_W, BG_COLOR);

    int eff_h = copyHeightEff(h);

    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)0 << 16) | (uint32_t)(uint16_t)UP_X;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)COL_W;
    int idx = 0;
    for (int row = 0; row < eff_h; row++) {
        uint16_t v = encodeRow(row);
        uint32_t doubled = (uint32_t)v | ((uint32_t)v << 16);
        for (int i = 0; i < (COL_W >> 1); i++) {
            streamPace(idx++);
            GPU_DATA = doubled;
        }
    }

    int top = -1, bot = -1, exact = 0;
    uint16_t buf[2];
    for (int row = 0; row < 1024; row++) {
        readStrip(UP_X + 4, row, 2, buf);
        if (row < eff_h && buf[0] == encodeRow(row)) {
            exact++;
            if (top < 0) top = row;
            bot = row;
        }
    }
    PROBE_RESULT("transfer-h-quirk cmd=upload h=%d eff_h=%d wrote_y_min=%d wrote_y_max=%d "
                 "exact=%d",
                 h, eff_h, top, bot, exact);
    waitGPU();
}

// Stamp the source area with a per-row pattern that's H-tall (capped at
// 512 so the source itself never tickles the bit-9 quirk), then blit
// src->dst with the test H value. Blit has no CPU data phase, so the
// only thing under test here is whether the blit's actual transfer size
// matches the documented copyHeightEff(h) formula.
static void blitPass(int16_t h) {
    gpuFullResetWithGate(1);
    fillColumn(UP_X, COL_W, BG_COLOR);
    fillColumn(BLIT_DST_X, COL_W, BG_COLOR);

    // Stamp source with 512 rows of distinct patterns. That's enough to
    // cover any plausible blit transfer. Use copyHeightEff so the data
    // phase matches exactly.
    int16_t src_h = 512;
    int src_eff_h = copyHeightEff(src_h);
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)0 << 16) | (uint32_t)(uint16_t)UP_X;
    GPU_DATA = ((uint32_t)(uint16_t)src_h << 16) | (uint32_t)(uint16_t)COL_W;
    int idx = 0;
    for (int row = 0; row < src_eff_h; row++) {
        uint16_t v = encodeRow(row);
        uint32_t doubled = (uint32_t)v | ((uint32_t)v << 16);
        for (int i = 0; i < (COL_W >> 1); i++) {
            streamPace(idx++);
            GPU_DATA = doubled;
        }
    }
    waitGPU();

    // Now the actual probe: blit src -> BLIT_DST_X with the test H.
    int eff_h = copyHeightEff(h);
    waitGPU();
    GPU_DATA = 0x80000000u;
    GPU_DATA = ((uint32_t)0 << 16) | (uint32_t)(uint16_t)UP_X;
    GPU_DATA = ((uint32_t)0 << 16) | (uint32_t)(uint16_t)BLIT_DST_X;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)COL_W;

    int top = -1, bot = -1, exact = 0;
    uint16_t buf[2];
    for (int row = 0; row < 1024; row++) {
        readStrip(BLIT_DST_X + 4, row, 2, buf);
        if (row < eff_h && buf[0] == encodeRow(row)) {
            exact++;
            if (top < 0) top = row;
            bot = row;
        }
    }
    PROBE_RESULT("transfer-h-quirk cmd=blit h=%d eff_h=%d found_y_min=%d found_y_max=%d "
                 "exact=%d",
                 h, eff_h, top, bot, exact);
    waitGPU();
}

int main(void) {
    ramsyscall_printf("\n=== 573 transfer-h-quirk ===\n");
    probeReset();
    gp1_09(1);  // upper bank on for clean readback

    ProbeStats stats;
    probeStatsInit(&stats);

    static const int16_t hs[] = {509, 510, 511, 512, 513, 514, 515, 516, 520, 768, 1023, 1024};
    static const int n_h = sizeof(hs) / sizeof(hs[0]);

    for (int i = 0; i < n_h; i++) {
        uploadPass(hs[i]);
    }
    for (int i = 0; i < n_h; i++) {
        blitPass(hs[i]);
    }

    PROBE_INFO(&stats, "transfer-h-quirk sweep complete");
    probeStatsSummary(&stats, "transfer-h-quirk");
    while (1) {
    }
    return 0;
}
