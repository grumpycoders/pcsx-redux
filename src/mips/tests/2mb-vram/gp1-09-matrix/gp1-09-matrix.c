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

// Test 9: GP1(0x09) gating matrix.
//
// Reruns a compact subset of the per-command Y/H probes under both
// polarities of GP1(0x09) to characterize whether the bank gate changes
// the masking behavior of any individual command. The bank-probe test
// already establishes which polarity opens the upper bank; this test
// looks at the deltas - does fast-fill mask Y differently with gate=0 vs
// gate=1? Does GP0(0xA0)? Does GP0(0x80)?
//
// One RESULT line per (gate, command, y, h) cell, so the captured log
// is grep-friendly into a side-by-side table.

#include "probe-common.h"

#define COL_X    0
#define COL_W    32
#define BG_COLOR 0x7fffu

static void fastFillCell(uint32_t gate, int16_t y, int16_t h) {
    fillColumn(COL_X, COL_W, BG_COLOR);
    waitGPU();
    GPU_DATA = 0x02000000u | 0x00ff80u;  // some recognizable color
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)COL_X;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)COL_W;

    int top = -1, bot = -1;
    uint16_t buf[2];
    for (int row = 0; row < 1024; row++) {
        readStrip(COL_X + 4, row, 2, buf);
        if (buf[0] != BG_COLOR) {
            if (top < 0) top = row;
            bot = row;
        }
    }
    PROBE_RESULT("gp1-09-matrix gate=%02x cmd=fast-fill y=%d h=%d filled_y_min=%d filled_y_max=%d",
                 gate, y, h, top, bot);
}

static uint16_t encodeRow(int y) { return (uint16_t)((y * 0x97) ^ 0xa55a) | 1; }

static void uploadCell(uint32_t gate, int16_t y, int16_t h) {
    fillColumn(COL_X, COL_W, BG_COLOR);
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)COL_X;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)COL_W;
    {
        int idx = 0;
        for (int row = 0; row < h; row++) {
            uint16_t v = encodeRow(row);
            uint32_t doubled = (uint32_t)v | ((uint32_t)v << 16);
            for (int i = 0; i < (COL_W >> 1); i++) {
                streamPace(idx++);
                GPU_DATA = doubled;
            }
        }
    }
    int top = -1, bot = -1;
    uint16_t buf[2];
    for (int row = 0; row < 1024; row++) {
        readStrip(COL_X + 4, row, 2, buf);
        if (buf[0] != BG_COLOR) {
            if (top < 0) top = row;
            bot = row;
        }
    }
    PROBE_RESULT("gp1-09-matrix gate=%02x cmd=upload y=%d h=%d wrote_y_min=%d wrote_y_max=%d",
                 gate, y, h, top, bot);
}

static void blitCell(uint32_t gate, int16_t src_y, int16_t dst_y, int16_t h) {
    fillColumn(COL_X, COL_W, BG_COLOR);
    fillColumn(COL_X + 256, COL_W, BG_COLOR);
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)src_y << 16) | (uint32_t)(uint16_t)COL_X;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)COL_W;
    {
        int idx = 0;
        for (int row = 0; row < h; row++) {
            uint16_t v = encodeRow(row);
            uint32_t doubled = (uint32_t)v | ((uint32_t)v << 16);
            for (int i = 0; i < (COL_W >> 1); i++) {
                streamPace(idx++);
                GPU_DATA = doubled;
            }
        }
    }
    waitGPU();
    GPU_DATA = 0x80000000u;
    GPU_DATA = ((uint32_t)(uint16_t)src_y << 16) | (uint32_t)(uint16_t)COL_X;
    GPU_DATA = ((uint32_t)(uint16_t)dst_y << 16) | (uint32_t)(uint16_t)(COL_X + 256);
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)COL_W;

    int top = -1, bot = -1;
    uint16_t buf[2];
    for (int row = 0; row < 1024; row++) {
        readStrip(COL_X + 256 + 4, row, 2, buf);
        if (buf[0] != BG_COLOR) {
            if (top < 0) top = row;
            bot = row;
        }
    }
    PROBE_RESULT("gp1-09-matrix gate=%02x cmd=blit src=%d dst=%d h=%d found_y_min=%d found_y_max=%d",
                 gate, src_y, dst_y, h, top, bot);
}

static void runMatrixForGate(uint32_t gate) {
    probeReset();
    gp1_09(gate);

    // Fast-fill samples
    fastFillCell(gate, 0, 511);
    fastFillCell(gate, 0, 512);
    fastFillCell(gate, 400, 200);
    fastFillCell(gate, 512, 100);
    fastFillCell(gate, 768, 256);

    // Upload samples
    uploadCell(gate, 400, 200);
    uploadCell(gate, 0, 512);
    uploadCell(gate, 512, 100);

    // Blit samples
    blitCell(gate, 100, 600, 64);
    blitCell(gate, 480, 50, 64);
    blitCell(gate, 480, 480, 64);
}

int main(void) {
    ramsyscall_printf("\n=== 573 gp1-09-matrix ===\n");

    ProbeStats stats;
    probeStatsInit(&stats);

    runMatrixForGate(0);
    runMatrixForGate(1);

    PROBE_INFO(&stats, "gp1-09 matrix complete");
    probeStatsSummary(&stats, "gp1-09-matrix");
    while (1) {
    }
    return 0;
}
