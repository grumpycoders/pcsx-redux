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

// Test 6: VRAM CPU<->VRAM transfers (GP0 0xA0 / GP0 0xC0) Y/H sweep.
//
// Probes how upload/download transfers behave with Y >= 512 and with
// heights that cross the bank boundary or exceed 511.

#include "probe-common.h"

#define COL_X    0
#define COL_W    32
#define BG_COLOR 0x0000u

// Encode Y so we can identify which row a given pixel came from after
// readback.
static uint16_t encodeRow(int y) { return (uint16_t)((y * 0x97) ^ 0xa55a) | 1; }

static void onePass(int16_t y, int16_t h) {
    gpuFullResetWithGate(1);
    fillColumn(COL_X, COL_W, BG_COLOR);

    // Upload a region with a per-row pattern via GP0(0xA0).
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)COL_X;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)COL_W;

    int eff_h = copyHeightEff(h);
    int idx = 0;
    for (int row = 0; row < eff_h; row++) {
        uint16_t v = encodeRow(row);
        uint32_t doubled = (uint32_t)v | ((uint32_t)v << 16);
        for (int i = 0; i < (COL_W >> 1); i++) {
            streamPace(idx++);
            GPU_DATA = doubled;
        }
    }

    // For each VRAM row, check whether it contains the EXACT pattern of
    // the source row (row - y) that the transfer SHOULD have placed there.
    int exact_count = 0;
    int first_match = -1;
    int last_match = -1;
    uint16_t buf[2];
    for (int row = 0; row < 1024; row++) {
        readStrip(COL_X + 4, row, 2, buf);
        int src_row = row - y;
        if (src_row < 0 || src_row >= eff_h) continue;
        if (buf[0] == encodeRow(src_row)) {
            exact_count++;
            if (first_match < 0) first_match = row;
            last_match = row;
        }
    }

    PROBE_RESULT("vram-transfers-y y=%d h=%d eff_h=%d exact_matches=%d "
                 "found_y_min=%d found_y_max=%d",
                 y, h, eff_h, exact_count, first_match, last_match);

    waitGPU();
}

int main(void) {
    ramsyscall_printf("\n=== 573 vram-transfers-y ===\n");
    probeReset();
    gp1_09(1);  // open upper bank

    ProbeStats stats;
    probeStatsInit(&stats);

    onePass(400, 100);
    onePass(400, 200);  // crosses
    onePass(0, 511);
    onePass(0, 512);
    onePass(0, 513);    // safe now: copyHeightEff -> 1 row
    onePass(512, 100);
    onePass(768, 256);
    onePass(900, 200);  // y+h>1024, wrap probe

    PROBE_INFO(&stats, "vram-transfers-y sweep complete");
    probeStatsSummary(&stats, "vram-transfers-y");
    while (1) {
    }
    return 0;
}
