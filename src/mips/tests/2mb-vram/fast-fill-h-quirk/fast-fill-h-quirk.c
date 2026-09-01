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

// Test 10: Fast-fill (GP0 0x02) H-boundary characterization.
//
// First-pass fast-fill-y data showed two surprises:
//   - H = 512 silently rejected (filled_count=0)
//   - H = 513 fills only row 0 (filled_count=1)
//   - H = 200 starting at Y=900 fills the full 1024 rows (Y+H>1024 wrap?)
//
// This binary sweeps H densely around the 511/512 transition and probes
// the Y+H>1024 wrap question with multiple Y values, so the bit-9-of-H
// behavior and the off-end wrap behavior can both be characterized.
//
// Runs with GP1(0x09)=1 so the upper bank is real (otherwise mirror
// artifacts confuse the readback).

#include "probe-common.h"

#define COL_X    0
#define COL_W    32
#define FILL_R   0x80
#define FILL_G   0x40
#define FILL_B   0xc0
#define BG_COLOR 0x7fffu

// Run one fast-fill at (y, h) and report exactly which rows became
// non-BG. Caller must clear the column first.
static void onePass(int16_t y, int16_t h) {
    gpuFullResetWithGate(1);
    fillColumn(COL_X, COL_W, BG_COLOR);

    waitGPU();
    GPU_DATA = 0x02000000u | (uint32_t)FILL_R | ((uint32_t)FILL_G << 8) |
               ((uint32_t)FILL_B << 16);
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)COL_X;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)COL_W;

    int top = -1, bot = -1, count = 0;
    uint16_t buf[2];
    for (int row = 0; row < 1024; row++) {
        readStrip(COL_X + 4, row, 2, buf);
        if (buf[0] != BG_COLOR) {
            count++;
            if (top < 0) top = row;
            bot = row;
        }
    }
    PROBE_RESULT("fast-fill-h-quirk y=%d h=%d filled_y_min=%d filled_y_max=%d filled_count=%d",
                 y, h, top, bot, count);
}

int main(void) {
    ramsyscall_printf("\n=== 573 fast-fill-h-quirk ===\n");
    probeReset();
    gp1_09(1);  // upper bank on; fast-fill writes go to real VRAM

    ProbeStats stats;
    probeStatsInit(&stats);

    // Dense sweep around the 511/512 transition.
    // Bit 9 of H flips at H=512, so probe H=510..520 to see the exact
    // pattern of acceptance and how the GPU interprets each value.
    static const int16_t hs[] = {510, 511, 512, 513, 514, 515, 516, 520, 600, 768, 1023, 1024};
    static const int n_h = sizeof(hs) / sizeof(hs[0]);
    for (int i = 0; i < n_h; i++) {
        onePass(0, hs[i]);
    }

    // Y+H wrap: hold H=200, sweep Y across the wrap point.
    // Y+H values: 800+200=1000 (no wrap), 900+200=1100 (wraps by 76),
    //             1000+200=1200 (wraps by 176), 1023+200=1223 (wraps by 199).
    static const int16_t wrap_ys[] = {800, 900, 1000, 1023};
    static const int n_wy = sizeof(wrap_ys) / sizeof(wrap_ys[0]);
    for (int i = 0; i < n_wy; i++) {
        onePass(wrap_ys[i], 200);
    }

    // Y+H wrap with single-row fills, to isolate "fills everything" from
    // "off-by-N wraparound".
    onePass(1023, 1);  // exactly at the edge, no wrap
    onePass(1023, 2);  // wraps by 1 row
    onePass(1024, 1);  // Y itself out of range

    PROBE_INFO(&stats, "fast-fill-h-quirk sweep complete");
    probeStatsSummary(&stats, "fast-fill-h-quirk");
    while (1) {
    }
    return 0;
}
