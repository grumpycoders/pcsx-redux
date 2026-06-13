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

// Test 5: Fast-fill (GP0 0x02) Y/H sweep.
//
// spicyjpeg observed: "fast fill can cross Y=512 but cannot fill more
// than 511 rows at a time." This test sweeps (Y, H) combinations to
// characterize the H truncation point precisely and to verify
// boundary-crossing.

#include "probe-common.h"

#define COL_X      0
#define COL_W      32
#define FILL_R     0x80
#define FILL_G     0x80
#define FILL_B     0x00     // yellow when packed via fast-fill
#define BG_COLOR   0x7fffu  // distinguishable from any fast-fill color

static void onePass(int16_t y, int16_t h) {
    fillColumn(COL_X, COL_W, BG_COLOR);

    // GP0(0x02) fast-fill ignores drawing area, so we just issue it directly.
    waitGPU();
    GPU_DATA = 0x02000000u | (uint32_t)FILL_R | ((uint32_t)FILL_G << 8) |
               ((uint32_t)FILL_B << 16);
    GPU_DATA = ((uint32_t)(uint16_t)y << 16) | (uint32_t)(uint16_t)COL_X;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)COL_W;

    // Find the actual filled extent by reading the column.
    int top = -1, bot = -1;
    uint16_t buf[2];
    for (int row = 0; row < 1024; row++) {
        readStrip(COL_X + 4, row, 2, buf);
        // Fast-fill packs RGB into a 16-bit pixel via top-5-bits of each
        // channel. We just check for "not BG_COLOR" rather than computing
        // the exact expected value.
        if (buf[0] != BG_COLOR) {
            if (top < 0) top = row;
            bot = row;
        }
    }

    int filled_count = (top < 0) ? 0 : (bot - top + 1);
    PROBE_RESULT("fast-fill-y y=%d h=%d filled_y_min=%d filled_y_max=%d filled_count=%d",
                 y, h, top, bot, filled_count);
}

int main(void) {
    ramsyscall_printf("\n=== 573 fast-fill-y ===\n");
    probeReset();

    ProbeStats stats;
    probeStatsInit(&stats);

    // Boundary-crossing
    onePass(400, 100);  // 400..499, no crossing
    onePass(400, 200);  // 400..599, crosses Y=512
    // Edge cases for the 511-row limit
    onePass(0, 511);    // exactly 511 rows
    onePass(0, 512);    // h=512: does it accept or truncate?
    onePass(0, 513);    // h>511: see what comes through
    onePass(510, 4);    // small fill at the boundary
    // Upper-bank
    onePass(512, 100);  // entirely upper bank
    onePass(768, 256);
    onePass(900, 200);  // would extend past 1023 if not clipped
    // Stress tests for masking
    onePass(0, 1024);   // h>1023
    onePass(1023, 2);   // y at end-of-VRAM, small h

    PROBE_INFO(&stats, "fast-fill-y sweep complete");
    probeStatsSummary(&stats, "fast-fill-y");
    while (1) {
    }
    return 0;
}
