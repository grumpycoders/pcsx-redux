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

// Test 2: Drawing area Y range.
//
// Sweeps GP0(0xE3)/GP0(0xE4) drawing-area Y across {0, 256, 511, 512, 513,
// 768, 1023}. For each pair, draws a tall solid rectangle that nominally
// covers the full column and reads back to find the actual scissored extent.
//
// Uses GP0(0x60) variable rectangle rather than a triangle because the
// rasterizer rejects polygons with vertex deltas > 511 vertically, which
// would prevent us from probing the full Y range with a single primitive.

#include "probe-common.h"

#define COL_X      0
#define COL_W      32
// Command color: R=0xff, G=0, B=0 -> VRAM pixel 0x001f (red 5:5:5).
#define CMD_COLOR  0x000000ffu
#define VRAM_COLOR 0x001fu
#define BG_COLOR   0x0000u

// Pre-fill only the column rows we'll inspect, not the whole VRAM. Saves
// ~16K word writes per test iteration.
#define PROBE_Y_MAX 1024

static void onePass(int16_t y_top, int16_t y_bot) {
    fillColumn(COL_X, COL_W, BG_COLOR);

    // GP0(0xE3) drawing area top-left.
    sendGPUData(0xe3000000u | ((uint32_t)(uint16_t)y_top << 10) |
                (uint32_t)(uint16_t)COL_X);
    // GP0(0xE4) drawing area bottom-right (inclusive). Subtracting 1 gives
    // a half-open [top, bot) interpretation that's easier to reason about.
    sendGPUData(0xe4000000u | ((uint32_t)(uint16_t)(y_bot - 1) << 10) |
                (uint32_t)(uint16_t)(COL_X + COL_W - 1));
    sendGPUData(0xe5000000u);  // drawing offset = (0,0)

    // GP0(0x60) variable rectangle. Width/height fields appear to mask to
    // around 10 bits, and h=1024 wraps to 0 (no draw), so we issue 4
    // stacked rectangles each h=256 to cover Y=0..1023. This way the
    // scissor of the drawing area decides which of the 4 rectangles
    // actually land in VRAM.
    for (int band = 0; band < 4; band++) {
        waitGPU();
        GPU_DATA = 0x60000000u | CMD_COLOR;
        GPU_DATA = ((uint32_t)(band * 256) << 16) | (uint32_t)(uint16_t)COL_X;
        GPU_DATA = ((uint32_t)256 << 16) | (uint32_t)(uint16_t)COL_W;
    }

    int top_drawn = -1;
    int bot_drawn = -1;
    uint16_t row_buf[2];
    for (int y = 0; y < PROBE_Y_MAX; y++) {
        readStrip(COL_X + COL_W / 2, y, 2, row_buf);
        if (row_buf[0] == VRAM_COLOR) {
            if (top_drawn < 0) top_drawn = y;
            bot_drawn = y;
        }
    }

    PROBE_RESULT("drawing-area-y top=%d bot=%d drawn_y_min=%d drawn_y_max=%d", y_top, y_bot,
                 top_drawn, bot_drawn);
}

int main(void) {
    ramsyscall_printf("\n=== 573 drawing-area-y ===\n");
    probeReset();

    static const int16_t ys[] = {0, 256, 511, 512, 513, 768, 1023};
    static const int n = sizeof(ys) / sizeof(ys[0]);

    ProbeStats stats;
    probeStatsInit(&stats);

    // Sweep y_top with a fixed large y_bot.
    for (int i = 0; i < n; i++) {
        int16_t y_bot = (ys[i] < 600) ? 600 : (ys[i] + 256);
        if (y_bot > 1023) y_bot = 1023;
        onePass(ys[i], y_bot);
    }

    // Sweep y_bot with y_top fixed at 0.
    for (int i = 0; i < n; i++) {
        if (ys[i] <= 0) continue;
        onePass(0, ys[i]);
    }

    PROBE_INFO(&stats, "drawing-area-y sweep complete");
    probeStatsSummary(&stats, "drawing-area-y");
    while (1) {
    }
    return 0;
}
