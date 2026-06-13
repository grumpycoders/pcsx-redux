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

// Test 3: Drawing offset Y range.
//
// GP0(0xE5) Drawing offset is signed 11-bit on retail (-1024..+1023).
// Sweep Y offset across that range plus the boundary points and observe
// where a primitive drawn at vertex Y=0 actually lands in VRAM.

#include "probe-common.h"

#define COL_X      0
#define COL_W      32
// Command color: G=0xff -> VRAM 0x03e0 (green 5:5:5).
#define CMD_COLOR  0x0000ff00u
#define VRAM_COLOR 0x03e0u
#define BG_COLOR   0x0000u

static void onePass(int16_t y_off) {
    fillColumn(COL_X, COL_W, BG_COLOR);

    // Drawing area = full VRAM (no scissoring beyond physical extent).
    sendGPUData(0xe3000000u | ((uint32_t)0 << 10) | (uint32_t)COL_X);
    sendGPUData(0xe4000000u | ((uint32_t)1023 << 10) |
                (uint32_t)(COL_X + COL_W - 1));
    // GP0(0xE5) drawing offset: 11-bit signed X (bits 0-10), 11-bit signed
    // Y (bits 11-21).
    sendGPUData(0xe5000000u | (((uint32_t)(uint16_t)y_off & 0x7ffu) << 11));

    // Draw a small flat rectangle at vertex Y=0 sized 16x16. The drawing
    // offset shifts it; we then locate where it landed.
    waitGPU();
    GPU_DATA = 0x60000000u | CMD_COLOR;
    GPU_DATA = ((uint32_t)0 << 16) | (uint32_t)COL_X;
    GPU_DATA = ((uint32_t)16 << 16) | (uint32_t)16;

    // Locate the drawn region. We sweep a wide Y range because the offset
    // could push the primitive anywhere in 0..1023 (or wrap).
    int top_drawn = -1;
    int bot_drawn = -1;
    uint16_t row_buf[2];
    for (int y = 0; y < 1024; y += 2) {
        readStrip(COL_X + 4, y, 2, row_buf);
        if (row_buf[0] == VRAM_COLOR || row_buf[1] == VRAM_COLOR) {
            if (top_drawn < 0) top_drawn = y;
            bot_drawn = y;
        }
    }

    PROBE_RESULT("drawing-offset-y y_off=%d drawn_y_min=%d drawn_y_max=%d", y_off,
                 top_drawn, bot_drawn);
}

int main(void) {
    ramsyscall_printf("\n=== 573 drawing-offset-y ===\n");
    probeReset();

    static const int16_t offsets[] = {-1024, -512, -1, 0, 1, 256, 511, 512, 513, 1023};
    static const int n = sizeof(offsets) / sizeof(offsets[0]);

    ProbeStats stats;
    probeStatsInit(&stats);

    for (int i = 0; i < n; i++) {
        onePass(offsets[i]);
    }

    PROBE_INFO(&stats, "drawing-offset-y sweep complete");
    probeStatsSummary(&stats, "drawing-offset-y");
    while (1) {
    }
    return 0;
}
