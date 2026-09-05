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

// Test 4: Primitives crossing the Y=512 boundary.
//
// Each primitive class (flat triangle, flat-shaded rectangle/sprite, line)
// is rendered to span the boundary. We then read the column back and
// classify whether the primitive drew continuously, was split, was
// scissored to one half, or vanished entirely.

#include "probe-common.h"

#define COL_X      64
#define COL_W      32
// Command color: B=0xff -> VRAM 0x7c00 (blue 5:5:5).
#define CMD_COLOR  0x00ff0000u
#define VRAM_COLOR 0x7c00u
#define BG_COLOR   0x0000u

static void setupArea(void) {
    fillColumn(COL_X, COL_W, BG_COLOR);
    sendGPUData(0xe3000000u | ((uint32_t)0 << 10) | (uint32_t)COL_X);
    sendGPUData(0xe4000000u | ((uint32_t)1023 << 10) |
                (uint32_t)(COL_X + COL_W - 1));
    sendGPUData(0xe5000000u);
}

// Read at a specific column; the line case draws at column COL_X+8 while
// the polygon/rectangle/sprite cases draw across the full COL_X..COL_X+W
// range, so the readback column must match the primitive being tested.
static void countDrawnAt(const char* label, int read_x) {
    uint16_t buf[2];
    int drawn_lo = 0, drawn_mid = 0, drawn_hi = 0;
    for (int y = 400; y < 600; y++) {
        readStrip(read_x, y, 2, buf);
        if (buf[0] == VRAM_COLOR || buf[1] == VRAM_COLOR) {
            if (y < 500) drawn_lo++;
            else if (y < 520) drawn_mid++;
            else drawn_hi++;
        }
    }
    PROBE_RESULT("primitives-cross %s drawn_y400_499=%d drawn_y500_519=%d drawn_y520_599=%d",
                 label, drawn_lo, drawn_mid, drawn_hi);
}

static void countDrawn(const char* label) { countDrawnAt(label, COL_X + 4); }

int main(void) {
    ramsyscall_printf("\n=== 573 primitives-cross ===\n");
    probeReset();
    // Open the upper bank so writes at y>=512 land in real second-bank VRAM
    // rather than aliasing back to the lower bank. Without this the test
    // produces the same output on retail and 573 (mirror artifact masquerading
    // as cross-boundary draw).
    gp1_09(1);

    ProbeStats stats;
    probeStatsInit(&stats);

    // 1. Flat triangle from Y=400 to Y=600.
    setupArea();
    waitGPU();
    GPU_DATA = 0x20000000u | CMD_COLOR;
    GPU_DATA = (uint32_t)400 << 16 | (uint32_t)(COL_X + 0);
    GPU_DATA = (uint32_t)600 << 16 | (uint32_t)(COL_X + 0);
    GPU_DATA = (uint32_t)500 << 16 | (uint32_t)(COL_X + 16);
    countDrawn("flat-triangle");

    // 2. Flat-shaded rectangle (variable) at Y=400 height=200.
    setupArea();
    waitGPU();
    GPU_DATA = 0x60000000u | CMD_COLOR;                  // GP0(0x60) variable rect
    GPU_DATA = (uint32_t)400 << 16 | (uint32_t)(COL_X);  // top-left
    GPU_DATA = (uint32_t)200 << 16 | (uint32_t)16;       // size (h, w)
    countDrawn("rectangle");

    // 3. Line from (X, 400) to (X, 600).
    setupArea();
    waitGPU();
    GPU_DATA = 0x40000000u | CMD_COLOR;
    GPU_DATA = (uint32_t)400 << 16 | (uint32_t)(COL_X + 8);
    GPU_DATA = (uint32_t)600 << 16 | (uint32_t)(COL_X + 8);
    countDrawnAt("line-vertical", COL_X + 8);

    // 4. Sprite (1x1 framebuffer-style) at Y=500 with implicit size from
    //    a variable sprite command. Uses GP0(0x64) textured sprite would
    //    require a texpage; we use GP0(0x60) with size as plain rectangle
    //    again at Y=500 height=100 to show single-shape boundary cross.
    setupArea();
    waitGPU();
    GPU_DATA = 0x60000000u | CMD_COLOR;
    GPU_DATA = (uint32_t)500 << 16 | (uint32_t)(COL_X);
    GPU_DATA = (uint32_t)100 << 16 | (uint32_t)16;
    countDrawn("sprite-at-500-h100");

    PROBE_INFO(&stats, "primitives-cross sweep complete");
    probeStatsSummary(&stats, "primitives-cross");
    while (1) {
    }
    return 0;
}
