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

// Test 7: VRAM-to-VRAM blit (GP0 0x80) src/dst sweep across boundary.

#include "probe-common.h"

#define SRC_X    256
#define DST_X    512
#define COL_W    32
#define BG_COLOR 0xffffu  // white background = "untouched"

static uint16_t encodeRow(int y) { return (uint16_t)((y * 0x97) ^ 0xa55a) | 1; }

static void onePass(const char* label, int16_t src_y, int16_t dst_y, int16_t h) {
    // Full GPU reset between iterations so a quirky H value from the
    // previous pass can't leave any latched state behind. GP1 is
    // unbuffered (Pixel) so this reaches the GPU immediately.
    gpuFullResetWithGate(1);
    fillColumn(SRC_X, COL_W, BG_COLOR);
    fillColumn(DST_X, COL_W, BG_COLOR);

    // Stamp a per-row pattern at the source location. Send exactly the
    // number of rows the GPU will actually consume (per psx-spx copy
    // formula), not h, so an H value with bit 9 set doesn't overflow
    // into the command stream.
    int eff_h = copyHeightEff(h);
    waitGPU();
    GPU_DATA = 0xa0000000u;
    GPU_DATA = ((uint32_t)(uint16_t)src_y << 16) | (uint32_t)(uint16_t)SRC_X;
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

    // Issue GP0(0x80) blit.
    waitGPU();
    GPU_DATA = 0x80000000u;
    GPU_DATA = ((uint32_t)(uint16_t)src_y << 16) | (uint32_t)(uint16_t)SRC_X;
    GPU_DATA = ((uint32_t)(uint16_t)dst_y << 16) | (uint32_t)(uint16_t)DST_X;
    GPU_DATA = ((uint32_t)(uint16_t)h << 16) | (uint32_t)(uint16_t)COL_W;

    // For each destination row in 0..1023, check whether it contains the
    // EXACT pattern that the source row at offset (row - dst_y) had. This
    // is a much tighter match than "any encodeRow value" - it confirms the
    // blit actually copied the right row to the right place.
    int found_first = -1, found_last = -1, exact_count = 0;
    uint16_t buf[2];
    for (int row = 0; row < 1024; row++) {
        readStrip(DST_X + 4, row, 2, buf);
        int src_row = row - dst_y;
        // Only valid where the (effective) blit would have placed a copied
        // row; eff_h is the documented row count for this H value.
        if (src_row < 0 || src_row >= eff_h) continue;
        if (buf[0] == encodeRow(src_row)) {
            exact_count++;
            if (found_first < 0) found_first = row;
            found_last = row;
        }
    }

    PROBE_RESULT("vram-blit-y %s src_y=%d dst_y=%d h=%d eff_h=%d exact_matches=%d "
                 "found_y_min=%d found_y_max=%d",
                 label, src_y, dst_y, h, eff_h, exact_count, found_first, found_last);

    waitGPU();
}

int main(void) {
    ramsyscall_printf("\n=== 573 vram-blit-y ===\n");
    probeReset();
    // Open the upper bank so blits to/from y>=512 hit real second-bank VRAM
    // rather than mirroring back into the lower bank.
    gp1_09(1);

    ProbeStats stats;
    probeStatsInit(&stats);

    // Src lower, dst upper
    onePass("src-lo-dst-hi", 100, 600, 64);
    // Src upper, dst lower
    onePass("src-hi-dst-lo", 600, 100, 64);
    // Src crosses
    onePass("src-crosses", 480, 50, 64);
    // Dst crosses
    onePass("dst-crosses", 50, 480, 64);
    // Both cross
    onePass("both-cross", 480, 480, 64);
    // h spans the documented 9-bit-mask boundary. copyHeightEff handles
    // the overflow safely so all values land cleanly.
    onePass("tall-h512", 0, 512, 512);
    onePass("tall-h513-eff1", 0, 0, 513);    // psx-spx: 1 row
    onePass("tall-h1024-eff512", 0, 0, 1024); // psx-spx: full 512 rows

    PROBE_INFO(&stats, "vram-blit-y sweep complete");
    probeStatsSummary(&stats, "vram-blit-y");
    while (1) {
    }
    return 0;
}
