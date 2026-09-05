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

// Test 8: Display area Y range (visual).
//
// Pre-fills VRAM with four 256-row colored bands at Y=0/256/512/768
// (red/green/blue/yellow), each containing a self-identifying scanline
// signature that's unique to its band so a phone photo can confirm
// which band is on screen. Then steps GP1(0x05) "Display area start" Y
// across {0, 256, 400, 511, 512, 600, 768, 1023} on a fixed cadence and
// idles. Manual visual inspection.

#include "probe-common.h"

#define BAND_W      640
#define BAND_H      256

#define COLOR_RED    0x001fu  // 5:5:5 red
#define COLOR_GREEN  0x03e0u
#define COLOR_BLUE   0x7c00u
#define COLOR_YELLOW 0x03ffu

static void paintBand(int y0, uint16_t color, int signature_row_offset) {
    fillRectViaUpload(0, y0, BAND_W, BAND_H, color);

    // Paint a horizontal white stripe at y0 + signature_row_offset so the
    // photo can identify which band is at the top of the visible area.
    fillRectViaUpload(0, y0 + signature_row_offset, BAND_W, 4, 0xffffu);
}

static void setDisplayY(int16_t y) {
    sendGPUStatus(0x05000000u | ((uint32_t)(uint16_t)y << 10) | 0u);
}

// Cheap busy-wait loop sized roughly for ~3 seconds at the R3000's
// effective clock. Not precise, just enough that a human can take a
// photo per step.
static void approximateDelay(void) {
    for (volatile int i = 0; i < 30000000; i++) {
    }
}

int main(void) {
    ramsyscall_printf("\n=== 573 display-area-y ===\n");
    probeReset();
    enableDisplay();

    // 320x240 NTSC, full VRAM accessible
    paintBand(0,   COLOR_RED,    32);   // signature stripe at y=32
    paintBand(256, COLOR_GREEN,  64);   // signature at y=320
    paintBand(512, COLOR_BLUE,   96);   // signature at y=608
    paintBand(768, COLOR_YELLOW, 128);  // signature at y=896

    static const int16_t ys[] = {0, 256, 400, 511, 512, 600, 768, 1023};
    static const int n = sizeof(ys) / sizeof(ys[0]);

    // Loop forever, advancing the display start Y on a fixed cadence so
    // a single binary upload exposes every step for photographing.
    while (1) {
        for (int i = 0; i < n; i++) {
            ramsyscall_printf("RESULT display-area-y display_y=%d\n", ys[i]);
            setDisplayY(ys[i]);
            approximateDelay();
        }
    }
    return 0;
}
