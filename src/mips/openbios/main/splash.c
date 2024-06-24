/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

#include "openbios/main/splash.h"

#include <stdint.h>

#include "common/hardware/gpu.h"
#include "common/hardware/hwregs.h"

static const union Color s_colors[] = {{.r = 255, .g = 255, .b = 255}, {.r = 255, .g = 255, .b = 0},
                                       {.r = 0, .g = 255, .b = 255},   {.r = 0, .g = 255, .b = 0},
                                       {.r = 255, .g = 0, .b = 255},   {.r = 255, .g = 0, .b = 0},
                                       {.r = 0, .g = 0, .b = 255},     {.r = 0, .g = 0, .b = 0}};

// The original version of this function (as found in the 573 BIOS) invokes a
// subroutine repeatedly in order to draw each color bar, rather than using an
// array and a loop, and has several completely unnecessary checks. This is a
// much simpler and more straightforward but functionally equivalent
// implementation.
void drawSplashScreen() {
#ifdef OPENBIOS_SHOW_SPLASH_SCREEN
    struct DisplayModeConfig config = {.hResolution = HR_256,
                                       .vResolution = VR_240,
                                       .videoMode = VM_NTSC,
                                       .colorDepth = CD_15BITS,
                                       .videoInterlace = VI_OFF,
                                       .hResolutionExtended = HRE_NORMAL};

    GPU_STATUS = 0x00000000;  // Reset
    setDisplayArea(0, 0);
    setHorizontalRange(0, 256 * 10);
    setVerticalRange(16, 255);
    setDisplayMode(&config);

    const int barCount = sizeof(s_colors) / sizeof(union Color);
    struct FastFill ff = {.c = 0, .x = 0, .y = 0, .w = 256 / barCount, .h = 240};

    for (int i = 0; i < barCount; i++, ff.x += ff.w) {
        ff.c.packed = s_colors[i].packed;
        fastFill(&ff);
    }

    waitGPU();
    enableDisplay();
#endif
}
