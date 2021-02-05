/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

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

#include "shell/gpu.h"

#include "common/hardware/gpu.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/irq.h"
#include "common/syscalls/syscalls.h"

static int s_frame = 0;

void flip(int doubleBuffer) {
    if (doubleBuffer) {
        s_frame ^= 1;
        setDisplayArea(s_frame ? WIDTH : 0, 0);
        setDrawingArea(s_frame ? 0 : WIDTH, 0, s_frame ? WIDTH : WIDTH * 2, HEIGHT);
        setDrawingOffset(s_frame ? 0 : WIDTH, 0);
        struct FastFill ff = {
            .c = s_bg,
            .x = s_frame ? 0 : WIDTH,
            .y = 0,
            .w = WIDTH,
            .h = HEIGHT,
        };
        fastFill(&ff);
    } else {
        struct FastFill ff = {
            .c = s_bg,
            .x = 0,
            .y = 0,
            .w = WIDTH,
            .h = HEIGHT,
        };
        fastFill(&ff);
    }
}

void waitVSync() {
    int wasLocked = enterCriticalSection();
    uint32_t imask = IMASK;

    IMASK = imask | IRQ_VBLANK;

    while ((IREG & IRQ_VBLANK) == 0)
        ;
    IREG &= ~IRQ_VBLANK;
    IMASK = imask;
    if (!wasLocked) leaveCriticalSection();
}

void initGPU() {
    GPU_STATUS = 0x00000000;  // reset GPU
    struct DisplayModeConfig config = {
        .hResolution = HR_640,
        .vResolution = VR_480,
        .videoMode = VM_NTSC,
        .colorDepth = CD_15BITS,
        .videoInterlace = VI_ON,
        .hResolutionExtended = HRE_NORMAL,
    };
    setDisplayMode(&config);
    setHorizontalRange(7, 0xa00);
    setVerticalRange(10, 250);
    setDisplayArea(0, 0);
    setDrawingArea(0, 0, WIDTH, HEIGHT);
    setDrawingOffset(0, 0);
}
