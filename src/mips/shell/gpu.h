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

#pragma once

#include <stdint.h>

#include "common/hardware/gpu.h"
#include "common/hardware/hwregs.h"
#include "shell/math.h"

#define WIDTH 640
#define HEIGHT 480

union GPUPoint {
    uint32_t packed;
    struct {
        int16_t x, y;
    };
};

void initGPU(int isPAL);
void flip(int doubleBuffer, const union Color bg);
void waitVSync(int interlaced, void (*idle)());

// we shift by 17 instead of 24 to do a scaling of 128
// therefore a typical square of (-1,-1)-(1,1) would
// end up as a 256x256 pixels one
static inline void sendGPUVertex(struct Vertex2D *v) {
    union GPUPoint p;
    int32_t x = v->x >> 17;
    int32_t y = v->y >> 17;
    // adjust ratio for proper 4:3 output view
    y = y * HEIGHT * 4 / (WIDTH * 3);
    p.x = x + WIDTH / 2;
    p.y = y + HEIGHT / 2;
    GPU_DATA = p.packed;
}
