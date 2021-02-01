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

// 2kB
extern int32_t g_cosTable[512];
static const unsigned int DC_2PI = 2048;
static const unsigned int DC_PI = 1024;
static const unsigned int DC_PI2 = 512;
static const unsigned int DC_PI4 = 256;

static inline int32_t dCos(unsigned int t) {
    t %= DC_2PI;
    int32_t r;

    if (t < DC_PI2) {
        r = g_cosTable[t];
    } else if (t < DC_PI) {
        r = -g_cosTable[DC_PI - 1 - t];
    } else if (t < (DC_PI + DC_PI2)) {
        r = -g_cosTable[t - DC_PI];
    } else {
        r = g_cosTable[DC_2PI - 1 - t];
    }

    return r;
}

// sin(x) = cos(x - pi / 2)
static inline int32_t dSin(unsigned int t) {
    t %= DC_2PI;

    if (t < DC_PI2) return dCos(t + DC_2PI - DC_PI2);
    return dCos(t - DC_PI2);
}

static inline int32_t dMul(int32_t a, int32_t b) {
    long long r = a;
    r *= b;
    return r >> 24;
}

void generateCosTable();
