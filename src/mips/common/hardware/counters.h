/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

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

struct Counter {
    uint16_t value;
    uint16_t padding1;
    uint16_t mode;
    uint16_t padding2;
    uint16_t target;
    uint8_t padding[6];
};

#define COUNTERS ((volatile struct Counter *)0xbf801100)

enum {
    TM_SYNC_EN      = 0x0001,
    TM_RESET_TARGET = 0x0008,
    TM_IRQ_TARGET   = 0x0010,
    TM_IRQ_OVERFLOW = 0x0020,
    TM_IRQ_REPEAT   = 0x0040,
    TM_IRQ_TOGGLE   = 0x0080,
    TM_CLK_EXTERNAL = 0x0100,
    TM_CLK_DIV8     = 0x0200,
    TM_IRQ_REQUEST  = 0x0400,
    TM_HIT_TARGET   = 0x0800,
    TM_HIT_OVERFLOW = 0x1000,
};

#define TM_SYNC_MODE(n) (((n) & 3) << 1)
