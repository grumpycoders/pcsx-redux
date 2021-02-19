/*

MIT License

Copyright (c) 2019 PCSX-Redux authors

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

#include "common/compiler/stdint.h"

struct Counter {
    uint16_t value;
    uint16_t padding1;
    uint16_t mode;
    uint16_t padding2;
    uint16_t target;
    uint8_t padding[6];
};

struct SIO {
    uint8_t fifo;
    uint8_t preview[3];
    uint16_t stat;
    uint16_t padding;
    uint16_t mode;
    uint16_t ctrl;
    uint16_t reserved;
    uint16_t baudRate;
};

#define HW_U8(x) (*(volatile uint8_t *)(x))
#define HW_U16(x) (*(volatile uint16_t *)(x))
#define HW_U32(x) (*(volatile uint32_t *)(x))
#define HW_S8(x) (*(volatile int8_t *)(x))
#define HW_S16(x) (*(volatile int16_t *)(x))
#define HW_S32(x) (*(volatile int32_t *)(x))

#define SBUS_DEV4_CTRL HW_U32(0x1f801014)
#define SBUS_DEV5_CTRL HW_U32(0x1f801018)
#define SBUS_COM_CTRL HW_U32(0x1f801020)

#define SIOS ((volatile struct SIO *)0x1f801040)

#define RAM_SIZE HW_U32(0x1f801060)

#define IREG HW_U32(0xbf801070)
#define IMASK HW_U32(0xbf801074)

#define DPCR HW_U32(0x1f8010f0)
#define DICR HW_U32(0x1f8010f4)

#define COUNTERS ((volatile struct Counter *)0xbf801100)

#define GPU_DATA HW_U32(0x1f801810)
#define GPU_STATUS HW_U32(0x1f801814)

#define ATCONS_STAT HW_U8(0x1f802000)
#define ATCONS_FIFO HW_U8(0x1f802002)
#define ATCONS_IRQ HW_U8(0x1f802030)
#define ATCONS_IRQ2 HW_U8(0x1f802032)

#define POST HW_U8(0xbf802041)
