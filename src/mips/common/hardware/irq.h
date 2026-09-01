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

#include <stdint.h>

enum IRQ {
    IRQ_VBLANK_NUMBER = 0,
    IRQ_VBLANK = 1 << IRQ_VBLANK_NUMBER,
    IRQ_GPU_NUMBER = 1,
    IRQ_GPU = 1 << IRQ_GPU_NUMBER,
    IRQ_CDROM_NUMBER = 2,
    IRQ_CDROM = 1 << IRQ_CDROM_NUMBER,
    IRQ_DMA_NUMBER = 3,
    IRQ_DMA = 1 << IRQ_DMA_NUMBER,
    IRQ_TIMER0_NUMBER = 4,
    IRQ_TIMER0 = 1 << IRQ_TIMER0_NUMBER,
    IRQ_TIMER1_NUMBER = 5,
    IRQ_TIMER1 = 1 << IRQ_TIMER1_NUMBER,
    IRQ_TIMER2_NUMBER = 6,
    IRQ_TIMER2 = 1 << IRQ_TIMER2_NUMBER,
    IRQ_CONTROLLER_NUMBER = 7,
    IRQ_CONTROLLER = 1 << IRQ_CONTROLLER_NUMBER,
    IRQ_SIO_NUMBER = 8,
    IRQ_SIO = 1 << IRQ_SIO_NUMBER,
    IRQ_SPU_NUMBER = 9,
    IRQ_SPU = 1 << IRQ_SPU_NUMBER,
    IRQ_PIO_NUMBER = 10,
    IRQ_PIO = 1 << IRQ_PIO_NUMBER,
};
