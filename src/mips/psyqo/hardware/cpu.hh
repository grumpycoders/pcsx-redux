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

#include "psyqo/hardware/hwregs.hh"

namespace psyqo::Hardware::CPU {

enum class IRQ : uint32_t {
    VBlank = 1 << 0,
    GPU = 1 << 1,
    CDRom = 1 << 2,
    DMA = 1 << 3,
    Timer0 = 1 << 4,
    Timer1 = 1 << 5,
    Timer2 = 1 << 6,
    Controller = 1 << 7,
    SIO = 1 << 8,
    SPU = 1 << 9,
    PIO = 1 << 10,
};

template <uint32_t offset>
struct IRQReg : public Register<offset> {
    void set(IRQ irq) { *this |= (static_cast<uint32_t>(irq)); }
    void clear(IRQ irq) { *this &= ~(static_cast<uint32_t>(irq)); }
};

extern IRQReg<0x0070> IReg;
extern IRQReg<0x0074> IMask;
extern Register<0x00f0> DPCR;
extern Register<0x00f4> DICR;

}  // namespace psyqo::Hardware::CPU
