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

#include <stdint.h>

#include "common/util/encoder.hh"

using namespace Mips::Encoder;

static uint32_t s_stack[4096];
static uint32_t s_regs[32];

extern uint32_t HandlerAsm;

template <uint8_t addr>
struct Handler {
    static constexpr unsigned N = 4;
    void install() {
        const uint32_t *src = reinterpret_cast<const uint32_t *>(addr);
        for (unsigned i = 0; i < N; i++) {
            data[i] = src[i];
        }

        uint32_t *dst = reinterpret_cast<uint32_t *>(addr);
        uint32_t value = reinterpret_cast<uint32_t>(&HandlerAsm);
        uint16_t high = value >> 16;
        int16_t low = value & 0xffff;
        dst[0] = lui(Reg::K0, high);
        dst[1] = ori(Reg::K0, Reg::K0, low);
        dst[2] = jr(Reg::K0);
        dst[3] = ori(Reg::K1, Reg::R0, addr);
    }

    void restore() {
        uint32_t *dst = reinterpret_cast<uint32_t *>(addr);
        for (unsigned i = 0; i < N; i++) {
            dst[i] = data[i];
        }
    }

    uint32_t data[N];
};

static Handler<0x40> s_handler40;
static Handler<0x80> s_handler80;

extern "C" void installExceptionHandlers(uint32_t (*handler)(uint32_t *regs, uint32_t from)) {
    uint32_t (*wrapper)(uint32_t * regs, uint32_t from, uint32_t(*handler)(uint32_t * regs, uint32_t from)) =
        [](uint32_t *regs, uint32_t from, uint32_t (*handler)(uint32_t * regs, uint32_t from)) -> uint32_t {
        return handler(regs, from);
    };
    __asm__ volatile(
        R"(
    sw   %0, stackPointer
    sw   %1, regsPointer
    sw   %2, handlerPointer
    sw   %3, wrapperPointer
    b    skipMe

.global HandlerAsm

HandlerAsm:
    lw   $k0, regsPointer

    sw   $0, 0x00($k0)
    sw   $1, 0x04($k0)
    sw   $2, 0x08($k0)
    sw   $3, 0x0c($k0)
    sw   $4, 0x10($k0)
    sw   $5, 0x14($k0)
    sw   $6, 0x18($k0)
    sw   $7, 0x1c($k0)
    sw   $8, 0x20($k0)
    sw   $9, 0x24($k0)
    sw   $10, 0x28($k0)
    sw   $11, 0x2c($k0)
    sw   $12, 0x30($k0)
    sw   $13, 0x34($k0)
    sw   $14, 0x38($k0)
    sw   $15, 0x3c($k0)
    sw   $16, 0x40($k0)
    sw   $17, 0x44($k0)
    sw   $18, 0x48($k0)
    sw   $19, 0x4c($k0)
    sw   $20, 0x50($k0)
    sw   $21, 0x54($k0)
    sw   $22, 0x58($k0)
    sw   $23, 0x5c($k0)
    sw   $24, 0x60($k0)
    sw   $25, 0x64($k0)
    sw   $26, 0x68($k0)
    sw   $27, 0x6c($k0)
    sw   $28, 0x70($k0)
    sw   $29, 0x74($k0)
    sw   $30, 0x78($k0)
    sw   $31, 0x7c($k0)

    lw   $sp, stackPointer
    lw   $a2, handlerPointer
    lw   $v0, wrapperPointer
    move $a0, $k0
    move $a1, $k1
    jalr $v0

    lw   $k0, regsPointer
    move $k1, $v0

    lw   $0, 0x00($k0)
    lw   $1, 0x04($k0)
    lw   $2, 0x08($k0)
    lw   $3, 0x0c($k0)
    lw   $4, 0x10($k0)
    lw   $5, 0x14($k0)
    lw   $6, 0x18($k0)
    lw   $7, 0x1c($k0)
    lw   $8, 0x20($k0)
    lw   $9, 0x24($k0)
    lw   $10, 0x28($k0)
    lw   $11, 0x2c($k0)
    lw   $12, 0x30($k0)
    lw   $13, 0x34($k0)
    lw   $14, 0x38($k0)
    lw   $15, 0x3c($k0)
    lw   $16, 0x40($k0)
    lw   $17, 0x44($k0)
    lw   $18, 0x48($k0)
    lw   $19, 0x4c($k0)
    lw   $20, 0x50($k0)
    lw   $21, 0x54($k0)
    lw   $22, 0x58($k0)
    lw   $23, 0x5c($k0)
    lw   $24, 0x60($k0)
    lw   $25, 0x64($k0)
    lw   $28, 0x70($k0)
    lw   $29, 0x74($k0)
    lw   $30, 0x78($k0)
    lw   $31, 0x7c($k0)

.set push
.set noreorder
    jr   $k1
    rfe
.set pop

stackPointer:
    .word 0

regsPointer:
    .word 0

handlerPointer:
    .word 0

wrapperPointer:
    .word 0

skipMe:
    )"
        :
        : "r"(s_stack + sizeof(s_stack)), "r"(s_regs), "r"(handler), "r"(wrapper));

    s_handler40.install();
    s_handler80.install();
}

extern "C" void uninstallExceptionHandlers() {
    s_handler40.restore();
    s_handler80.restore();
}
