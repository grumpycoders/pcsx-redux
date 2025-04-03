/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

#include "common/hardware/gpu.h"
#include "common/hardware/irq.h"
#include "common/kernel/threads.h"
#include "psyqo/kernel.hh"
#include "psyqo/primitives/control.hh"
#include "psyqo/primitives/misc.hh"
#include "psyqo/primitives/sprites.hh"
#include "psyqo/xprintf.h"

static const char *const s_exceptionNames[] = {
    "Interrupt",
    "TLB Mod",
    "TLB Load",
    "TLB Store",
    "Address Load",
    "Address Store",
    "Bus Error Load",
    "Bus Error Store",
    "Syscall",
    "Breakpoint",
    "Reserved Instruction",
    "Coprocessor Unusable",
    "Arithmetic Overflow",
    "Trap",
    "Floating Point Exception",
    "Watchpoint",
};

namespace {

template <typename Prim>
void sendPrimitive(const Prim &primitive) {
    waitGPU();
    const uint32_t *ptr = reinterpret_cast<const uint32_t *>(&primitive);
    constexpr size_t size = sizeof(Prim) / sizeof(uint32_t);
    for (int i = 0; i < size; i++) {
        GPU_DATA = *ptr++;
    }
}

}  // namespace

struct RegisterInfo {
    const char *name;
    uint32_t offsetCustom;
    uint32_t offsetDefault;
};

static void printString(const char *str, psyqo::Prim::Sprite &sprite, const uint8_t baseV, psyqo::Vertex &location) {
    for (const char *p = str; *p != '\0'; p++) {
        char c = *p;
        if (c < 32 || c > 127) {
            c = '?';
        }
        if (c == ' ') {
            location.x += 8;
            continue;
        }
        if (c <= '?') {
            sprite.texInfo.u = (c - ' ') * 8;
            sprite.texInfo.v = baseV;
        } else if (c <= '_') {
            sprite.texInfo.u = (c - '@') * 8;
            sprite.texInfo.v = baseV + 16;
        } else {
            sprite.texInfo.u = (c - '`') * 8;
            sprite.texInfo.v = baseV + 32;
        }
        sprite.position = location;
        sendPrimitive(sprite);
        location.x += 8;
    }
}

static const RegisterInfo s_registers[] = {
    {"r0", 0, 0},      {"at", 0x100, 1},  {"v0", 0x104, 2},  {"v1", 0x108, 3},  {"a0", 0x10c, 4},  {"a1", 0x110, 5},
    {"a2", 0x114, 6},  {"a3", 0x118, 7},  {"t0", 0x11c, 8},  {"t1", 0x120, 9},  {"t2", 0x124, 10}, {"t3", 0x128, 11},
    {"t4", 0x12c, 12}, {"t5", 0x130, 13}, {"t6", 0x134, 14}, {"t7", 0x138, 15}, {"s0", 0x154, 16}, {"s1", 0x158, 17},
    {"s2", 0x15c, 18}, {"s3", 0x160, 19}, {"s4", 0x164, 20}, {"s5", 0x168, 21}, {"s6", 0x16c, 22}, {"s7", 0x170, 23},
    {"t8", 0x140, 24}, {"t9", 0x144, 25}, {"gp", 0x150, 28}, {"sp", 0x148, 29}, {"fp", 0x174, 30}, {"ra", 0x14c, 31}};

static void printRegister(unsigned number, psyqo::Prim::Sprite &sprite, const uint8_t baseV, psyqo::Vertex &location,
                          uint32_t *kernelRegisters) {
    const RegisterInfo &info = s_registers[number];
    char buffer[32];
    auto x = location.x;
    uint32_t value = 0;
    if (number != 0) {
        if (kernelRegisters) {
            value = kernelRegisters[info.offsetDefault];
        } else {
            value = *(uint32_t *)(info.offsetCustom);
        }
    }
    int len = snprintf(buffer, sizeof(buffer), "%s: 0x%08x", info.name, value);
    printString(buffer, sprite, baseV, location);
    if (number & 1) {
        location.x = x;
        location.y += 16;
    } else {
        location.x = x + 128;
    }
}

static inline uint32_t getCop0BadVAddr() {
    uint32_t r;
    asm("mfc0 %0, $8 ; nop" : "=r"(r));
    return r;
}

static inline uint32_t getCop0EPC() {
    uint32_t r;
    asm("mfc0 %0, $14 ; nop" : "=r"(r));
    return r;
}

[[noreturn]] void psyqo::Kernel::Internal::crashHandler(uint32_t exceptionCode, uint32_t *kernelRegisters) {
    IMASK = 0;
    IREG = 0;
    const bool isPAL = (*((char *)0xbfc7ff52) == 'E');
    GPU_STATUS = 0x00000000;  // reset GPU
    DisplayModeConfig config = {
        .hResolution = HR_640,
        .vResolution = VR_480,
        .videoMode = isPAL ? VM_PAL : VM_NTSC,
        .colorDepth = CD_15BITS,
        .videoInterlace = VI_ON,
        .hResolutionExtended = HRE_NORMAL,
    };
    setDisplayMode(&config);
    setHorizontalRange(0, 0xa00);
    setVerticalRange(16, 255);
    setDisplayArea(0, 2);
    setDrawingArea(0, 0, 640, 480);
    setDrawingOffset(0, 0);

    const Vertex location = {{.x = 960, .y = 464}};
    Prim::VRAMUpload vramUpload;
    vramUpload.region.pos = location;
    vramUpload.region.size = {{.w = 2, .h = 1}};
    sendPrimitive(vramUpload);
    GPU_DATA = 0x7fff0000;
    Prim::FlushCache flushCache;
    sendPrimitive(flushCache);
    Prim::TPage tpage;
    tpage.attr.setPageX(location.x >> 6)
        .setPageY(location.y >> 8)
        .set(Prim::TPageAttr::Tex4Bits)
        .setDithering(false)
        .enableDisplayArea();
    sendPrimitive(tpage);
    Prim::Sprite s;
    s.setColor({{.r = 0x80, .g = 0x80, .b = 0x80}});
    s.size = {{.w = 8, .h = 16}};
    s.texInfo.clut = location;
    const uint8_t baseV = location.y & 0xff;
    enableDisplay();

    IMASK = IRQ_VBLANK;
    while (true) {
        while ((IREG & IRQ_VBLANK) == 0);
        IREG &= ~IRQ_VBLANK;
        FastFill ff = {
            .c = {0, 0, 0},
            .x = 0,
            .y = 0,
            .w = 640,
            .h = 480,
        };
        fastFill(&ff);
        Vertex p = {{.x = 16, .y = 16}};
        printString("Crash handler: ", s, baseV, p);
        printString(s_exceptionNames[exceptionCode], s, baseV, p);
        p.x = 16;
        p.y += 32;
        for (unsigned i = 0; i < 30; i++) {
            if ((i & 1) == 0) {
                p.x = 16;
            }
            printRegister(i, s, baseV, p, kernelRegisters);
        }

        p.x = 300;
        p.y = 48;

        uint32_t badVAddr = getCop0BadVAddr();
        uint32_t epc = getCop0EPC();
        char buffer[32];
        snprintf(buffer, sizeof(buffer), "BadVAddr: 0x%08x", badVAddr);
        printString(buffer, s, baseV, p);
        p.x = 300;
        p.y += 16;
        snprintf(buffer, sizeof(buffer), "EPC     : 0x%08x", epc);
        printString(buffer, s, baseV, p);
        p.x = 300;
        p.y += 16;

        if ((exceptionCode == 8) || (exceptionCode == 9)) {
            uint32_t code = *(uint32_t *)(epc & ~3) >> 6;
            uint32_t category = code >> 10;
            code &= 0x3ff;
            snprintf(buffer, sizeof(buffer), "Code    : %d", code);
            printString(buffer, s, baseV, p);
            p.x = 300;
            p.y += 16;
            snprintf(buffer, sizeof(buffer), "Category: %d", category);
            printString(buffer, s, baseV, p);
            if (category == 7) {
                p.x = 300;
                p.y += 32;
                switch (code) {
                    case 0:
                        printString("Division by zero", s, baseV, p);
                        break;
                }
            }
        }
    }
    __builtin_unreachable();
}
