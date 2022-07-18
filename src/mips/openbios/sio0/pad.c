/*

MIT License

Copyright (c) 2020 PCSX-Redux authors

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

#include "openbios/sio0/pad.h"

#include <memory.h>
#include <stdint.h>

#include "common/syscalls/syscalls.h"


static uint8_t s_padBuffer1[0x22];
static uint8_t s_padBuffer2[0x22];
uint32_t *g_userPadBuffer;

void *fastMemset(void *ptr, int value, size_t num);

int __attribute__((section(".ramtext"))) initPadHighLevel(uint32_t padType, uint32_t *buffer, int c, int d) {
    __asm__ volatile("sw %0, 4($sp)\nsw %1, 8($sp)\nsw %2, 12($sp)" : : "r"(buffer), "r"(c), "r"(d));
    switch (padType) {
        case 0x10000001:
            ramsyscall_printf("TYPE : Dual cross key  ->  not supported!\n");
            break;
        case 0x20000000:
        case 0x20000001:
            ramsyscall_printf("TYPE : 6 free button or flying-V form\n");
            // this is technically an inlined memset here, but I can't deal
            // with the far jumps in debug mode for now.
            fastMemset(s_padBuffer1, 0xff, 0x22);
            fastMemset(s_padBuffer2, 0xff, 0x22);
            initPad(s_padBuffer1, 0x22, s_padBuffer2, 0x22);
            g_userPadBuffer = buffer;
            startPad();
            return 2;
            break;
        default:
            ramsyscall_printf("TYPE : Unknown (%d)  ->  not supported!\n", padType);
            break;
    }

    return 0;
}

static void __attribute__((section(".ramtext"))) alterUserPadData(uint16_t *ptr, uint8_t *input) {
    if (input[0] != 0) return;
    uint8_t c = input[1];
    int is6free = c == 0x41;
    int isFlyingV = c == 0x23;

    if (!is6free && !isFlyingV) return;

    uint16_t o = input[2];
    o <<= 8;
    o |= input[3];
    *ptr = o;

    if (!isFlyingV) return;

    *ptr |= 0x7c7;
    if (input[5] > 0x10) {
        *ptr &= ~0x40;
    }
    if (input[6] > 0x10) {
        *ptr &= ~0x80;
    }
}

uint32_t __attribute__((section(".ramtext"))) readPadHighLevel() {
    uint32_t *ret = g_userPadBuffer;
    uint16_t *ptr = (uint16_t *)ret;
    *ret = 0xffffffff;

    alterUserPadData(ptr++, s_padBuffer1);
    alterUserPadData(ptr++, s_padBuffer2);

    return *ret;
}
