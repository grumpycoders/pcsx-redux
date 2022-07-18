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

#include <stdint.h>

void cpu_early_init() {}

void cpu_init() {}

void cpu_late_init() {}

static inline uint32_t getCop0Status() {
    uint32_t r;
    asm("mfc0 %0, $12 ; nop" : "=r"(r));
    return r;
}

static inline void setCop0Status(uint32_t r) {
    asm("mtc0 %0, $12 ; nop" : : "r"(r));
}

static inline int fastEnterCriticalSection() {
    uint32_t sr = getCop0Status();
    setCop0Status(sr & ~0x401);
    return (sr & 0x401) == 0x401;
}

static inline void fastLeaveCriticalSection() {
    uint32_t sr = getCop0Status();
    sr |= 0x401;
    setCop0Status(sr);
}

__attribute__((weak)) int8_t __sync_fetch_and_add_1(int8_t* ptr, int8_t arg) {
    int needsToLeaveCS = fastEnterCriticalSection();
    int8_t r = *ptr;
    *ptr += arg;
    if (needsToLeaveCS) {
        fastLeaveCriticalSection();
    }
    return r;
}
