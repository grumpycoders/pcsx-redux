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

// https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-18048.html
struct BuildId {
    uint32_t namesz;
    uint32_t descsz;
    uint32_t type;
    uint8_t strings[];
};

static inline int isOpenBiosPresent() {
    uintptr_t* a0table = (uintptr_t*)0x200;
    return (a0table[11] & 3) == 1;
}

static inline uint32_t getOpenBiosApiVersion() {
    if (!isOpenBiosPresent()) return 0;
    register int n asm("t1") = 0x00;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    uintptr_t* a0table = (uintptr_t*)0x200;
    return ((uint32_t(*)())(a0table[11] ^ 1))();
}

static inline struct BuildId* getOpenBiosBuildId() {
    if (!isOpenBiosPresent()) return 0;
    register int n asm("t1") = 0x01;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    uintptr_t* a0table = (uintptr_t*)0x200;
    return ((struct BuildId * (*)())(a0table[11] ^ 1))();
}
