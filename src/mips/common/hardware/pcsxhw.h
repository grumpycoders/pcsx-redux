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

#pragma once

#include <stdint.h>

static __inline__ void pcsx_putc(int c) { *((volatile char* const)0x1f802080) = c; }
static __inline__ void pcsx_debugbreak() { *((volatile char* const)0x1f802081) = 0; }
static __inline__ void pcsx_execSlot(uint8_t slot) { *((volatile uint8_t* const)0x1f802081) = slot; }
static __inline__ void pcsx_exit(int code) { *((volatile int16_t* const)0x1f802082) = code; }
static __inline__ void pcsx_message(const char* msg) { *((volatile const char** const)0x1f802084) = msg; }
static __inline__ void pcsx_checkKernel(int enable) { *((volatile char*)0x1f802088) = enable; }
static __inline__ int pcsx_isCheckingKernel() { return *((volatile char* const)0x1f802088) != 0; }
static __inline__ void pcsx_initMsan() { *((volatile char* const)0x1f802089) = 0; }
static __inline__ void pcsx_resetMsan() { *((volatile char* const)0x1f802089) = 1; }
static __inline__ void* pcsx_msanAlloc(uint32_t size) {
    register uint32_t a0 asm("a0") = size;
    void* ret;
    __asm__ volatile("lw %0, 0x208c(%1)" : "=r"(ret) : "r"(0x1f800000), "r"(a0));
    return ret;
}
static __inline__ void pcsx_msanFree(void* ptr) { *((void* volatile* const)0x1f80208c) = ptr; }
static __inline__ void* pcsx_msanRealloc(void* ptr, uint32_t size) {
    register void* a0 asm("a0") = ptr;
    register uint32_t a1 asm("a1") = size;
    void* ret;
    __asm__ volatile("lw %0, 0x2090(%1)" : "=r"(ret) : "r"(0x1f800000), "r"(a0), "r"(a1));
    return ret;
}
static __inline__ void pcsx_msanSetChainPtr(void* headerAddr, void* ptrToNext, uint32_t wordCount) {
    register void* a0 asm("a0") = ptrToNext;
    register uint32_t a1 asm("a1") = wordCount;
    __asm__ volatile("sw %0, 0x2094(%1)" : : "r"(a0), "r"(0x1f800000), "r"(a1));
}
static __inline__ void* pcsx_msanGetChainPtr(void* headerAddr) {
    register void* a0 asm("a0") = headerAddr;
    void* ret;
    __asm__ volatile("lw %0, 0x2094(%1)" : "=r"(ret) : "r"(0x1f800000), "r"(a0));
    return ret;
}

static __inline__ int pcsx_present() { return *((volatile uint32_t* const)0x1f802080) == 0x58534350; }
