/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

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

#include <EASTL/functional.h>
#include <stdint.h>

namespace psyqo {

namespace Kernel {

namespace Internal {
static inline uint32_t getCop0Status() {
    uint32_t r;
    asm("mfc0 %0, $12 ; nop" : "=r"(r));
    return r;
}

static inline void setCop0Status(uint32_t r) { asm("mtc0 %0, $12 ; nop" : : "r"(r)); }
}  // namespace Internal

static inline bool fastEnterCriticalSection() {
    uint32_t sr = Internal::getCop0Status();
    Internal::setCop0Status(sr & ~0x401);
    return (sr & 0x401) == 0x401;
}

static inline void fastLeaveCriticalSection() {
    uint32_t sr = Internal::getCop0Status();
    sr |= 0x401;
    Internal::setCop0Status(sr);
}

enum class DMA : unsigned {
    MDECin,
    MDECout,
    GPU,
    CDRom,
    SPU,
    EXP1,
    OTC,
    Max,
};

void abort(const char* msg);
uint32_t openEvent(uint32_t classId, uint32_t spec, uint32_t mode, eastl::function<void()>&& lambda);
unsigned registerDmaEvent(DMA channel, eastl::function<void()>&& lambda);
void enableDma(DMA channel, unsigned priority = 7);
void disableDma(DMA channel);
void unregisterDmaEvent(unsigned slot);

void queueCallback(eastl::function<void()>&& lambda);
void queueCallbackFromISR(eastl::function<void()>&& lambda);

void pumpCallbacks();

namespace Internal {
void prepare();
void addOnFrame(eastl::function<void()>&& lambda);
void beginFrame();
}  // namespace Internal

inline void assert(bool condition, const char* message) {
    if (!condition) abort(message);
}

}  // namespace Kernel

}  // namespace psyqo
