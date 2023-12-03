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

#include "psyqo/kernel.hh"

#include <EASTL/atomic.h>
#include <EASTL/bonus/fixed_ring_buffer.h>
#include <EASTL/fixed_vector.h>
#include <stdint.h>

#include "common/hardware/pcsxhw.h"
#include "common/kernel/events.h"
#include "common/syscalls/syscalls.h"
#include "common/util/encoder.hh"
#include "psyqo/hardware/cpu.hh"

namespace {

typedef void (*KernelEventFunction)();

struct Function {
    uint32_t code[2] = {0, 0};
    eastl::function<void()> lambda = nullptr;
    KernelEventFunction getFunction() {
        uintptr_t p = reinterpret_cast<uintptr_t>(code);
        return reinterpret_cast<KernelEventFunction>(p);
    }
};

constexpr unsigned SLOTS = 16;

Function s_functions[SLOTS];

void trampoline(int slot) { s_functions[slot].lambda(); }

KernelEventFunction allocateEventFunction(eastl::function<void()>&& lambda) {
    for (unsigned slot = 0; slot < SLOTS; slot++) {
        if (!s_functions[slot].lambda) {
            s_functions[slot].code[0] = Mips::Encoder::j(reinterpret_cast<uint32_t>(trampoline));
            s_functions[slot].code[1] = Mips::Encoder::addiu(Mips::Encoder::Reg::A0, Mips::Encoder::Reg::R0, slot);
            s_functions[slot].lambda = eastl::move(lambda);
            syscall_flushCache();
            return s_functions[slot].getFunction();
        }
    }
    psyqo::Kernel::abort("allocateEventFunction: no function slot available");
    return reinterpret_cast<void (*)()>(-1);
}

}  // namespace

[[noreturn]] void psyqo::Kernel::abort(const char* msg) {
    fastEnterCriticalSection();
    pcsx_message(msg);
    pcsx_debugbreak();
    syscall_puts(msg);
    syscall_putchar('\n');
    while (1) asm("");
}

uint32_t psyqo::Kernel::openEvent(uint32_t classId, uint32_t spec, uint32_t mode, eastl::function<void()>&& lambda) {
    auto function = allocateEventFunction(eastl::move(lambda));
    return syscall_openEvent(classId, spec, mode, function);
}

namespace {
eastl::function<void()> s_dmaCallbacks[7][SLOTS];
}

unsigned psyqo::Kernel::registerDmaEvent(DMA channel_, eastl::function<void()>&& lambda) {
    unsigned channel = static_cast<unsigned>(channel_);
    if (channel >= static_cast<unsigned>(DMA::Max)) {
        psyqo::Kernel::abort("registerDmaEvent: invalid dma channel");
    }
    auto& slots = s_dmaCallbacks[channel];
    for (unsigned slot = 0; slot < SLOTS; slot++) {
        if (!slots[slot]) {
            slots[slot] = eastl::move(lambda);
            return (channel << 16) | slot;
        }
    }

    psyqo::Kernel::abort("registerDmaEvent: no function slot available");
    return 0xffffffff;
}

void psyqo::Kernel::enableDma(DMA channel_, unsigned priority) {
    unsigned channel = static_cast<unsigned>(channel_);
    if (channel >= static_cast<unsigned>(DMA::Max)) {
        psyqo::Kernel::abort("enableDma: invalid dma channel");
    }
    uint32_t dpcr = Hardware::CPU::DPCR;
    if (priority > 7) priority = 7;
    unsigned shift = channel * 4;
    uint32_t mask = 15 << shift;
    dpcr &= ~mask;
    mask = priority;
    mask |= 8;
    mask <<= shift;
    dpcr |= mask;
    Hardware::CPU::DPCR = dpcr;
}

void psyqo::Kernel::disableDma(DMA channel_) {
    unsigned channel = static_cast<unsigned>(channel_);
    if (channel >= static_cast<unsigned>(DMA::Max)) {
        psyqo::Kernel::abort("disableDma: invalid dma channel");
    }
    uint32_t dpcr = Hardware::CPU::DPCR;
    unsigned shift = channel * 4;
    uint32_t mask = 15 << shift;
    dpcr &= ~mask;
    Hardware::CPU::DPCR = dpcr;
}

void psyqo::Kernel::unregisterDmaEvent(unsigned slot) {
    unsigned channel = slot >> 16;
    slot &= 0xffff;

    if ((channel >= static_cast<unsigned>(DMA::Max)) || (slot >= SLOTS) || !s_dmaCallbacks[channel][slot]) {
        psyqo::Kernel::abort("unregisterDmaEvent: function wasn't previously allocated.");
    }
    s_dmaCallbacks[channel][slot] = nullptr;
}

namespace {
auto& getInitializers() {
    static eastl::fixed_vector<eastl::function<void()>, 12> initializers;
    return initializers;
}
}  // namespace

void psyqo::Kernel::Internal::addInitializer(eastl::function<void()>&& lambda) {
    getInitializers().push_back(eastl::move(lambda));
}

void psyqo::Kernel::Internal::prepare() {
    syscall_dequeueCDRomHandlers();
    syscall_setDefaultExceptionJmpBuf();
    uint32_t event = syscall_openEvent(EVENT_DMA, 0x1000, EVENT_MODE_CALLBACK, []() {
        uint32_t dicr = Hardware::CPU::DICR;
        uint32_t dirqs = dicr >> 24;
        dicr &= 0xffffff;
        uint32_t ack = 0x80;

        for (unsigned irq = 0; irq < 7; irq++) {
            uint32_t mask = 1 << irq;
            if (dirqs & mask) {
                ack |= mask;
            }
        }

        ack <<= 24;
        dicr |= ack;
        Hardware::CPU::DICR = dicr;

        for (unsigned irq = 0; irq < 7; irq++) {
            uint32_t mask = 1 << irq;
            if (dirqs & mask) {
                for (auto& lambda : s_dmaCallbacks[irq]) {
                    if (lambda) lambda();
                }
            }
        }
    });
    syscall_enableEvent(event);
    Hardware::CPU::IMask.set(Hardware::CPU::IRQ::DMA);
    uint32_t dicr = Hardware::CPU::DICR;
    dicr &= 0xffffff;
    dicr |= 0x800000;
    Hardware::CPU::DICR = dicr;
    syscall_setIrqAutoAck(3, 1);

    for (auto& i : getInitializers()) i();
}

namespace {
uint32_t s_flag = 0;
eastl::fixed_ring_buffer<eastl::function<void()>, 128> s_callbacks(128);
}

void psyqo::Kernel::queueCallback(eastl::function<void()>&& lambda) {
    fastEnterCriticalSection();
    s_flag = 1;
    s_callbacks.push_back(eastl::move(lambda));
    fastLeaveCriticalSection();
}

void psyqo::Kernel::queueCallbackFromISR(eastl::function<void()>&& lambda) {
    s_callbacks.push_back() = eastl::move(lambda);
    s_flag = 1;
    eastl::atomic_signal_fence(eastl::memory_order_release);
}

void psyqo::Kernel::Internal::pumpCallbacks() {
    eastl::atomic_signal_fence(eastl::memory_order_acquire);
    if (s_flag == 0) return;
    fastEnterCriticalSection();
    s_flag = 0;
    while (!s_callbacks.empty()) {
        auto& l = s_callbacks.front();
        fastLeaveCriticalSection();
        l();
        fastEnterCriticalSection();
        s_callbacks.pop_front();
    }
    fastLeaveCriticalSection();
}

namespace {
auto& getBeginFrameEvents() {
    static eastl::fixed_vector<eastl::function<void()>, 128> beginFrameEvents;
    return beginFrameEvents;
}
}  // namespace

void psyqo::Kernel::Internal::addOnFrame(eastl::function<void()>&& lambda) {
    getBeginFrameEvents().push_back(eastl::move(lambda));
}

void psyqo::Kernel::Internal::beginFrame() {
    for (auto& f : getBeginFrameEvents()) {
        f();
    }
}
