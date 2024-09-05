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

#include <EASTL/array.h>
#include <EASTL/atomic.h>
#include <EASTL/bonus/fixed_ring_buffer.h>
#include <EASTL/fixed_vector.h>
#include <stdint.h>

#include "common/hardware/dma.h"
#include "common/hardware/pcsxhw.h"
#include "common/kernel/events.h"
#include "common/syscalls/syscalls.h"
#include "common/util/encoder.hh"
#include "psyqo/application.hh"
#include "psyqo/hardware/cpu.hh"
#include "psyqo/spu.hh"
#include "psyqo/xprintf.h"

namespace {

bool s_tookOverKernel = false;

eastl::array<eastl::fixed_vector<eastl::function<void()>, 12>, static_cast<size_t>(psyqo::Kernel::IRQ::Max) - 1>*
    s_irqHandlers = nullptr;
eastl::array<eastl::fixed_vector<eastl::function<void()>, 12>, static_cast<size_t>(psyqo::Kernel::IRQ::Max) - 1>
    s_irqHandlersStorage;

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
    psyqo::Kernel::assert(!s_tookOverKernel, "allocateEventFunction: kernel has been taken over");
    for (unsigned slot = 0; slot < SLOTS; slot++) {
        if (!s_functions[slot].lambda) {
            s_functions[slot].lambda = eastl::move(lambda);
            return s_functions[slot].getFunction();
        }
    }
    psyqo::Kernel::abort("allocateEventFunction: no function slot available");
    __builtin_unreachable();
}

int printfStub(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int r = vxprintf([](const char* data, int size, void*) { syscall_write(1, data, size); }, nullptr, fmt, args);
    va_end(args);
    return r;
}

}  // namespace

bool psyqo::Kernel::isKernelTakenOver() { return s_tookOverKernel; }

extern "C" {
void psyqoExceptionHandler(uint32_t ireg) {
    constexpr uint32_t start = static_cast<uint32_t>(psyqo::Kernel::IRQ::GPU) - 1;
    constexpr uint32_t end = static_cast<uint32_t>(psyqo::Kernel::IRQ::Max) - 1;
    uint32_t mask = 1 << (start + 1);
    for (uint32_t irq = start; irq < end; irq++, mask <<= 1) {
        if ((ireg & mask) == 0) continue;
        auto& handlers = s_irqHandlersStorage[irq];
        for (auto& handler : handlers) handler();
    }
}
void psyqoAssemblyExceptionHandler();
}

void psyqo::Kernel::takeOverKernel() {
    if (s_tookOverKernel) return;
    s_irqHandlers = &s_irqHandlersStorage;
    s_tookOverKernel = true;
    Internal::addInitializer([](Application& application) {
        __builtin_memset(nullptr, 0, 0x1000);
        application.gpu().prepareForTakeover();
        uint32_t* const exceptionHandler = reinterpret_cast<uint32_t*>(0x80);
        exceptionHandler[0] = Mips::Encoder::j(reinterpret_cast<uint32_t>(psyqoAssemblyExceptionHandler));
        exceptionHandler[1] = Mips::Encoder::nop();
        uint32_t* const handlers = reinterpret_cast<uint32_t*>(0xa0);
        // We want to redirect printf, but nothing else.
        uintptr_t printfAddr = reinterpret_cast<uintptr_t>(printfStub);
        uint16_t hi = printfAddr >> 16;
        uint16_t lo = printfAddr & 0xffff;
        if (lo >= 0x8000) hi++;
        // a0
        handlers[0] = Mips::Encoder::addiu(Mips::Encoder::Reg::T0, Mips::Encoder::Reg::R0, 0x3f);
        handlers[1] = Mips::Encoder::beq(Mips::Encoder::Reg::T1, Mips::Encoder::Reg::T0, 12);
        handlers[2] = Mips::Encoder::lui(Mips::Encoder::Reg::T0, hi);
        handlers[3] = Mips::Encoder::nop();
        // b0
        handlers[4] = Mips::Encoder::jr(Mips::Encoder::Reg::RA);
        handlers[5] = Mips::Encoder::addiu(Mips::Encoder::Reg::T0, Mips::Encoder::Reg::T0, lo);
        handlers[6] = Mips::Encoder::jr(Mips::Encoder::Reg::T0);
        handlers[7] = Mips::Encoder::nop();
        // c0
        handlers[8] = Mips::Encoder::jr(Mips::Encoder::Reg::RA);
        handlers[9] = Mips::Encoder::nop();
        flushCache();
    });
}

void psyqo::Kernel::queueIRQHandler(IRQ irq, eastl::function<void()>&& lambda) {
    Kernel::assert(irq != IRQ::VBlank, "queueIRQHandler: VBlank cannot be queued");
    auto& handlers = *s_irqHandlers;
    size_t index = static_cast<size_t>(irq) - 1;
    Kernel::assert(index < handlers.size(), "queueIRQHandler: invalid irq");
    Kernel::assert(s_tookOverKernel, "queueIRQHandler: kernel not taken over");
    handlers[index].push_back(eastl::move(lambda));
}

[[noreturn]] void psyqo::Kernel::abort(const char* msg, std::source_location loc) {
    fastEnterCriticalSection();
    ramsyscall_printf("Abort at %s:%i: %s\n", loc.file_name(), loc.line(), msg);
    pcsx_message(msg);
    pcsx_debugbreak();
    while (1) asm("");
    __builtin_unreachable();
}

uint32_t psyqo::Kernel::openEvent(uint32_t classId, uint32_t spec, uint32_t mode, eastl::function<void()>&& lambda) {
    auto function = allocateEventFunction(eastl::move(lambda));
    return syscall_openEvent(classId, spec, mode, function);
}

namespace {
eastl::function<void()> s_dmaCallbacks[static_cast<unsigned>(psyqo::Kernel::DMA::Max)][4];
}

unsigned psyqo::Kernel::registerDmaEvent(DMA channel_, eastl::function<void()>&& lambda) {
    unsigned channel = static_cast<unsigned>(channel_);
    if (channel >= static_cast<unsigned>(DMA::Max)) {
        psyqo::Kernel::abort("registerDmaEvent: invalid dma channel");
        __builtin_unreachable();
    }
    auto& slots = s_dmaCallbacks[channel];
    for (unsigned slot = 0; slot < SLOTS; slot++) {
        if (!slots[slot]) {
            slots[slot] = eastl::move(lambda);
            return (channel << 16) | slot;
        }
    }

    psyqo::Kernel::abort("registerDmaEvent: no function slot available");
    __builtin_unreachable();
}

void psyqo::Kernel::enableDma(DMA channel_, unsigned priority) {
    unsigned channel = static_cast<unsigned>(channel_);
    if (channel >= static_cast<unsigned>(DMA::Max)) {
        psyqo::Kernel::abort("enableDma: invalid dma channel");
        __builtin_unreachable();
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
        __builtin_unreachable();
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
        __builtin_unreachable();
    }
    s_dmaCallbacks[channel][slot] = nullptr;
}

namespace {
auto& getInitializers() {
    static eastl::fixed_vector<eastl::function<void(psyqo::Application&)>, 12> initializers;
    return initializers;
}
}  // namespace

void psyqo::Kernel::Internal::addInitializer(eastl::function<void(Application&)>&& lambda) {
    getInitializers().push_back(eastl::move(lambda));
}

namespace {
void dmaIRQ() {
    psyqo::Hardware::CPU::IReg.clear(psyqo::Hardware::CPU::IRQ::DMA);
    uint32_t dicr = psyqo::Hardware::CPU::DICR;
    uint32_t dirqs = dicr >> 24;
    dicr &= 0xff7fff;
    uint32_t ack = 0x80;

    for (unsigned dma = 0; dma < static_cast<unsigned>(psyqo::Kernel::DMA::Max); dma++) {
        uint32_t mask = 1 << dma;
        if (dirqs & mask) {
            ack |= mask;
        }
    }

    ack <<= 24;
    dicr |= ack;
    psyqo::Hardware::CPU::DICR = dicr;

    for (unsigned dma = 0; dma < static_cast<unsigned>(psyqo::Kernel::DMA::Max); dma++) {
        uint32_t mask = 1 << dma;
        if (dirqs & mask) {
            for (auto& lambda : s_dmaCallbacks[dma]) {
                if (lambda) lambda();
            }
        }
    }
}
}  // namespace

void psyqo::Kernel::Internal::prepare(Application& application) {
    SPU::reset();
    Hardware::CPU::IMask.clear();
    Hardware::CPU::IReg.clear();
    for (unsigned i = 0; i < 7; i++) {
        DMA_CTRL[i].CHCR = 0;
        DMA_CTRL[i].BCR = 0;
        DMA_CTRL[i].MADR = 0;
    }
    Hardware::CPU::DPCR = 0;
    uint32_t dicr = Hardware::CPU::DICR;
    Hardware::CPU::DICR = dicr;
    Hardware::CPU::DICR = 0;
    for (unsigned slot = 0; slot < SLOTS; slot++) {
        s_functions[slot].code[0] = Mips::Encoder::j(reinterpret_cast<uint32_t>(trampoline));
        s_functions[slot].code[1] = Mips::Encoder::addiu(Mips::Encoder::Reg::A0, Mips::Encoder::Reg::R0, slot);
    }
    if (!s_tookOverKernel) {
        syscall_flushCache();
        struct KernelData {
            void* data;
            uint32_t size;
        };
        KernelData* const handlers = reinterpret_cast<KernelData*>(0x100);
        KernelData* const events = reinterpret_cast<KernelData*>(0x120);
        __builtin_memset(handlers->data, 0, handlers->size);
        __builtin_memset(events->data, 0, events->size);
        syscall_setDefaultExceptionJmpBuf();
        syscall_enqueueSyscallHandler(0);
        syscall_enqueueIrqHandler(3);
        syscall_enqueueRCntIrqs(1);
        uint32_t event = syscall_openEvent(EVENT_DMA, 0x1000, EVENT_MODE_CALLBACK, dmaIRQ);
        syscall_enableEvent(event);
    } else {
        queueIRQHandler(IRQ::DMA, dmaIRQ);
    }
    Hardware::CPU::IMask.set(Hardware::CPU::IRQ::DMA);
    dicr = Hardware::CPU::DICR;
    dicr &= 0xffffff;
    dicr |= 0x800000;
    Hardware::CPU::DICR = dicr;

    for (auto& i : getInitializers()) i(application);
}

namespace {
uint32_t s_flag = 0;
eastl::fixed_ring_buffer<eastl::function<void()>, 32> s_callbacks(32);
}  // namespace

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
eastl::fixed_vector<eastl::function<void()>, 32> s_beginFrameEvents;
}  // namespace

void psyqo::Kernel::Internal::addOnFrame(eastl::function<void()>&& lambda) {
    s_beginFrameEvents.push_back(eastl::move(lambda));
}

void psyqo::Kernel::Internal::beginFrame() {
    for (auto& f : s_beginFrameEvents) {
        f();
    }
}
