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

#include <source_location>

namespace psyqo {

class Application;

/**
 * @brief The Kernel namespace for internal use.
 *
 * @details The Kernel namespace is technically for internal use
 * only, but it is included in the public API for convenience.
 * It contains various glue to the actual PS1 kernel, as well as
 * some useful utility functions.
 */

namespace Kernel {

namespace Internal {
static inline uint32_t getCop0Status() {
    uint32_t r;
    asm("mfc0 %0, $12 ; nop" : "=r"(r));
    return r;
}

static inline void setCop0Status(uint32_t r) { asm("mtc0 %0, $12 ; nop" : : "r"(r)); }
}  // namespace Internal

/**
 * @brief A faster version of `enterCriticalSection`.
 *
 * @details This function is technically equivalent to `enterCriticalSection`.
 * @return false if the critical section was already entered, true otherwise.
 */
static inline void fastEnterCriticalSection() { asm volatile("mtc0 %0, $12 ; nop ; nop" : : "r"(0x40000000)); }

/**
 * @brief A faster version of `leaveCriticalSection`.
 *
 * @details This function is technically equivalent to `leaveCriticalSection`.
 */
static inline void fastLeaveCriticalSection() { asm volatile("mtc0 %0, $12" : : "r"(0x40000401)); }

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

enum class IRQ : unsigned {
    VBlank,
    GPU,
    CDRom,
    DMA,
    Timer0,
    Timer1,
    Timer2,
    Controller,
    SIO,
    SPU,
    PIO,
    Max,
};

/**
 * @brief Stops the execution of the application.
 */
[[noreturn]] void abort(const char* msg, std::source_location location = std::source_location::current());

/**
 * @brief Takes over the kernel. Can only be called once inside the main function.
 *
 * @details This function will make psyqo take over the retail kernel.
 * This means the application will no longer be able to call any of the
 * kernel functions, and will have to rely on the psyqo kernel instead.
 * Debugging features from third party addons which hook into the kernel
 * will no longer work. Most calls to the kernel will either be no-ops or
 * will crash the application. Most notably, only the `printf` call will
 * be redirected to psyqo's printf, but will not be printing anywhere, so
 * only emulators hooking into A0 calls will be able to see the output.
 *
 * Disabling the kernel is a one-way operation, and cannot be undone.
 * The kernel will be taken over before the first call to `prepare`.
 * The exception handler that psyqo installs will not be able to catch
 * problems, but is much more lightweight and faster than the retail one.
 * Also, 60kB of memory can be reclaimed, and linking the binary with
 * -Xlinker --defsym=TLOAD_ADDR=0x80001000 will allow the application to
 * do just that. This requires a loader able to write into the kernel
 * while disabling interrupts. The ps1-packer tool can achieve that.
 * The first 4kB of memory is reserved for the psyqo kernel.
 *
 * It is noteworthy that while the pros of taking over the kernel are
 * significant, the cons are also significant. The loss of debugging,
 * flexibility, and retail kernel features may not be worth it for most
 * application cases, and should be considered carefully.
 *
 * Last but not least, like with most psyqo features, the added payload
 * to the binary to support the feature will only occur if this function
 * is called.
 */
void takeOverKernel();

/**
 * @brief Returns whether the kernel has been taken over.
 */
bool isKernelTakenOver();

/**
 * @brief Queues an IRQ handler to be called from the exception handler.
 *
 * @details This function is used to queue an IRQ handler to be called
 * from the exception handler when the kernel has been taken over. The
 * VBlank IRQ is excluded from this function, as it is handled by the
 * GPU object instead. Also, note that the kernel has its own DMA IRQ
 * handler, and that the `registerDmaEvent` function should be used
 * instead of trying to queue a handler for the DMA IRQ. The specified
 * handler will be called from the exception handler, with the same
 * restrictions as for any other interrupt handler.
 *
 * @param irq The IRQ to handle.
 * @param lambda The function to call when the IRQ is triggered.
 */
void queueIRQHandler(IRQ irq, eastl::function<void()>&& lambda);

/**
 * @brief A C++ wrapper around the `openEvent` syscall.
 *
 * @details This enables the application to register a C++ lambda
 * for the kernel's OpenEvent call. This will allocate an internal
 * slot, with currently no mechanism to free it. This means that
 * calling `closeEvent` on the resulting event will leak resources.
 * If psyqo took over the kernel, this function will no longer work.
 */
uint32_t openEvent(uint32_t classId, uint32_t spec, uint32_t mode, eastl::function<void()>&& lambda);

/**
 * @brief Sets an ISR callback for a given DMA channel.
 *
 * @details The PSYQo kernel registers a dispatcher interrupt
 * handler for DMA interrupts, and this function registers a
 * callback function for a given DMA channel. Multiple callbacks
 * can be registered for a given channel. All the callbacks
 * registered will be called sequentially during the dispatcher
 * interrupt handler. Note this means the callbacks will be
 * called from the interrupt handler, with the same restrictions
 * as for any other interrupt handler.
 * @return unsigned A slot id for the given callback.
 */
unsigned registerDmaEvent(DMA channel, eastl::function<void()>&& lambda);

/**
 * @brief Flushes the i-cache.
 *
 * @details This function is used to flush the i-cache. This is
 * required when the application has written some code to memory.
 */
void flushCache();

/**
 * @brief Enables the given DMA channel.
 *
 * @param channel the DMA channel to enable.
 * @param priority the priority of the channel.
 */
void enableDma(DMA channel, unsigned priority = 7);

/**
 * @brief Disables the given DMA channel.
 *
 * @param channel the DMA channel to disable.
 */
void disableDma(DMA channel);

/**
 * @brief Frees the given DMA callback slot.
 *
 * @param slot The slot to free, as returned by `registerDmaEvent`.
 */
void unregisterDmaEvent(unsigned slot);

/**
 * @brief Queues a callback to be called from the main thead.
 *
 * @details This function is used to queue a callback to be called
 * from the main thread, during idle moments like various blocking
 * operations. This variant is safe to call from the main thread
 * only. Its usefulness from the main thread is limited, and could
 * be considered the same as JavaScript's `process.nextTick()`,
 * meaning it's a great way to avoid get out of a deep callstack.
 */
void queueCallback(eastl::function<void()>&& lambda);

/**
 * @brief Queues a callback to be called from the main thead.
 *
 * @details This function is used to queue a callback to be called
 * from the main thead, during idle moments like various blocking
 * operations. This variant is safe to call from an interrupt handler.
 * This is how to idiomatically execute something safely from an
 * interrupt handler.
 */
void queueCallbackFromISR(eastl::function<void()>&& lambda);

namespace Internal {
void pumpCallbacks();
void prepare(Application&);
void addInitializer(eastl::function<void(Application&)>&& lambda);
void addOnFrame(eastl::function<void()>&& lambda);
void beginFrame();
}  // namespace Internal

/**
 * @brief A simple `assert` macro.
 */
inline void assert(bool condition, const char* message,
                   std::source_location location = std::source_location::current()) {
    if (!condition) {
        abort(message, location);
        __builtin_unreachable();
    }
}

}  // namespace Kernel

}  // namespace psyqo
