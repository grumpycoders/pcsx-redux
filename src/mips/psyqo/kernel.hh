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

/**
 * @brief Stops the execution of the application.
 */
[[noreturn]] void abort(const char* msg, std::source_location location = std::source_location::current());

/**
 * @brief A C++ wrapper around the `openEvent` syscall.
 *
 * @details This enables the application to register a C++ lambda
 * for the kernel's OpenEvent call. This will allocate an internal
 * slot, with currently no mechanism to free it. This means that
 * calling `closeEvent` on the resulting event will leak resources.
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
void prepare();
void addInitializer(eastl::function<void()>&& lambda);
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
