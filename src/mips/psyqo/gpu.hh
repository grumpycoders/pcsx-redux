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

#include <EASTL/array.h>
#include <EASTL/atomic.h>
#include <EASTL/functional.h>
#include <EASTL/utility.h>
#include <stdint.h>

#include "common/hardware/hwregs.h"
#include "psyqo/primitives.hh"

namespace psyqo {

namespace DMA {

enum DmaCallback {
    FROM_ISR,
    FROM_MAIN_LOOP,
};

}

/**
 * @brief The singleton GPU class.
 *
 * @details This class shouldn't be instantiated directly. It is a singleton instantiated
 * within the `Application` class, and accessed using the `gpu` method. It contains
 * the current state of the psyqo renderer, and provides various helpers for rendering.
 */

class GPU {
  public:
    struct Configuration;
    enum class Resolution { W256, W320, W368, W512, W640 };
    enum class VideoMode { AUTO, NTSC, PAL };
    enum class ColorMode { C15BITS, C24BITS };
    enum class Interlace { PROGRESSIVE, INTERLACED };
    void initialize(const Configuration &config);

    static constexpr uint32_t US_PER_HBLANK = 64;

    /**
     * @brief Returns the refresh rate of the GPU.
     *
     * @details This method will return either 60 or 50, depending on the current
     * video mode.
     */
    unsigned getRefreshRate() const { return m_refreshRate; }

    /**
     * @brief Returns the number of frames rendered by the GPU so far.
     *
     * @details This returns the internal frame counter being kept by the
     * GPU class. The 32 bits value will wrap around when it reaches 2^32
     * frames, which is 2 years, 3 months, 7 days, 6 hours, 6 minutes and
     * 28.27 seconds when running constantly at a 60Hz refresh rate.
     */
    uint32_t getFrameCount() const { return m_frameCount; }

    /**
     * @brief Immediately clears the drawing buffer.
     *
     * @details This method will immediately clear the drawing buffer
     * with the specified color.
     * @param bg The color to fill the drawing buffer with.
     */
    void clear(Color bg = {{0, 0, 0}});

    /**
     * @brief Sets a `FastFill` primitive to clear the current drawing buffer.
     *
     * @details This method will set the `FastFill` primitive passed as
     * an argument in a way to completely clear the current drawing buffer with
     * the specified color. This will be done in accordance to the current
     * drawing buffer settings.
     * @param ff The `FastFill` primitive to set.
     * @param end The color to issue.
     */
    void getClear(Prim::FastFill &ff, Color bg = {{0, 0, 0}}) const;

    /**
     * @brief Sets a `FastFill` primitive to clear the next drawing buffer.
     *
     * @details This method will set the `FastFill` primitive passed as
     * an argument in a way to completely clear the next drawing buffer with
     * the specified color. This will be done in accordance to the next
     * drawing buffer settings, after a flip. This is useful for clearing the
     * buffer within a dma chain to be sent during the frame flip.
     * @param ff The `FastFill` primitive to set.
     * @param end The color to issue.
     */
    void getNextClear(Prim::FastFill &ff, Color bg = {{0, 0, 0}}) const;

    /**
     * @brief Uploads a buffer to the VRAM as a blocking call.
     *
     * @details This method will immediately upload the specified set of
     * pixels to the VRAM, at the specified location and size. The GPU
     * cache will be flushed. It will block until completion of the upload.
     * @param data The pixels to upload. Must be a contiguous array of
     * 16-bpp pixels, with the number of pixels being equal to the area
     * specified by the `region` parameter.
     * @param region The region in VRAM to upload the pixels to.
     */
    void uploadToVRAM(const uint16_t *data, Rect region);

    /**
     * @brief Uploads a buffer to the VRAM as a non-blocking call.
     *
     * @details This method will initiate an upload of the specified set of
     * pixels to the VRAM, at the specified location and size. The GPU
     * cache will be flushed. It will return immediately, and the upload
     * will be performed in the background. Upon completion, the specified
     * callback will be called. If `dmaCallback` is set to `FROM_ISR`, the
     * callback will be called from the interrupt handler, and care must be
     * taken to properly synchronize variable changes. Please use the EASTL's
     * `atomic_signal_fence` function for this purpose. If `dmaCallback`
     * is set to `FROM_MAIN_LOOP`, the callback will be called in the same
     * execution context as the main loop, and it is therefore safe to access
     * variables there. The callback will thus be called between calls to the
     * current scene's `frame` method, or during `Kernel::pumpCallbacks()`.
     * Note that during the upload, no GPU operation should be performed.
     * @param data The pixels to upload. Must be a contiguous array of
     * 16-bpp pixels, with the number of pixels being equal to the area
     * specified by the `region` parameter.
     * @param region The region in VRAM to upload the pixels to.
     * @param callback The callback to call upon completion.
     * @param dmaCallback `DMA::FROM_MAIN_LOOP` or `DMA::FROM_ISR`.
     */
    void uploadToVRAM(const uint16_t *data, Rect region, eastl::function<void()> &&callback,
                      DMA::DmaCallback dmaCallback = DMA::FROM_MAIN_LOOP);

    /**
     * @brief Immediately sends a fragment to the GPU. This is a blocking operation.
     * See the fragments.hh file for more information.
     *
     * @param fragment The fragment to send to the GPU.
     */
    template <typename Fragment>
    void sendFragment(const Fragment &fragment) {
        sendFragment(&fragment.head + 1, fragment.getActualFragmentSize());
    }

    /**
     * @brief Sends a fragment to the GPU as a non-blocking call.
     *
     * @details See the non-blocking variant of `uploadToVRAM` for more information about asynchronous transfers.
     *
     * @param fragment The fragment to send to the GPU.
     * @param callback The callback to call upon completion.
     * @param dmaCallback `DMA::FROM_MAIN_LOOP` or `DMA::FROM_ISR`.
     */
    template <typename Fragment>
    void sendFragment(const Fragment &fragment, eastl::function<void()> &&callback,
                      DMA::DmaCallback dmaCallback = DMA::FROM_MAIN_LOOP) {
        sendFragment(&fragment.head + 1, fragment.getActualFragmentSize(), eastl::move(callback), dmaCallback);
    }

    /**
     * @brief Immediately disables the scissoring of the VRAM.
     */
    void disableScissor();

    /**
     * @brief Enables the scissoring of the VRAM.
     *
     * @details This method will enable the scissoring of the VRAM,
     * and will clip the drawing to the currently active buffer.
     */
    void enableScissor();

    /**
     * @brief Gets the current scissoring region.
     *
     * @details This method will set the scissor primitive to the currently
     * active drawing buffer.
     * @param scissor The scissor primitive to set.
     */
    void getScissor(Prim::Scissor &scissor);

    /**
     * @brief Gets the next scissoring region.
     *
     * @details This method will set the scissor primitive to the next
     * active drawing buffer. This is useful for setting the scissor
     * within a dma chain to be sent during the frame flip.
     * @param scissor The scissor primitive to set.
     */
    void getNextScissor(Prim::Scissor &scissor);

    /**
     * @brief Waits until the GPU is ready to send a command.
     */
    static void waitReady();

    /**
     * @brief Sends a raw 32 bits value to the GP0 register of the GPU.
     */
    static void sendRaw(uint32_t data) { GPU_DATA = data; }
    template <typename Primitive>

    /**
     * @brief Sends a primitive to the GPU. This is a blocking call.
     *
     * @details This method will immediately send the specified primitive to the GPU.
     * @param primitive The primitive to send to the GPU.
     */
    static void sendPrimitive(const Primitive &primitive) {
        static_assert((sizeof(Primitive) % 4) == 0, "Primitive's size must be a multiple of 4");
        waitReady();
        const uint32_t *ptr = reinterpret_cast<const uint32_t *>(&primitive);
        size_t size = sizeof(Primitive) / sizeof(uint32_t);
        for (int i = 0; i < size; i++) {
            sendRaw(*ptr++);
        }
    }

    /**
     * @brief Chains a fragment to the next DMA chain transfer.
     *
     * @details This method will chain a fragment to the next DMA chain transfer. DMA Chaining is a complex
     * operation, and it is recommended that you use the `sendFragment` method instead if you are unsure.
     * This can be used while a DMA chain is being sent. Use the `sendChain` method to transfer the DMA chain
     * during the current frame, or simply return from the current scene's `frame` method to transfer the
     * DMA chain automatically during the frame flip operation. Note that the latter means the DMA chain
     * will render on the _next_ rendered frame, thus creating a sort of triple buffering system. The
     * constructed DMA chain will thus need to be using the `Next` variants of the primitive constructors,
     * if applicable.
     * @param fragment The fragment to chain.
     */
    template <typename Fragment>
    void chain(Fragment &fragment) {
        chain(&fragment.head, fragment.getActualFragmentSize());
    }

    /**
     * @brief Immediately sends the current DMA chain
     *
     * @details This method will immediately send the current DMA chain to the GPU, and block until completion.
     */
    void sendChain();

    /**
     * @brief Initiates the transfer of the current DMA chain.
     *
     * @details See the non-blocking variant of `uploadToVRAM` for more information about asynchronous transfers.
     * @param callback The callback to call upon completion.
     * @param dmaCallback `DMA::FROM_MAIN_LOOP` or `DMA::FROM_ISR`.
     */
    void sendChain(eastl::function<void()> &&callback, DMA::DmaCallback dmaCallback = DMA::FROM_MAIN_LOOP);

    /**
     * @brief Gets the status of the background DMA transfer operation when initiated by a frame flip.
     *
     * @return true if no background DMA transfer is in progress nor completed.
     */
    bool isChainIdle() const;

    /**
     * @brief Gets the status of the background DMA transfer operation when initiated by a frame flip.
     *
     * @return true if a background DMA transfer is in progress.
     */
    bool isChainTransferring() const;

    /**
     * @brief Gets the status of the background DMA transfer operation when initiated by a frame flip.
     *
     * @return true if a background DMA transfer has completed, and is now waiting for a frame flip.
     */
    bool isChainTransferred() const;

    /**
     * @brief Gets the current timestamp in microseconds.
     *
     * @details The current timestamp is in microseconds. It will wrap around after a bit more than
     * an hour, so it shouldn't be used for deadlines that are more than 30 minutes away. This relies
     * on root counter 1 set in hsync mode without any target value. The value will be updated
     * during the idle moments of the page flip, without relying on interrupts. The precision isn't
     * really good, as it assumes one scanline runs at 64ms, but it should be good enough for most
     * purposes. Creating a stopwatch out of it should show that it's running a bit too fast,
     * approximately 1 second too fast every minute or so. Its monotonicity should be proper however.
     *
     * The method `now()` should be reserved for interacting with timers. If longer span is required,
     * with more accuracy but less precision, for something that's not related with timers, then the
     * current amount of time in seconds since the application started can simply be obtained using
     * `getFrameCount() / getRefreshRate()`.
     * @return The current timestamp in microseconds.
     */
    uint32_t now() const { return m_currentTime; }

    /**
     * @brief Creates a single-use timer.
     *
     * @details This method will create a single-use timer. The timer will fire after the specified
     * deadline has passed. Timers will only fire during the idle period of the CPU, between calls
     * to the `frame` method of the current scene. If the scene takes too long to complete,
     * timers may significantly be delayed past their set deadline. The deadline can be computed
     * based on the return value of the `now()` method. It is okay if the deadline rolls over
     * their 32 bits span. Simply doing `gpu().now() + DELAY_IN_MICROSECONDS` will still work,
     * as long as the delay isn't greater than 30 minutes. Single-use timers will automatically
     * be disabled upon being fired, and their id will no longer be valid. The returned id is
     * guaranteed to be unique across active timers, but may collision with the id of timers
     * that got canceled or got disabled on their own.
     * @param deadline The deadline of the timer in microseconds.
     * @param callback The callback function to be called when the timer expires.
     * @return The id of the created timer.
     */
    uintptr_t armTimer(uint32_t deadline, eastl::function<void(uint32_t)> &&callback);

    /**
     * @brief Creates a periodic timer.
     *
     * @details This method will create a periodic timer. The timer will fire every `period` microseconds.
     * See the `armTimer` method for more information about timers in general. Periodic timers
     * will first fire at `now() + period` microseconds, and then every `period` microseconds thereafter.
     * They will never be canceled automatically.
     * @param period The period of the timer in microseconds.
     * @param callback The callback function to be called when the timer expires.
     * @return The id of the created timer.
     */
    unsigned armPeriodicTimer(uint32_t period, eastl::function<void(uint32_t)> &&callback);

    /**
     * @brief Changes the period of a periodic timer.
     *
     * @details This method will change the period of a periodic timer. The timer now will fire
     * every `period` microseconds instead of its previous period. When the `reset` argument is
     * false, the next deadline for the timer will be adjusted according to the difference
     * between the new period and the previous one. If the new period is shorter, and the
     * deadline goes in the past, the timer will fire as soon as possible. When the `reset`
     * argument is true, the new deadline will simply be set to the new `period`.
     * This method has no effect if the timer is not periodic.
     * @param id The id of the timer to change.
     * @param period The new period of the timer.
     * @param reset The timer's deadline will be adjusted to the new period if false.
     */
    void changeTimerPeriod(uintptr_t id, uint32_t period, bool reset = false);

    /**
     * @brief Pauses a timer.
     *
     * @details This method will pause a timer. It will not fire anymore, even if its deadline
     * had already passed at the moment of this call, but it will remain active, and its id
     * will remain valid. The remainder of the deadline will be remembered, for when the timer
     * is resumed. This method has no effect if the timer is already paused.
     * @param id The id of the timer to pause.
     */
    void pauseTimer(uintptr_t id);

    /**
     * @brief Resumes a paused timer.
     *
     * @details This method will resume a paused timer. The timer will be able to fire again,
     * according to its original settings. The new deadline will be calculated from the
     * remainder of the time left when it was paused. This method will have no effect if the
     * timer is not paused.
     * @param id The id of the timer to resume.
     */
    void resumeTimer(uintptr_t id);

    /**
     * @brief Cancels a timer.
     *
     * @details This method will cancel an active timer. The timer will no longer fire.
     * Its id will no longer be valid.
     * @param id The id of the timer to cancel.
     */
    void cancelTimer(uintptr_t id);

    /**
     * @brief Runs one round of event processing.
     *
     * @details While this method is technically for internal use, it is exposed here
     * for convenience. It will run one round of event processing, including the
     * processing of timers. This method should be called in a loop when waiting
     * for other events to be processed.
     */
    void pumpCallbacks();

  private:
    void sendFragment(const uint32_t *data, size_t count);
    void sendFragment(const uint32_t *data, size_t count, eastl::function<void()> &&callback,
                      DMA::DmaCallback dmaCallback);
    void chain(uint32_t *head, size_t count);

    eastl::function<void(void)> m_dmaCallback = nullptr;
    unsigned m_refreshRate = 0;
    bool m_fromISR = false;
    bool m_flushCacheAfterDMA = false;
    int m_width = 0;
    int m_height = 0;
    uint32_t m_currentTime = 0;
    uint32_t m_frameCount = 0;
    uint32_t m_previousFrameCount = 0;
    int m_parity = 0;
    uint32_t *m_chainHead = nullptr;
    uint32_t *m_chainTail = nullptr;
    size_t m_chainTailCount = 0;
    enum { CHAIN_IDLE, CHAIN_TRANSFERRING, CHAIN_TRANSFERRED } m_chainStatus;

    uint16_t m_lastHSyncCounter = 0;
    bool m_interlaced = false;
    void flip();
    friend class Application;
};

}  // namespace psyqo

#include "psyqo/internal/gpu/configuration.hh"
