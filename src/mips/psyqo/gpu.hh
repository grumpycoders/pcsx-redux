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
    enum Resolution { W256, W320, W368, W512, W640 };
    enum VideoMode { AUTO, NTSC, PAL };
    enum ColorMode { C15BITS, C24BITS };
    void initialize(const Configuration &config);

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
     * @brief Sets a `FastFill` primitive to clear the drawing buffer.
     *
     * @details This method will set the `FastFill` primitive passed as
     * an argument in a way to completely clear the drawing buffer with
     * the specified color. This will be done in accordance to the current
     * drawing buffer settings.
     * @param ff The `FastFill` primitive to set.
     * @param end The color to issue.
     */
    void getClear(Prim::FastFill &ff, Color bg = {{0, 0, 0}}) const;

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

  private:
    void sendFragment(const uint32_t *data, size_t count);
    void sendFragment(const uint32_t *data, size_t count, eastl::function<void()> &&callback,
                      DMA::DmaCallback dmaCallback);
    eastl::function<void(void)> m_dmaCallback = nullptr;
    unsigned m_refreshRate = 0;
    bool m_fromISR = false;
    bool m_flushCacheAfterDMA = false;
    int m_width = 0;
    int m_height = 0;
    uint32_t m_frameCount = 0;
    uint32_t m_previousFrameCount = 0;
    int m_parity = 0;

    bool m_interlaced = false;
    void flip();
    friend class Application;
};

}  // namespace psyqo

#include "psyqo/internal/gpu/configuration.hh"