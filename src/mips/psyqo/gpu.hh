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
    FROM_MAIN_THREAD,
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
    unsigned getRefreshRate() const { return m_refreshRate; }

    uint32_t getFrameCount() const { return m_frameCount; }

    void clear(Color bg = {{0, 0, 0}});
    void getClear(Prim::FastFill &, Color bg = {{0, 0, 0}}) const;

    void uploadToVRAM(const uint16_t *data, Rect region);
    void uploadToVRAM(const uint16_t *data, Rect region, eastl::function<void()> &&callback,
                      DMA::DmaCallback dmaCallback = DMA::FROM_MAIN_THREAD);
    template <typename Fragment>

    void sendFragment(const Fragment &fragment, unsigned count) {
        sendFragment(fragment.getFragmentDataPtr(), fragment.getActualFragmentSize());
    }
    template <typename Fragment>
    void sendFragment(const Fragment &fragment, eastl::function<void()> &&callback,
                      DMA::DmaCallback dmaCallback = DMA::FROM_MAIN_THREAD) {
        sendFragment(fragment.getFragmentDataPtr(), fragment.getActualFragmentSize(), eastl::move(callback),
                     dmaCallback);
    }

    void disableScissor();
    void enableScissor();
    void getScissor(Prim::Scissor &);

    static void waitReady();
    static void sendRaw(uint32_t data) { GPU_DATA = data; }
    template <typename Primitive>
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
