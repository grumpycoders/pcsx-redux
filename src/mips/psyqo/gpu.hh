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

#include "common/hardware/gpu.h"
#include "psyqo/primitives.hh"

namespace psyqo {

class GPU {
  public:
    struct Configuration;
    enum Resolution { W256, W320, W368, W512, W640 };
    enum VideoMode { AUTO, NTSC, PAL };
    enum ColorMode { C15BITS, C24BITS };
    void initialize(const Configuration &config);
    void onVsync(eastl::function<void()> &&callback) { m_vsync = eastl::move(callback); }
    uint32_t getFrameCount() { return m_frameCount; }
    void clear(Color bg = {{0, 0, 0}});

    void uploadToVRAM(const uint16_t *data, Rect rect) {
        bool done = false;
        uploadToVRAM(
            data, rect,
            [&done]() {
                done = true;
                eastl::atomic_signal_fence(eastl::memory_order_release);
            },
            FROM_ISR);
        while (!done) {
            eastl::atomic_signal_fence(eastl::memory_order_acquire);
        }
    }
    enum DmaCallback {
        FROM_ISR,
        FROM_MAIN_THREAD,
    };
    template <typename Fragment>
    void sendFragment(const Fragment &fragment, unsigned count) {
        bool done = false;
        sendFragment(
            reinterpret_cast<uint32_t *>(fragment.data.data()),
            count * sizeof(typename Fragment::FragmentBaseType) / sizeof(uint32_t),
            [&done]() {
                done = true;
                eastl::atomic_signal_fence(eastl::memory_order_release);
            },
            FROM_ISR);
        while (!done) {
            eastl::atomic_signal_fence(eastl::memory_order_acquire);
        }
    }
    template <typename Fragment>
    void sendFragment(const Fragment &fragment, eastl::function<void()> &&callback,
                      DmaCallback dmaCallback = FROM_MAIN_THREAD) {
        sendFragment(fragment.getFragmentDataPtr(), fragment.getActualFragmentSize(), eastl::move(callback), dmaCallback);
    }
    void uploadToVRAM(const uint16_t *data, Rect rect, eastl::function<void()> &&callback,
                      DmaCallback dmaCallback = FROM_MAIN_THREAD);
    void disableScissor();
    void enableScissor();
    void getScissor(Prim::Scissor &);

  private:
    void sendFragment(const uint32_t *data, size_t count, eastl::function<void()> &&callback,
                      DmaCallback dmaCallback);
    eastl::function<void(void)> m_vsync = nullptr;
    eastl::function<void(void)> m_dmaCallback = nullptr;
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
