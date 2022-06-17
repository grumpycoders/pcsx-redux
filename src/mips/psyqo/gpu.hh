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

namespace psyqo {

struct Vertex {
    union {
        int16_t x, w;
    };
    union {
        int16_t y, h;
    };
};

struct Rect {
    union {
        Vertex a, pos;
    };
    union {
        Vertex b, size;
    };
};

class GPU {
  public:
    template <typename T, size_t count>
    struct Fragment {
        typedef T FragmentBaseType;
        constexpr size_t size() { return count; }
        uint32_t head;
        eastl::array<T, count> data;
    };
    struct ClutIndex {
        ClutIndex() : index(0) {}
        ClutIndex(uint16_t x, uint16_t y) : index((y << 6) | x) {}
        uint16_t index;
    };
    struct TexInfo {
        uint8_t u;
        uint8_t v;
        ClutIndex clut;
    };
    struct Sprite {
        Sprite() : command(0b01100100000000000000000000000000) {}
        uint32_t command;
        Vertex position;
        TexInfo texInfo;
        Vertex size;
    };
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
    void sendFragment(Fragment &fragment, unsigned count) {
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
    void sendFragment(Fragment &fragment, unsigned count, eastl::function<void()> &&callback,
                      DmaCallback dmaCallback = FROM_MAIN_THREAD) {
        sendFragment(reinterpret_cast<uint32_t *>(fragment.data.data()),
                     count * sizeof(typename Fragment::FragmentBaseType) / sizeof(uint32_t), eastl::move(callback),
                     dmaCallback);
    }
    void uploadToVRAM(const uint16_t *data, Rect rect, eastl::function<void()> &&callback,
                      DmaCallback dmaCallback = FROM_MAIN_THREAD);
    bool disableScissor();
    bool enableScissor();

  private:
    void sendFragment(uint32_t *data, unsigned count, eastl::function<void()> &&callback, DmaCallback dmaCallback);
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
    bool m_scissorEnabled = false;
    void flip();
    friend class Application;

  public:
    struct Configuration {
        Configuration &setResolution(Resolution resolution) {
            if (resolution == Resolution::W368) {
                config.hResolution = HR_EXTENDED;
                config.hResolutionExtended = HRE_368;
            } else {
                config.hResolutionExtended = HRE_NORMAL;
                switch (resolution) {
                    case Resolution::W256:
                        config.hResolution = HR_256;
                        break;
                    case Resolution::W320:
                        config.hResolution = HR_320;
                        break;
                    case Resolution::W512:
                        config.hResolution = HR_512;
                        break;
                    case Resolution::W640:
                        config.hResolution = HR_640;
                        break;
                }
            }
            return *this;
        }
        Configuration &setVideoMode(VideoMode videoMode) {
            switch (videoMode) {
                case VideoMode::AUTO:
                    config.videoMode = (*((char *)0xbfc7ff52) == 'E') ? VM_PAL : VM_NTSC;
                    break;
                case VideoMode::NTSC:
                    config.videoMode = VM_NTSC;
                    break;
                case VideoMode::PAL:
                    config.videoMode = VM_PAL;
                    break;
            }
            return *this;
        }
        Configuration &setColorMode(ColorMode colorMode) {
            switch (colorMode) {
                case ColorMode::C15BITS:
                    config.colorDepth = CD_15BITS;
                    break;
                case ColorMode::C24BITS:
                    config.colorDepth = CD_24BITS;
                    break;
            }
            return *this;
        }
        Configuration &setInterlace(bool interlace) {
            config.videoInterlace = interlace ? VI_ON : VI_OFF;
            return *this;
        }

      private:
        DisplayModeConfig config = {};
        friend class GPU;
    };
};

}  // namespace psyqo
