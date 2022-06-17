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

#include "psyqo/gpu.hh"

namespace psyqo {

class Font {
  public:
    void uploadSystemFont(GPU& gpu) {
        bool done = false;
        uploadSystemFont(
            gpu,
            [&done]() {
                done = true;
                eastl::atomic_signal_fence(eastl::memory_order_release);
            },
            GPU::FROM_ISR);
        while (!done) {
            eastl::atomic_signal_fence(eastl::memory_order_acquire);
        }
    }
    void uploadSystemFont(GPU& gpu, eastl::function<void()>&& callback,
                          GPU::DmaCallback dmaCallback = GPU::FROM_MAIN_THREAD);
    void print(GPU& gpu, const char* text, Vertex pos, Color color = {.r = 255, .g = 255, .b = 255}) {
        bool done = false;
        print(
            gpu, text, pos, color,
            [&done]() {
                done = true;
                eastl::atomic_signal_fence(eastl::memory_order_release);
            },
            GPU::FROM_ISR);
        while (!done) {
            eastl::atomic_signal_fence(eastl::memory_order_acquire);
        }
    }
    void print(GPU& gpu, const char* text, Vertex pos, Color color, eastl::function<void()>&& callback,
               GPU::DmaCallback dmaCallback);

  private:
    GPU::Fragment<GPU::Sprite, 256> m_fragment;
    bool m_is8bits = false;
    Vertex m_size;
    eastl::array<GPU::TexInfo, 96> m_lut;
};

}  // namespace psyqo
