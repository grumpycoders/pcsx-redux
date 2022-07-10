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
#include <stdarg.h>

#include "psyqo/fragments.hh"
#include "psyqo/gpu.hh"
#include "psyqo/primitives.hh"

namespace psyqo {

template <size_t Fragments = 16>
class Font;

class FontBase {
  public:
    virtual ~FontBase() {}
    // Blocking call that will unpack the built-in system font and upload it to vram at a fixed location.
    void uploadSystemFont(GPU& gpu);

    void print(GPU& gpu, const char* text, Vertex pos, Color color);
    void print(GPU& gpu, const char* text, Vertex pos, Color color, eastl::function<void()>&& callback,
               DMA::DmaCallback dmaCallback);
    void printf(GPU& gpu, Vertex pos, Color color, const char* format, ...) {
        va_list args;
        va_start(args, format);
        vprintf(gpu, pos, color, format, args);
        va_end(args);
    }
    void printf(GPU& gpu, Vertex pos, Color color, eastl::function<void()>&& callback, DMA::DmaCallback dmaCallback,
                const char* format, ...) {
        va_list args;
        va_start(args, format);
        vprintf(gpu, pos, color, eastl::move(callback), dmaCallback, format, args);
        va_end(args);
    }
    void vprintf(GPU& gpu, Vertex pos, Color color, const char* format, va_list ap);
    void vprintf(GPU& gpu, Vertex pos, Color color, eastl::function<void()>&& callback, DMA::DmaCallback dmaCallback,
                 const char* format, va_list ap);

  protected:
    struct GlyphsFragmentPrologue {
        Prim::Scissor disableScissor;
        Prim::Pixel clutWriter;
        Prim::FlushCache flushCache;
        Prim::Scissor enableScissor;
        Prim::TexPage tpage;
    };
    typedef Fragments::FixedFragment<GlyphsFragmentPrologue, Prim::Sprite, 48> GlyphsFragment;
    virtual GlyphsFragment& getGlyphFragment(bool increment) = 0;
    virtual void forEach(eastl::function<void(GlyphsFragment&)>&& cb) = 0;

  private:
    struct XPrintfInfo;
    GlyphsFragment& printToFragment(GPU& gpu, const char* text, Vertex pos, Color color);
    eastl::array<Prim::TexInfo, 96> m_lut;
    Vertex m_size;

    friend struct XPrintfInfo;
};

}  // namespace psyqo

#include "psyqo/internal/font.hh"
