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

#include "psyqo/font.hh"

#include <EASTL/atomic.h>
#include <stdarg.h>

#include "psyqo/gpu.hh"
#include "system-font.c"

void psyqo::FontBase::uploadSystemFont(psyqo::GPU& gpu) {
    Vertex clutPosition = {.x = 961, .y = 464};
    Prim::ClutIndex clut(clutPosition);
    for (unsigned i = 0; i < 96; i++) {
        Prim::TexInfo texInfo = {.u = 0, .v = 208, .clut = clut};
        uint8_t l = i / 32;
        texInfo.u = i * 8;
        texInfo.v += 16 * l;
        m_lut[i] = texInfo;
    }
    auto size = m_size = {.w = 8, .h = 16};
    forEach([this, clutPosition](auto& fragment) {
        fragment.prologue.clutWriter.position = clutPosition;
        psyqo::Prim::TPageAttr attr;
        attr.setPageX(15).setPageY(1).set(psyqo::Prim::TPageAttr::Tex4Bits).setDithering(false).enableDisplayArea();
        fragment.prologue.tpage.attr = attr;
        for (auto& p : fragment.primitives) {
            p.setColor({{.r = 0xff, .g = 0xff, .b = 0xff}});
            p.size = m_size;
        }
    });

    Rect region = {.pos = {.x = 960, .y = 464}, .size = {.w = 64, .h = 48}};
    Prim::VRAMUpload upload;
    upload.region = region;
    gpu.sendPrimitive(upload);

    // On the fly decompression of the system font.
    uint32_t d;
    for (unsigned i = 0; i < sizeof(s_systemFont); i++) {
        uint8_t b = s_systemFont[i];
        for (unsigned j = 0; j < 4; j++) {
            uint32_t m;
            d >>= 8;
            switch (b & 3) {
                case 0:
                    m = 0x00000000;
                    break;
                case 1:
                    m = 0x01000000;
                    break;
                case 2:
                    m = 0x10000000;
                    break;
                case 3:
                    m = 0x11000000;
                    break;
            }
            d |= m;
            b >>= 2;
        }
        GPU_DATA = d;
    }
}

void psyqo::FontBase::print(GPU& gpu, const char* text, Vertex pos, Color color) {
    bool done = false;
    print(
        gpu, text, pos, color,
        [&done]() {
            done = true;
            eastl::atomic_signal_fence(eastl::memory_order_release);
        },
        DMA::FROM_ISR);
    while (!done) {
        gpu.pumpCallbacks();
        eastl::atomic_signal_fence(eastl::memory_order_acquire);
    }
}

void psyqo::FontBase::print(GPU& gpu, const char* text, Vertex pos, Color color, eastl::function<void()>&& callback,
                            DMA::DmaCallback dmaCallback) {
    auto& fragment = getGlyphFragment(false);
    innerprint(fragment, gpu, text, pos, color);
    gpu.sendFragment(fragment, eastl::move(callback), dmaCallback);
}

void psyqo::FontBase::chainprint(GPU& gpu, const char* text, Vertex pos, Color color) {
    auto& fragment = getGlyphFragment(true);
    innerprint(fragment, gpu, text, pos, color);
    gpu.chain(fragment);
}

void psyqo::FontBase::innerprint(GlyphsFragment& fragment, GPU& gpu, const char* text, Vertex pos, Color color) {
    auto size = m_size;
    unsigned i;
    auto maxSize = fragment.primitives.size();

    for (i = 0; i < maxSize; pos.x += size.w) {
        auto c = *text++;
        if (c == 0) break;
        if (c < 32 || c > 127) {
            c = '?';
        }
        if (c == ' ') {
            continue;
        }
        auto& f = fragment.primitives[i++];
        auto p = m_lut[c - 32];
        f.position = pos;
        f.texInfo = p;
    }
    fragment.count = i;
    color.r >>= 1;
    color.g >>= 1;
    color.b >>= 1;
    fragment.prologue.clutWriter.setColor(color);
    gpu.getScissor(fragment.prologue.enableScissor);
}

void psyqo::FontBase::vprintf(GPU& gpu, Vertex pos, Color color, const char* format, va_list ap) {
    bool done = false;
    vprintf(
        gpu, pos, color,
        [&done]() {
            done = true;
            eastl::atomic_signal_fence(eastl::memory_order_release);
        },
        DMA::FROM_ISR, format, ap);
    while (!done) {
        gpu.pumpCallbacks();
        eastl::atomic_signal_fence(eastl::memory_order_acquire);
    }
}

void psyqo::FontBase::vprintf(GPU& gpu, Vertex pos, Color color, eastl::function<void()>&& callback,
                              DMA::DmaCallback dmaCallback, const char* format, va_list ap) {
    auto& fragment = getGlyphFragment(false);
    innervprintf(fragment, gpu, pos, color, format, ap);
    gpu.sendFragment(fragment, eastl::move(callback), dmaCallback);
}

void psyqo::FontBase::chainvprintf(GPU& gpu, Vertex pos, Color color, const char* format, va_list ap) {
    auto& fragment = getGlyphFragment(true);
    innervprintf(fragment, gpu, pos, color, format, ap);
    gpu.chain(fragment);
}

struct psyqo::FontBase::XPrintfInfo {
    psyqo::FontBase::GlyphsFragment& fragment;
    GPU& gpu;
    psyqo::Vertex pos;
    psyqo::Color color;
    psyqo::FontBase* self;
};

extern "C" int vxprintf(void (*func)(const char*, int, void*), void* arg, const char* format, va_list ap);

void psyqo::FontBase::innervprintf(GlyphsFragment& fragment, GPU& gpu, Vertex pos, Color color, const char* format,
                                   va_list ap) {
    fragment.count = 0;
    color.r >>= 1;
    color.g >>= 1;
    color.b >>= 1;
    XPrintfInfo info{getGlyphFragment(false), gpu, pos, color, this};
    fragment.prologue.clutWriter.setColor(info.color);
    gpu.getScissor(fragment.prologue.enableScissor);
    vxprintf(
        [](const char* str, int len, void* info_) {
            auto& info = *static_cast<XPrintfInfo*>(info_);
            auto& fragment = info.fragment;
            auto& primitives = info.fragment.primitives;
            auto maxSize = primitives.size();
            auto& pos = info.pos;
            auto& color = info.color;
            auto self = info.self;
            unsigned i;
            for (i = 0; i < len; i++) {
                if (fragment.count >= maxSize) break;
                auto c = str[i];
                if (c == ' ') {
                    pos.x += self->m_size.w;
                    continue;
                }
                if (c < 32 || c > 127) {
                    c = '?';
                }
                auto& f = primitives[fragment.count++];
                auto p = self->m_lut[c - 32];
                f.position = pos;
                f.texInfo = p;
                pos.x += self->m_size.w;
            }
        },
        &info, format, ap);
}
