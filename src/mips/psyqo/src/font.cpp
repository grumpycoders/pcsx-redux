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

#include <cstdint>

#include "common/syscalls/syscalls.h"
#include "psyqo/gpu.hh"
#include "system-font.inc"


void psyqo::FontBase::uploadSystemFont(psyqo::GPU& gpu, psyqo::Vertex location) {
    initialize(gpu, location, {{.w = 8, .h = 16}});
    unpackFont(gpu, s_systemFont, location, {{.w = 256, .h = 48}});
}

void psyqo::FontBase::uploadKromFont(psyqo::GPU& gpu, psyqo::Vertex location) {
    static constexpr uint16_t sjisLookup[] = {
        0x0000,  // space
        0x8149,  // !
        0x8168,  // "
        0x8194,  // #
        0x8190,  // $
        0x8193,  // %
        0x8195,  // &
        0x8166,  // '
        0x8169,  // (
        0x816a,  // )
        0x8196,  // *
        0x817b,  // +
        0x8143,  // ,
        0x817c,  // -
        0x8144,  // .
        0x815e,  // /
        0x824f,  // 0
        0x8250,  // 1
        0x8251,  // 2
        0x8252,  // 3
        0x8253,  // 4
        0x8254,  // 5
        0x8255,  // 6
        0x8256,  // 7
        0x8257,  // 8
        0x8258,  // 9
        0x8146,  // :
        0x8147,  // ;
        0x8183,  // <
        0x8181,  // =
        0x8184,  // >
        0x8148,  // ?
        0x8197,  // @
        0x8260,  // A
        0x8261,  // B
        0x8262,  // C
        0x8263,  // D
        0x8264,  // E
        0x8265,  // F
        0x8266,  // G
        0x8267,  // H
        0x8268,  // I
        0x8269,  // J
        0x826a,  // K
        0x826b,  // L
        0x826c,  // M
        0x826d,  // N
        0x826e,  // O
        0x826f,  // P
        0x8270,  // Q
        0x8271,  // R
        0x8272,  // S
        0x8273,  // T
        0x8274,  // U
        0x8275,  // V
        0x8276,  // W
        0x8277,  // X
        0x8278,  // Y
        0x8279,  // Z
        0x816d,  // [
        0x815f,  // backslash
        0x816e,  // ]
        0x814f,  // ^
        0x8151,  // _
        0x8165,  // `
        0x8281,  // a
        0x8282,  // b
        0x8283,  // c
        0x8284,  // d
        0x8285,  // e
        0x8286,  // f
        0x8287,  // g
        0x8288,  // h
        0x8289,  // i
        0x828a,  // j
        0x828b,  // k
        0x828c,  // l
        0x828d,  // m
        0x828e,  // n
        0x828f,  // o
        0x8290,  // p
        0x8291,  // q
        0x8292,  // r
        0x8293,  // s
        0x8294,  // t
        0x8295,  // u
        0x8296,  // v
        0x8297,  // w
        0x8298,  // x
        0x8299,  // y
        0x829a,  // z
        0x816f,  // {
        0x8162,  // |
        0x8170,  // }
        0x8160,  // ~
        0x0000,  // DEL
    };

    Prim::FastFill fill;
    fill.rect = {.pos = location, .size = {{.w = 64, .h = 90}}};
    gpu.sendPrimitive(fill);

    auto cursor = location;
    for (auto sjis : sjisLookup) {
        Prim::VRAMUpload upload;
        upload.region.pos = cursor;
        upload.region.size = {{.w = 4, .h = 15}};
        cursor.x += 4;
        if (cursor.x >= (location.x + 64)) {
            cursor.x = location.x;
            cursor.y += 15;
        }
        if (sjis == 0) {
            continue;
        }
        const uint8_t* ptr = syscall_Krom2RawAdd(sjis);
        if (ptr == (const uint8_t*)-1) {
            continue;
        }
        gpu.sendPrimitive(upload);
        for (unsigned i = 0; i < 15; i++) {
            uint16_t v = ptr[0] | (ptr[1] << 8);
            uint32_t d = 0;
            for (unsigned j = 0; j < 16; j++) {
                d <<= 4;
                if (v & (1 << j)) {
                    d |= 1;
                }
                if ((j & 7) == 7) {
                    Hardware::GPU::Data = d;
                }
            }
            ptr += 2;
        }
    }
    initialize(gpu, location, {{.w = 16, .h = 15}});
}

void psyqo::FontBase::unpackFont(GPU& gpu, const uint8_t* data, Vertex location, Vertex size) {
    Rect region = {.pos = location, .size = {{.w = int16_t(size.w / 4), .h = size.h}}};
    Prim::VRAMUpload upload;
    upload.region = region;
    gpu.sendPrimitive(upload);

    uint32_t d;
    uint32_t bb = 0x100;
    const int8_t* tree = reinterpret_cast<const int8_t*>(data);
    const uint8_t* lut = data;
    lut += data[0];
    data += data[1];
    unsigned amount = size.h * size.w / 8;
    for (unsigned i = 0; i < amount; i++) {
        int8_t c = 2;
        while (c > 0) {
            if (bb == 0x100) bb = *data++ | 0x10000;
            uint32_t bit = bb & 1;
            bb >>= 1;
            c = tree[c + bit];
        }
        auto b = lut[-c];
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
        Hardware::GPU::Data = d;
    }
}

void psyqo::FontBase::initialize(GPU& gpu, Vertex location, Vertex glyphSize) {
    m_glyphSize = glyphSize;
    Prim::ClutIndex clut(location);
    unsigned glyphPerRow = 256 / glyphSize.w;
    uint8_t baseV = location.y & 0xff;
    for (unsigned i = 0; i < 224; i++) {
        Prim::TexInfo texInfo = {.u = 0, .v = baseV, .clut = clut};
        uint8_t l = i / glyphPerRow;
        texInfo.u = i * glyphSize.w;
        texInfo.v += glyphSize.h * l;
        m_lut[i] = texInfo;
    }
    forEach([this, location](auto& fragment) {
        fragment.prologue.upload.region.pos = location;
        fragment.prologue.upload.region.size = {{.w = 2, .h = 1}};
        fragment.prologue.pixel = 0x7fff0000;
        psyqo::Prim::TPageAttr attr;
        uint8_t pageX = location.x >> 6;
        uint8_t pageY = location.y >> 8;
        attr.setPageX(pageX)
            .setPageY(pageY)
            .set(psyqo::Prim::TPageAttr::Tex4Bits)
            .setDithering(false)
            .enableDisplayArea();
        fragment.prologue.tpage.attr = attr;
        for (auto& p : fragment.primitives) {
            p.setColor({{.r = 0x80, .g = 0x80, .b = 0x80}});
            p.size = m_glyphSize;
        }
    });
}

void psyqo::FontBase::print(GPU& gpu, eastl::string_view text, Vertex pos, Color color) {
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

void psyqo::FontBase::print(GPU& gpu, eastl::string_view text, Vertex pos, Color color,
                            eastl::function<void()>&& callback, DMA::DmaCallback dmaCallback) {
    auto& fragment = getGlyphFragment(false);
    innerprint(fragment, gpu, text, pos, color);
    gpu.sendFragment(fragment, eastl::move(callback), dmaCallback);
}

void psyqo::FontBase::print(GPU& gpu, const char* text, Vertex pos, Color color, eastl::function<void()>&& callback,
                            DMA::DmaCallback dmaCallback) {
    auto& fragment = getGlyphFragment(false);
    innerprint(fragment, gpu, text, pos, color);
    gpu.sendFragment(fragment, eastl::move(callback), dmaCallback);
}

void psyqo::FontBase::chainprint(GPU& gpu, eastl::string_view text, Vertex pos, Color color) {
    auto& fragment = getGlyphFragment(true);
    innerprint(fragment, gpu, text, pos, color);
    gpu.chain(fragment);
}

void psyqo::FontBase::chainprint(GPU& gpu, const char* text, Vertex pos, Color color) {
    auto& fragment = getGlyphFragment(true);
    innerprint(fragment, gpu, text, pos, color);
    gpu.chain(fragment);
}

void psyqo::FontBase::innerprint(GlyphsFragment& fragment, GPU& gpu, eastl::string_view text, Vertex pos, Color color) {
    auto size = m_glyphSize;
    unsigned i = 0;
    auto maxSize = fragment.primitives.size();

    for (auto c : text) {
        if (i >= maxSize) break;
        if (c < 32 || c > 127) {
            c = '?';
        }
        if (c == ' ') {
            pos.x += size.w;
            continue;
        }
        auto& f = fragment.primitives[i++];
        auto p = m_lut[c - 32];
        f.position = pos;
        f.texInfo = p;
        pos.x += size.w;
    }
    fragment.count = i;
    color.r >>= 3;
    color.g >>= 3;
    color.b >>= 3;
    uint32_t pixel = color.r | (color.g << 5) | (color.b << 10);
    fragment.prologue.pixel = pixel << 16;
}

void psyqo::FontBase::innerprint(GlyphsFragment& fragment, GPU& gpu, const char* text, Vertex pos, Color color) {
    auto size = m_glyphSize;
    unsigned i;
    auto maxSize = fragment.primitives.size();

    for (i = 0; i < maxSize; pos.x += size.w) {
        uint8_t c = *text++;
        if (c == 0) break;
        if (c < 32) {
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
    color.r >>= 3;
    color.g >>= 3;
    color.b >>= 3;
    uint32_t pixel = color.r | (color.g << 5) | (color.b << 10);
    fragment.prologue.pixel = pixel << 16;
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
    GlyphsFragment& fragment;
    GPU& gpu;
    Vertex pos;
    FontBase* self;
};

extern "C" int vxprintf(void (*func)(const char*, int, void*), void* arg, const char* format, va_list ap);

void psyqo::FontBase::innervprintf(GlyphsFragment& fragment, GPU& gpu, Vertex pos, Color color, const char* format,
                                   va_list ap) {
    fragment.count = 0;
    color.r >>= 3;
    color.g >>= 3;
    color.b >>= 3;
    uint32_t pixel = color.r | (color.g << 5) | (color.b << 10);
    fragment.prologue.pixel = pixel << 16;
    XPrintfInfo info{fragment, gpu, pos, this};
    vxprintf(
        [](const char* str, int len, void* info_) {
            auto& info = *static_cast<XPrintfInfo*>(info_);
            auto& fragment = info.fragment;
            auto& primitives = info.fragment.primitives;
            auto maxSize = primitives.size();
            auto& pos = info.pos;
            auto self = info.self;
            unsigned i;
            for (i = 0; i < len; i++) {
                if (fragment.count >= maxSize) break;
                auto c = str[i];
                if (c < 32 || c > 127) {
                    c = '?';
                }
                if (c == ' ') {
                    pos.x += self->m_glyphSize.w;
                    continue;
                }
                auto& f = primitives[fragment.count++];
                auto p = self->m_lut[c - 32];
                f.position = pos;
                f.texInfo = p;
                pos.x += self->m_glyphSize.w;
            }
        },
        &info, format, ap);
}
