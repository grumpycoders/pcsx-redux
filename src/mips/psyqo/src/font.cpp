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
        for (auto& p : fragment.primitives) {
            p.setColor({{.r = 0xff, .g = 0xff, .b = 0xff}});
            p.size = m_size;
        }
    });
    {
        Rect rect = {.pos = {.x = 960, .y = 464}, .size = {.w = 64, .h = 48}};
        uint32_t coords = rect.pos.packed;
        uint32_t size = rect.size.packed;
        sendGPUData(0xa0000000);
        GPU_DATA = coords;
        GPU_DATA = size;
    }
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

void psyqo::FontBase::print(psyqo::GPU& gpu, const char* text, Vertex pos, Color color,
                            eastl::function<void()>&& callback, GPU::DmaCallback dmaCallback) {
    auto size = m_size;
    unsigned i;
    auto& fragment = getGlyphFragment(false);
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
    fragment.prologue.clutWriter.setColor(color);
    gpu.getScissor(fragment.prologue.enableScissor);
    gpu.sendFragment(fragment, eastl::move(callback), dmaCallback);
}
