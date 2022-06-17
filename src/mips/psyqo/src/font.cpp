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

void psyqo::Font::uploadSystemFont(psyqo::GPU& gpu, eastl::function<void()>&& callback, GPU::DmaCallback dmaCallback) {
    GPU::ClutIndex clut(0, 240);
    for (unsigned i = 0; i < 96; i++) {
        GPU::TexInfo texInfo = {.u = 0, .v = 240, .clut = clut};
        texInfo.u = i * 8;
        m_lut[i] = texInfo;
    }
    auto size = m_size = {.w = 8, .h = 16};
    for (auto& p : m_fragment.data) {
        p.command |= 0xffffff;
        p.size = size;
    }
    Rect rect = {.pos = {.x = 0, .y = 240}, .size = {.w = 188, .h = 16}};
    gpu.uploadToVRAM(reinterpret_cast<const uint16_t*>(s_systemFont), rect, eastl::move(callback), dmaCallback);
}

void psyqo::Font::print(psyqo::GPU& gpu, const char* text, Vertex pos, Color color, eastl::function<void()>&& callback,
                        GPU::DmaCallback dmaCallback) {
    auto size = m_size;
    unsigned i;

    for (i = 0; i < m_fragment.size(); pos.x += size.w) {
        auto c = *text++;
        if (c == 0) break;
        if (c < 32 || c > 127) {
            c = '?';
        }
        if (c == ' ') {
            continue;
        }
        auto& f = m_fragment.data[i++];
        auto& p = m_lut[c - 32];
        f.position = pos;
        f.texInfo = p;
    }
    uint32_t cmd = color.packed | 0b01101000000000000000000000000000;
    union {
        Vertex p;
        uint32_t packed;
    } arg;
    arg.p = {.x = 1, .y = 240};
    bool enableScissor = gpu.disableScissor();
    sendGPUData(cmd);
    GPU_DATA = arg.packed;
    flushGPUCache();
    if (enableScissor) gpu.enableScissor();
    sendGPUData(0b11100001000000000000010000000001);
    gpu.sendFragment(m_fragment, i, eastl::move(callback), dmaCallback);
}
