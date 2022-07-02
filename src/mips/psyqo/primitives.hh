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

#include <stdint.h>

namespace psyqo {

union Vertex {
    struct {
        union {
            int16_t x, w;
        };
        union {
            int16_t y, h;
        };
    };
    int32_t packed;
};

struct Rect {
    union {
        Vertex a, pos;
    };
    union {
        Vertex b, size;
    };
};

union Color {
    struct {
        uint8_t r, g, b;
    };
    uint32_t packed;
};

namespace Prim {

struct ClutIndex {
    ClutIndex() : index(0) {}
    ClutIndex(Vertex v) : ClutIndex(v.x >> 4, v.y) {}
    ClutIndex(uint16_t x, uint16_t y) : index((y << 6) | x) {}
    uint16_t index;
};

struct TexInfo {
    uint8_t u;
    uint8_t v;
    ClutIndex clut;
};

struct FastFill {
    FastFill() : command(0x02000000) {}
    FastFill(Color c) : command(0x02000000 | c.packed) {}
    void setColor(Color c) { command = 0x02000000 | c.packed; }

  private:
    uint32_t command;

  public:
    Rect rect;
};

struct Sprite {
    Sprite() : command(0b01100100'00000000'00000000'00000000) {}
    Sprite(Color c) : command(0b01100100'00000000'00000000'00000000 | c.packed) {}
    void setColor(Color c) { command = 0b01100100'00000000'00000000'00000000 | c.packed; }

  private:
    uint32_t command;

  public:
    Vertex position;
    TexInfo texInfo;
    Vertex size;
};

struct Pixel {
    Pixel() : command(0b01101000'00000000'00000000'00000000) {}
    Pixel(Color c) : command(0b01101000'00000000'00000000'00000000 | c.packed) {}
    void setColor(Color c) { command = 0b01101000'00000000'00000000'00000000 | c.packed; }

  private:
    uint32_t command;

  public:
    Vertex position;
};

struct FlushCache {
    FlushCache() : command(0x01000000) {}
    uint32_t command;
};

struct DrawingAreaStart {
    DrawingAreaStart(Vertex p) : command(0xe3000000 | p.x | (p.y << 10)) {}
    uint32_t command;
};

struct DrawingAreaEnd {
    DrawingAreaEnd(Vertex p) : command(0xe4000000 | (p.x - 1) | ((p.y - 1) << 10)) {}
    uint32_t command;
};

struct DrawingOffset {
    DrawingOffset(Vertex p) : command(0xe5000000 | p.x | (p.y << 11)) {}
    uint32_t command;
};

struct Scissor {
    DrawingAreaStart start = DrawingAreaStart(Vertex{{.x = 0, .y = 0}});
    DrawingAreaEnd end = DrawingAreaEnd(Vertex{{.x = 1024, .y = 512}});
    DrawingOffset offset = DrawingOffset(Vertex{{.x = 0, .y = 0}});
};

struct VRAMUpload {
    VRAMUpload() : command(0xa0000000) {}
    uint32_t command;
    Rect region;
};

}  // namespace Prim

}  // namespace psyqo
