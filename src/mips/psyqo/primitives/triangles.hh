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

#include "psyqo/primitives/common.hh"

namespace psyqo {

namespace Prim {

struct FlatTriangle {
    FlatTriangle() : command(0x20000000) {}
    FlatTriangle(Color c) : command(0x20000000 | c.packed) {}
    FlatTriangle& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x20000000 | c.packed | wasSemiTrans;
        return *this;
    }
    FlatTriangle& setSolid() {
        command &= ~0x02000000;
        return *this;
    }
    FlatTriangle& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex pointA;
    Vertex pointB;
    Vertex pointC;
};
static_assert(sizeof(FlatTriangle) == (sizeof(uint32_t) * 4), "FlatTriangle is not 4 words");

struct FlatTexturedTriangle {
    FlatTexturedTriangle() : command(0x24000000) {}
    FlatTexturedTriangle& setSolid() {
        command &= ~0x02000000;
        return *this;
    }
    FlatTexturedTriangle& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex pointA;
    UVCoords uvA;
    ClutIndex clutIndex;
    Vertex pointB;
    UVCoords uvB;
    TPage tpage;
    Vertex pointC;
    UVCoordsPadded uvC;
};
static_assert(sizeof(FlatTexturedTriangle) == (sizeof(uint32_t) * 7), "FlatTexturedTriangle is not 7 words");

struct GouraudTriangle {
    GouraudTriangle() : command(0x30000000) {}
    GouraudTriangle(Color c) : command(0x30000000 | c.packed) {}
    GouraudTriangle& setColorA(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x30000000 | c.packed| wasSemiTrans;
        return *this;
    }
    GouraudTriangle& setColorB(Color c) {
        colorB = c;
        return *this;
    }
    GouraudTriangle& setColorC(Color c) {
        colorC = c;
        return *this;
    }
    GouraudTriangle& setSolid() {
        command &= ~0x02000000;
        return *this;
    }
    GouraudTriangle& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex pointA;
    Color colorB;
    Vertex pointB;
    Color colorC;
    Vertex pointC;
};
static_assert(sizeof(GouraudTriangle) == (sizeof(uint32_t) * 6), "GouraudTriangle is not 6 words");

struct GouraudTexturedTriangle {
    GouraudTexturedTriangle() : command(0x35000000) {}
    GouraudTexturedTriangle(Color c) : command(0x35000000 | c.packed) {}
    GouraudTexturedTriangle& setColorA(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x35000000 | c.packed | wasSemiTrans;
        return *this;
    }
    GouraudTexturedTriangle& setColorB(Color c) {
        colorB = c;
        return *this;
    }
    GouraudTexturedTriangle& setColorC(Color c) {
        colorC = c;
        return *this;
    }
    GouraudTexturedTriangle& setSolid() {
        command &= ~0x02000000;
        return *this;
    }
    GouraudTexturedTriangle& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex pointA;
    UVCoords uvA;
    ClutIndex clutIndex;
    Color colorB;
    Vertex pointB;
    UVCoords uvB;
    TPage tpage;
    Color colorC;
    Vertex pointC;
    UVCoordsPadded uvC;
};
static_assert(sizeof(GouraudTexturedTriangle) == (sizeof(uint32_t) * 9), "GouraudTexturedTriangle is not 9 words");

}  // namespace Prim

}  // namespace psyqo
