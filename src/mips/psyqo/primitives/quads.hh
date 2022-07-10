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

struct FlatQuad {
    FlatQuad() : command(0x28000000) {}
    FlatQuad(Color c) : command(0x28000000 | c.packed) {}
    FlatQuad& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x28000000 | c.packed | wasSemiTrans;
        return *this;
    }
    FlatQuad& setSolid() {
        command &= ~0x02000000;
        return *this;
    }
    FlatQuad& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex pointA;
    Vertex pointB;
    Vertex pointC;
    Vertex pointD;
};
static_assert(sizeof(FlatQuad) == (sizeof(uint32_t) * 5), "FlatQuad is not 5 words");

struct FlatTexturedQuad {
    FlatTexturedQuad() : command(0x2c000000) {}
    FlatTexturedQuad& setSolid() {
        command &= ~0x02000000;
        return *this;
    }
    FlatTexturedQuad& setSemiTrans() {
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
    Vertex pointD;
    UVCoordsPadded uvD;
};
static_assert(sizeof(FlatTexturedQuad) == (sizeof(uint32_t) * 9), "FlatTexturedQuad is not 9 words");

struct GouraudQuad {
    GouraudQuad() : command(0x38000000) {}
    GouraudQuad(Color c) : command(0x38000000 | c.packed) {}
    GouraudQuad& setColorA(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x38000000 | c.packed| wasSemiTrans;
        return *this;
    }
    GouraudQuad& setColorB(Color c) {
        colorB = c;
        return *this;
    }
    GouraudQuad& setColorC(Color c) {
        colorC = c;
        return *this;
    }
    GouraudQuad& setColorD(Color c) {
        colorD = c;
        return *this;
    }
    GouraudQuad& setSolid() {
        command &= ~0x02000000;
        return *this;
    }
    GouraudQuad& setSemiTrans() {
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
    Color colorD;
    Vertex pointD;
};
static_assert(sizeof(GouraudQuad) == (sizeof(uint32_t) * 8), "GouraudQuad is not 8 words");

struct GouraudTexturedQuad {
    GouraudTexturedQuad() : command(0x3d000000) {}
    GouraudTexturedQuad(Color c) : command(0x3d000000 | c.packed) {}
    GouraudTexturedQuad& setColorA(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x3d000000 | c.packed | wasSemiTrans;
        return *this;
    }
    GouraudTexturedQuad& setColorB(Color c) {
        colorB = c;
        return *this;
    }
    GouraudTexturedQuad& setColorC(Color c) {
        colorC = c;
        return *this;
    }
    GouraudTexturedQuad& setColorD(Color c) {
        colorD = c;
        return *this;
    }
    GouraudTexturedQuad& setSolid() {
        command &= ~0x02000000;
        return *this;
    }
    GouraudTexturedQuad& setSemiTrans() {
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
    Color colorD;
    Vertex pointD;
    UVCoordsPadded uvD;
};
static_assert(sizeof(GouraudTexturedQuad) == (sizeof(uint32_t) * 12), "GouraudTexturedQuad is not 12 words");

}  // namespace Prim

}  // namespace psyqo
