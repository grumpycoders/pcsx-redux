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

/**
 * @brief The Line primitive.
 *
 * @details The Line primitive will draw a single, flat-colored segment. It
 * will be drawn between the `pointA` and `pointB` vertices.
 */
struct Line {
    Line() : command(0x40000000) {}
    Line(Color c) : command(0x40000000 | c.packed) {}
    Line& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x40000000 | c.packed | wasSemiTrans;
        return *this;
    }
    Line& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    Line& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex pointA;
    Vertex pointB;
};
static_assert(sizeof(Line) == sizeof(uint32_t) * 3, "Line is not 3 words");

/**
 * @brief The Gouraud-shaded Line primitive.
 *
 * @details The Line primitive will draw a single, gouraud-shaded segment. It
 * will be drawn between the `pointA` and `pointB` vertices. The color of the
 * segment will be interpolated between the `colorA` and `colorB` colors.
 * Note that `colorA` can only be set using the constructor, or the
 * `setColorA` method.
 */
struct GouraudLine {
    GouraudLine() : command(0x50000000) {}
    GouraudLine(Color c) : command(0x50000000 | c.packed) {}
    GouraudLine& setColorA(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x50000000 | c.packed | wasSemiTrans;
        return *this;
    }
    GouraudLine& setColorB(Color c) {
        colorB = c;
        return *this;
    }
    GouraudLine& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    GouraudLine& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex pointA;
    Color colorB;
    Vertex pointB;
};
static_assert(sizeof(GouraudLine) == sizeof(uint32_t) * 4, "Line is not 4 words");

}  // namespace Prim

}  // namespace psyqo
