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
 * @brief A flat-colored triangle.
 *
 * @details This primitive will draw a flat-colored triangle. It will be drawn
 * between the `pointA`, `pointB`, and `pointC`.
 */
struct Triangle {
    Triangle() : command(0x20000000) {}
    Triangle(Color c) : command(0x20000000 | c.packed) {}
    Triangle& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x20000000 | c.packed | wasSemiTrans;
        return *this;
    }
    Triangle& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    Triangle& setSemiTrans() {
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
static_assert(sizeof(Triangle) == (sizeof(uint32_t) * 4), "Triangle is not 4 words");

/**
 * @brief A textured triangle.
 *
 * @details This primitive will draw a textured triangle. It will be drawn
 * between the `pointA`, `pointB`, and `pointC` vertices. The primitive has
 * weird-looking ordering of members, but it is necessary to accommodate the
 * way the hardware wants the triangle information to be sent to it. The
 * attributes of the primitive can be better visualized with this order:
 * - `pointA`, `pointB`, `pointC`
 * - `uvA`, `uvB`, `uvC`
 * - `clutIndex`, `tpage`
 */
struct TexturedTriangle {
    TexturedTriangle() : command(0x24000000) {}
    TexturedTriangle& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    TexturedTriangle& setSemiTrans() {
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
    TPageAttr tpage;
    Vertex pointC;
    UVCoordsPadded uvC;
};
static_assert(sizeof(TexturedTriangle) == (sizeof(uint32_t) * 7), "TexturedTriangle is not 7 words");

/**
 * @brief A gouraud-shaded triangle.
 *
 * @details This primitive will draw a gouraud-shaded triangle. It will be drawn
 * between the `pointA`, `pointB`, and `pointC`. Its color will be interpolated
 * between the colors of its three vertices. Note that `colorA` can only be set
 * using the constructor, or the `setColorA` method.
 */
struct GouraudTriangle {
    GouraudTriangle() : command(0x30000000) {}
    GouraudTriangle(Color c) : command(0x30000000 | c.packed) {}
    GouraudTriangle& setColorA(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x30000000 | c.packed | wasSemiTrans;
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
    GouraudTriangle& setOpaque() {
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

/**
 * @brief A textured, blended triangle.
 *
 * @details This primitive will draw a textured triangle with its texels
 * blended with the interpolated color values of its vertices. It will be draw
 * between the `pointA`, `pointB`, and `pointC` vertices. The primitive has
 * weird-looking ordering of members, but it is necessary to accommodate the
 * way the hardware wants the triangle information to be sent to it. The
 * attributes of the primitive can be better visualized with this order:
 * - `pointA`, `pointB`, `pointC`
 * - `colorA`, `colorB`, `colorC`
 * - `uvA`, `uvB`, `uvC`
 * - `clutIndex`, `tpage`
 */
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
    GouraudTexturedTriangle& setOpaque() {
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
    TPageAttr tpage;
    Color colorC;
    Vertex pointC;
    UVCoordsPadded uvC;
};
static_assert(sizeof(GouraudTexturedTriangle) == (sizeof(uint32_t) * 9), "GouraudTexturedTriangle is not 9 words");

}  // namespace Prim

}  // namespace psyqo
