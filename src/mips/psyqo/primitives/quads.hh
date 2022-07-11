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
 * @brief A flat-colored quad.
 *
 * @details This primitive will draw a flat-colored quad. It will be drawn
 * between the `pointA`, `pointB`, `pointC`, and `pointD` vertices. Note that
 * the ordering of the vertices matters for proper rendering, and it is not
 * intuitive. The quad will be drawn using two triangles: the first triangle
 * will be drawn with the `pointA`, `pointB`, and `pointC` vertices, and the
 * second triangle will be drawn with the `pointB`, `pointC`, and `pointD`
 * vertices. This means that the vertices of the quad need to be sent in a
 * Z pattern to be drawn properly. Failure to do so will result in a weird
 * looking 5-edged polygon resembling a M envelope, which is not what you want.
 */
struct Quad {
    Quad() : command(0x28000000) {}
    Quad(Color c) : command(0x28000000 | c.packed) {}
    Quad& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x28000000 | c.packed | wasSemiTrans;
        return *this;
    }
    Quad& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    Quad& setSemiTrans() {
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
static_assert(sizeof(Quad) == (sizeof(uint32_t) * 5), "Quad is not 5 words");

/**
 * @brief A textured quad.
 *
 * @details This primitive will draw a textured quad. See `Quad` for more information
 * about vertices and ordering. The primitive has weird-looking ordering of members, but
 * it is necessary to accommodate the way the hardware wants the quad information to be
 * sent to it. The attributes of the primitive can be better visualized with this order:
 * - `pointA`, `pointB`, `pointC`, `pointD`
 * - `uvA`, `uvB`, `uvC`, `uvD`
 * - `clutIndex`, `tpage`
 */
struct TexturedQuad {
    TexturedQuad() : command(0x2c000000) {}
    TexturedQuad& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    TexturedQuad& setSemiTrans() {
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
    Vertex pointD;
    UVCoordsPadded uvD;
};
static_assert(sizeof(TexturedQuad) == (sizeof(uint32_t) * 9), "TexturedQuad is not 9 words");

/**
 * @brief A gouraud-shaded quad.
 *
 * @details This primitive will draw a gouraud-shaded quad. See `Quad` for more information
 * about vertices and ordering. The color of the quad will be interpolated between the colors
 * of its four vertices. Note that `colorA` can only be set using the constructor, or the
 * `setColorA` method.
 */
struct GouraudQuad {
    GouraudQuad() : command(0x38000000) {}
    GouraudQuad(Color c) : command(0x38000000 | c.packed) {}
    GouraudQuad& setColorA(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x38000000 | c.packed | wasSemiTrans;
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
    GouraudQuad& setOpaque() {
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

/**
 * @brief A textured, blended quad.
 *
 * @details This primitive will draw a textured quad with its texels blended with the interpolated
 * color values of its vertices. See `Quad` for more information about vertices and ordering.
 * The primitive has weird-looking ordering of members, but it is necessary to accommodate the
 * way the hardware wants the quad information to be sent to it. The attributes of the primitive
 * can be better visualized with this order:
 * - `pointA`, `pointB`, `pointC`, `pointD`
 * - `colorA`, `colorB`, `colorC`, `colorD`
 * - `uvA`, `uvB`, `uvC`, `uvD`
 * - `clutIndex`, `tpage`
 * Note that `colorA` can only be set using the constructor, or the
 * `setColorA` method.
 */
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
    GouraudTexturedQuad& setOpaque() {
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
    TPageAttr tpage;
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
