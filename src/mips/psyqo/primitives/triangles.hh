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

#include "psyqo/gte-kernels.hh"
#include "psyqo/gte-registers.hh"
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
    Triangle(Color c) : command(0x20000000 | (c.packed & 0x00ffffff)) {}
    Triangle(const Triangle& other, Color c) : command(other.command | (c.packed & 0x00ffffff)) {}
    Triangle& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x20000000 | (c.packed & 0x00ffffff) | wasSemiTrans;
        return *this;
    }
    Color getColor() const { return Color{.packed = command & 0x00ffffff}; }
    Triangle& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    Triangle& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }
    bool isSemiTrans() const { return command & 0x02000000; }
    Triangle& setPointA(Vertex v) {
        pointA = v;
        return *this;
    }
    Triangle& setPointB(Vertex v) {
        pointB = v;
        return *this;
    }
    Triangle& setPointC(Vertex v) {
        pointC = v;
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
    TexturedTriangle() : command(0x24808080) {}
    TexturedTriangle(Color c) : command(0x24000000 | (c.packed & 0x00ffffff)) {}
    TexturedTriangle(const TexturedTriangle& other, Color c) : command(other.command | (c.packed & 0x00ffffff)) {}
    TexturedTriangle& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x24000000 | (c.packed & 0x00ffffff) | wasSemiTrans;
        return *this;
    }
    Color getColor() const { return Color{.packed = command & 0x00ffffff}; }
    TexturedTriangle& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    TexturedTriangle& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }
    bool isSemiTrans() const { return command & 0x02000000; }

  private:
    uint32_t command;

  public:
    Vertex pointA;
    PrimPieces::UVCoords uvA;
    PrimPieces::ClutIndex clutIndex;
    Vertex pointB;
    PrimPieces::UVCoords uvB;
    PrimPieces::TPageAttr tpage;
    Vertex pointC;
    PrimPieces::UVCoordsPadded uvC;
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
    GouraudTriangle(Color c) : command(0x30000000 | (c.packed & 0x00ffffff)) {}
    GouraudTriangle(const GouraudTriangle& other, Color c) : command(other.command | (c.packed & 0x00ffffff)) {}
    GouraudTriangle& setColorA(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x30000000 | (c.packed & 0x00ffffff) | wasSemiTrans;
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
    Color getColorA() const { return Color{.packed = command & 0x00ffffff}; }
    Color getColorB() const { return colorB; }
    Color getColorC() const { return colorC; }
    GouraudTriangle& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    GouraudTriangle& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }
    bool isSemiTrans() const { return command & 0x02000000; }
    GouraudTriangle& setPointA(Vertex v) {
        pointA = v;
        return *this;
    }
    GouraudTriangle& setPointB(Vertex v) {
        pointB = v;
        return *this;
    }
    GouraudTriangle& setPointC(Vertex v) {
        pointC = v;
        return *this;
    }
    template <Transparency transparency = Transparency::Auto>
    void interpolateColors(const Color* a, const Color* b, const Color* c) {
        GTE::write<GTE::Register::RGB0, GTE::Unsafe>(&a->packed);
        GTE::write<GTE::Register::RGB1, GTE::Unsafe>(&b->packed);
        GTE::write<GTE::Register::RGB2, GTE::Unsafe>(&c->packed);
        if constexpr (transparency == Transparency::Auto) {
            GTE::write<GTE::Register::RGB, GTE::Safe>(&command);
        } else if constexpr (transparency == Transparency::Opaque) {
            GTE::write<GTE::Register::RGB, GTE::Safe>(0x30000000);
        } else if constexpr (transparency == Transparency::SemiTransparent) {
            GTE::write<GTE::Register::RGB, GTE::Safe>(0x32000000);
        }
        GTE::Kernels::dpct();
        GTE::read<GTE::Register::RGB0>(&command);
        GTE::read<GTE::Register::RGB1>(&colorB.packed);
        GTE::read<GTE::Register::RGB2>(&colorC.packed);
    }
    template <Transparency transparency = Transparency::Auto>
    void interpolateColors(Color a, Color b, Color c) {
        GTE::write<GTE::Register::RGB0, GTE::Unsafe>(a.packed);
        GTE::write<GTE::Register::RGB1, GTE::Unsafe>(b.packed);
        GTE::write<GTE::Register::RGB2, GTE::Unsafe>(c.packed);
        if constexpr (transparency == Transparency::Auto) {
            GTE::write<GTE::Register::RGB, GTE::Safe>(&command);
        } else if constexpr (transparency == Transparency::Opaque) {
            GTE::write<GTE::Register::RGB, GTE::Safe>(0x30000000);
        } else if constexpr (transparency == Transparency::SemiTransparent) {
            GTE::write<GTE::Register::RGB, GTE::Safe>(0x32000000);
        }
        GTE::Kernels::dpct();
        GTE::read<GTE::Register::RGB0>(&command);
        GTE::read<GTE::Register::RGB1>(&colorB.packed);
        GTE::read<GTE::Register::RGB2>(&colorC.packed);
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
    GouraudTexturedTriangle() : command(0x34000000) {}
    GouraudTexturedTriangle(Color c) : command(0x34000000 | (c.packed & 0x00ffffff)) {}
    GouraudTexturedTriangle(const GouraudTexturedTriangle& other, Color c)
        : command(other.command | (c.packed & 0x00ffffff)) {}
    GouraudTexturedTriangle& setColorA(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x34000000 | (c.packed & 0x00ffffff) | wasSemiTrans;
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
    Color getColorA() const { return Color{.packed = command & 0x00ffffff}; }
    Color getColorB() const { return colorB; }
    Color getColorC() const { return colorC; }
    GouraudTexturedTriangle& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    GouraudTexturedTriangle& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }
    bool isSemiTrans() const { return command & 0x02000000; }
    template <Transparency transparency = Transparency::Auto>
    void interpolateColors(const Color* a, const Color* b, const Color* c) {
        GTE::write<GTE::Register::RGB0, GTE::Unsafe>(&a->packed);
        GTE::write<GTE::Register::RGB1, GTE::Unsafe>(&b->packed);
        GTE::write<GTE::Register::RGB2, GTE::Unsafe>(&c->packed);
        if constexpr (transparency == Transparency::Auto) {
            GTE::write<GTE::Register::RGB, GTE::Safe>(&command);
        } else if constexpr (transparency == Transparency::Opaque) {
            GTE::write<GTE::Register::RGB, GTE::Safe>(0x34000000);
        } else if constexpr (transparency == Transparency::SemiTransparent) {
            GTE::write<GTE::Register::RGB, GTE::Safe>(0x36000000);
        }
        GTE::Kernels::dpct();
        GTE::read<GTE::Register::RGB0>(&command);
        GTE::read<GTE::Register::RGB1>(&colorB.packed);
        GTE::read<GTE::Register::RGB2>(&colorC.packed);
    }
    template <Transparency transparency = Transparency::Auto>
    void interpolateColors(Color a, Color b, Color c) {
        GTE::write<GTE::Register::RGB0, GTE::Unsafe>(a.packed);
        GTE::write<GTE::Register::RGB1, GTE::Unsafe>(b.packed);
        GTE::write<GTE::Register::RGB2, GTE::Unsafe>(c.packed);
        if constexpr (transparency == Transparency::Auto) {
            GTE::write<GTE::Register::RGB, GTE::Safe>(&command);
        } else if constexpr (transparency == Transparency::Opaque) {
            GTE::write<GTE::Register::RGB, GTE::Safe>(0x34000000);
        } else if constexpr (transparency == Transparency::SemiTransparent) {
            GTE::write<GTE::Register::RGB, GTE::Safe>(0x36000000);
        }
        GTE::Kernels::dpct();
        GTE::read<GTE::Register::RGB0>(&command);
        GTE::read<GTE::Register::RGB1>(&colorB.packed);
        GTE::read<GTE::Register::RGB2>(&colorC.packed);
    }

  private:
    uint32_t command;

  public:
    Vertex pointA;
    PrimPieces::UVCoords uvA;
    PrimPieces::ClutIndex clutIndex;
    Color colorB;
    Vertex pointB;
    PrimPieces::UVCoords uvB;
    PrimPieces::TPageAttr tpage;
    Color colorC;
    Vertex pointC;
    PrimPieces::UVCoordsPadded uvC;
};
static_assert(sizeof(GouraudTexturedTriangle) == (sizeof(uint32_t) * 9), "GouraudTexturedTriangle is not 9 words");

}  // namespace Prim

}  // namespace psyqo
