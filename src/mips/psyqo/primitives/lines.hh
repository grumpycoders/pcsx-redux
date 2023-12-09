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

#include <EASTL/array.h>
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

/**
 * @brief The primitive used to begin a polyline.
 *
 * @details This primitive is used to begin a flat-color polyline. As polylines
 * are drawn using multiple Line primitives, this primitive is used to set the
 * color of the polyline and the first vertex. As polylines can be complex,
 * this allows drawing them piece by piece, iteratively. After sending this
 * primitive, you need to send a number of Vertex structures using the GPU's
 * `sendRaw` method, and then send a PolyLineEnd struct to finish the polyline.
 * Note that it may be necessary to use the `waitFifo` method of the GPU to
 * ensure that the GPU has finished processing the previous vertex data before
 * sending the next one.
 */
struct PolyLineBegin {
    PolyLineBegin() : command(0x48000000) {}
    PolyLineBegin(Color c) : command(0x48000000 | c.packed) {}
    PolyLineBegin& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x48000000 | c.packed | wasSemiTrans;
        return *this;
    }
    PolyLineBegin& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    PolyLineBegin& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex point;
};
static_assert(sizeof(PolyLineBegin) == sizeof(uint32_t) * 2, "PolyLineBegin is not 2 words");

struct PolyLineEnd {
    const uint32_t endMarker = 0x50005000;
};

/**
 * @brief The primitive used to draw a polyline.
 *
 * @details This primitive is used to draw a flat-color polyline. This variant
 * of the primitive is used when the number of segments in the polyline is
 * known at compile time. If the number of segments is not known at compile
 * time, use the `PolyLineBegin` mechanism instead.
 *
 * @tparam N The number of segments in the polyline.
 */

template <unsigned N>
struct PolyLine {
    PolyLine() : command(0x48000000) {}
    PolyLine(Color c) : command(0x48000000 | c.packed) {}
    PolyLine& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = 0x48000000 | c.packed | wasSemiTrans;
        return *this;
    }
    PolyLine& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    PolyLine& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    eastl::array<Vertex, N + 1> points;

  private:
    const uint32_t endMarker = 0x50005000;
};

}  // namespace Prim

}  // namespace psyqo
