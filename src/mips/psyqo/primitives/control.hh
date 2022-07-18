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

struct TPage {
    TPage() : command(0xe100) {}
    TPageAttr attr;

  private:
    uint16_t command;
};
static_assert(sizeof(TPage) == sizeof(uint32_t), "TPage is not 32 bits");

/**
 * @brief The DrawingAreaStart primitive.
 *
 * @details This primitive will define the start location of the drawing area.
 * It will be used by the `GPU` class when changing buffers, so there shouldn't
 * be any need to use it directly. Any primitive drawn outside of the drawing
 * area will be clipped away.
 */
struct DrawingAreaStart {
    DrawingAreaStart(Vertex p) : command(0xe3000000 | p.x | (p.y << 10)) {}

  private:
    uint32_t command;
};
static_assert(sizeof(DrawingAreaStart) == sizeof(uint32_t), "DrawingAreaStart is not 32 bits");

/**
 * @brief The DrawingAreaEnd primitive.
 *
 * @details This primitive will define the end location of the drawing area.
 * It will be used by the `GPU` class when changing buffers, so there shouldn't
 * be any need to use it directly. Any primitive drawn outside of the drawing
 * area will be clipped away.
 */
struct DrawingAreaEnd {
    DrawingAreaEnd(Vertex p) : command(0xe4000000 | (p.x - 1) | ((p.y - 1) << 10)) {}

  private:
    uint32_t command;
};
static_assert(sizeof(DrawingAreaEnd) == sizeof(uint32_t), "DrawingAreaEnd is not 32 bits");

/**
 * @brief The DrawingOffset primitive.
 *
 * @details This primitive will define the end location of the drawing area.
 * It will be used by the `GPU` class when changing buffers, so there shouldn't
 * be any need to use it directly. Any primitive drawn will be shifted by the
 * offset specified in the constructor.
 */
struct DrawingOffset {
    DrawingOffset(Vertex p) : command(0xe5000000 | p.x | (p.y << 11)) {}

  private:
    uint32_t command;
};
static_assert(sizeof(DrawingOffset) == sizeof(uint32_t), "DrawingOffset is not 32 bits");

/**
 * @brief A compounded Scissor primitive.
 *
 * @details This compounds the necessary primitives to alter the drawing area
 * for all drawing commands. It's meant to be used by the `GPU` class, but
 * can be used sometimes to clip a different area within the vram.
 *
 * The default constructor will create a Scissor which will clip over the
 * entire VRAM, effectively disabling scissoring.
 */
struct Scissor {
    DrawingAreaStart start = DrawingAreaStart(Vertex{{.x = 0, .y = 0}});
    DrawingAreaEnd end = DrawingAreaEnd(Vertex{{.x = 1024, .y = 512}});
    DrawingOffset offset = DrawingOffset(Vertex{{.x = 0, .y = 0}});
};

/**
 * @brief Initiates a VRAM upload.
 *
 * @details This primitive really shouldn't be used directly. If sent to the GPU,
 * it must be followed by the raw pixel data to be sent to the VRAM.
 */
struct VRAMUpload {
    VRAMUpload() : command(0xa0000000) {}

  private:
    uint32_t command;

  public:
    Rect region;
};
static_assert(sizeof(VRAMUpload) == (sizeof(uint32_t) * 3), "VRAMUpload is not 96 bits");

}  // namespace Prim

}  // namespace psyqo
