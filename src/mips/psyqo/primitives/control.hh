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
    PrimPieces::TPageAttr attr;

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
 * area will be clipped away. There is no set method for the `Vertex` field, as
 * there is no other field in the struct, and one can simply use a copy constructor
 * to set it.
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
 * area will be clipped away. There is no set method for the `Vertex` field, as
 * there is no other field in the struct, and one can simply use a copy constructor
 * to set it.
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
 * offset specified in the constructor. There is no set method for the `Vertex`
 * field, as there is no other field in the struct, and one can simply use a copy
 * constructor to set it.
 */
struct DrawingOffset {
    DrawingOffset(Vertex p) : command(0xe5000000 | p.x | (p.y << 11)) {}

  private:
    uint32_t command;
};
static_assert(sizeof(DrawingOffset) == sizeof(uint32_t), "DrawingOffset is not 32 bits");

/**
 * @brief The MaskControl primitive.
 *
 * @details This primitive will control the masking of the drawing area. Masking
 * on the GPU is used to prevent drawing in certain areas of the screen. It can
 * be used to create and use a sort of stencil buffer. When the mask is set to
 * `ForceSet`, the "stencil buffer" will be set to 1, and when it's set to
 * `FromSource`, it will be set to the value read from the source texel, knowing it is
 * bit 15 of the texel or the CLUT used by the texture. Texture-less primitives will set
 * the stencil buffer to 0 in this mode, effectively allowing subsequent drawings in
 * the area. The mask can also be set to test the stencil buffer, and only draw if
 * the stencil buffer is set to 0. The mechanism used here can be a little bit
 * counter-intuitive compared with modern hardware, but it's the way the PS1 GPU works.
 */
struct MaskControl {
    enum Set {
        FromSource,
        ForceSet,
    };
    enum class Test {
        No,
        Yes,
    };
    MaskControl() : command(0xe6000000) {}
    MaskControl(Set set, Test test) : command(0xe6000000 | set | (static_cast<uint32_t>(test) << 1)) {}
    MaskControl(Test test, Set set) : MaskControl(set, test) {}
    MaskControl(Set set) : MaskControl(set, Test::No) {}
    MaskControl(Test test) : MaskControl(Set::FromSource, test) {}
    MaskControl &set(Set set) {
        command &= ~0x1;
        command |= set;
        return *this;
    }
    MaskControl &set(Test test) {
        command &= ~0x2;
        command |= static_cast<uint32_t>(test) << 1;
        return *this;
    }
    MaskControl &set(Set set, Test test) {
        return *this = MaskControl(set, test);
    }
    MaskControl &set(Test test, Set set) {
        return *this = MaskControl(set, test);
    }

  private:
    uint32_t command;
};
static_assert(sizeof(MaskControl) == sizeof(uint32_t), "MaskControl is not 32 bits");

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
