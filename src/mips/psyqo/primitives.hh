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

/**
 * @brief The Vertex struct.
 *
 * @details Represents a vertex in the VRAM space. Its binary representation is meant
 * to be the same as the vertices that GPU commands await. It should fit in a single
 * register, and the MIPS ABI ought to pass it as argument or return value gracefully,
 * making it a nice general purpose utility.
 *
 * Accessors can be either {x, y}, {u, v}, or {w, h}, for readability purposes.
 *
 * Using C++ list-initializations, one can create a vertex directly using such syntax:
 *
 *    `Vertex{{.x = 18, .y = 42}};`
 */
union Vertex {
    ~Vertex() { static_assert(sizeof(*this) == sizeof(uint32_t), "Vertex is not 32 bits"); }
    struct {
        union {
            int16_t x, u, w;
        };
        union {
            int16_t y, v, h;
        };
    };
    int32_t packed;
};

/**
 * @brief The Rect struct.
 *
 * @details Represents a rectangle in the VRAM space. Its binary representation is meant
 * to be the same as the rectangles that GPU commands await. It should fit in two
 * registers, and the MIPS ABI ought to pass it as argument or return value gracefully,
 * making it a nice general purpose utility.
 *
 * Accessors can be either {a, b}, or {pos, size}, for readability purposes.
 *
 * Using C++ list-initializations, one can create a rectangle directly using such syntax:
 *
 *    `Rect{a. = {.x = 18, .y = 42}, .b = {}};`
 */
struct Rect {
    ~Rect() { static_assert(sizeof(*this) == sizeof(uint64_t), "Rect is not 64 bits"); }
    union {
        Vertex a, pos;
    };
    union {
        Vertex b, size;
    };
};

/**
 * @brief The Color struct
 *
 * @details Represents a 24-bits color, that works properly in GPU binary primitives.
 */

union Color {
    ~Color() { static_assert(sizeof(*this) == sizeof(uint32_t), "Color is not 32 bits"); }
    struct {
        uint8_t r, g, b;
    };
    uint32_t packed;
};

namespace Prim {

/**
 * @brief A primitive's CLUT command
 *
 * @details This shouldn't be used directly, but rather be part of another primitive.
 * The binary representation is meant to be the same as the CLUT argument for
 * GPU commands. The constructor can take either a `Vertex` or the raw x and y
 * coordinates for the CLUT to use.
 *
 * Remember that CLUTs are aligned to 16 pixels, so the coordinates are rounded
 * to the lowest multiple of 16 on the X axis.
 */
struct ClutIndex {
    ClutIndex() { static_assert(sizeof(*this) == sizeof(uint16_t), "ClutIndex is not 16 bits"); }
    ClutIndex(Vertex v) : ClutIndex(v.x >> 4, v.y) {}
    ClutIndex(uint16_t x, uint16_t y) : index((y << 6) | x) {}

  private:
    uint16_t index = 0;
};

/**
 * @brief A primitive's texture information.
 *
 * @details This shouldn't be used directly, but rather be part of another primitive.
 * The binary representation is meant to be the same as the texture argument for
 * GPU commands.
 */
struct TexInfo {
    ~TexInfo() { static_assert(sizeof(*this) == sizeof(uint32_t), "TexInfo is not 32 bits"); }
    uint8_t u;
    uint8_t v;
    ClutIndex clut;
};

/**
 * @brief The FastFill primitive.
 *
 * @details Sending this command will fill the VRAM space specified by the
 * `rect` member with the color specified by the `Color` argument of the
 * constructor or the `setColor` method.
 *
 * This primitive will ignore the current scissor, so it's not a good idea
 * to use it directly. It'll be used properly by the various GPU clear commands.
 */
struct FastFill {
    FastFill() : command(0x02000000) {
        static_assert(sizeof(*this) == (sizeof(uint32_t) * 3), "FastFill is not 96 bits");
    }
    FastFill(Color c) : command(0x02000000 | c.packed) {}
    void setColor(Color c) { command = 0x02000000 | c.packed; }

  private:
    uint32_t command;

  public:
    Rect rect;
};

/**
 * @brief The Sprite primitive.
 *
 * @details This primitive will draw a sprite of arbitrary size. The `position` member
 * describes the location within the screen where the sprite will be blitted. The
 * `texInfo`member indicates where the source sprite is blitted from, and the
 * `size` member specifies actual sprite size to blit.
 *
 * The texture information needs to be specified with a TPage primitive beforehand.
 */
struct Sprite {
    Sprite() : command(0b01100100'00000000'00000000'00000000) {
        static_assert(sizeof(*this) == (sizeof(uint32_t) * 4), "Sprite is not 128 bits");
    }
    Sprite(Color c) : command(0b01100100'00000000'00000000'00000000 | c.packed) {}
    void setColor(Color c) { command = 0b01100100'00000000'00000000'00000000 | c.packed; }

  private:
    uint32_t command;

  public:
    Vertex position;
    TexInfo texInfo;
    Vertex size;
};

/**
 * @brief The Pixel primitive.
 *
 * @details This primitive will draw a single pixel. The `position` member
 * specifies the location within the screen where the pixel will be drawn.
 * The color is specified by the constructor parameter, or the `setColor`
 * method.
 */
struct Pixel {
    Pixel() : command(0b01101000'00000000'00000000'00000000) {
        static_assert(sizeof(*this) == (sizeof(uint64_t)), "Pixel is not 64 bits");
    }
    Pixel(Color c) : command(0b01101000'00000000'00000000'00000000 | c.packed) {}
    void setColor(Color c) { command = 0b01101000'00000000'00000000'00000000 | c.packed; }

  private:
    uint32_t command;

  public:
    Vertex position;
};

/**
 * @brief The FlushCache primitive.
 *
 * @details This primitive will flush the GPU's cache. It's meant to be used
 * after changing a texture or a CLUT, as the GPU has a small texture cache.
 * The primary usage should be when doing render-to-texture. The `GPU` class
 * will use it for its `uploadToVRAM` method.
 */
struct FlushCache {
    FlushCache() : command(0x01000000) {
        static_assert(sizeof(*this) == sizeof(uint32_t), "FlushCache is not 32 bits");
    }

  private:
    uint32_t command;
};

/**
 * @brief The DrawingAreaStart primitive.
 *
 * @details This primitive will define the start location of the drawing area.
 * It will be used by the `GPU` class when changing buffers, so there shouldn't
 * be any need to use it directly. Any primitive drawn outside of the drawing
 * area will be clipped away.
 */
struct DrawingAreaStart {
    DrawingAreaStart(Vertex p) : command(0xe3000000 | p.x | (p.y << 10)) {
        static_assert(sizeof(*this) == sizeof(uint32_t), "DrawingAreaStart is not 32 bits");
    }

  private:
    uint32_t command;
};

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

/**
 * @brief The DrawingOffset primitive.
 *
 * @details This primitive will define the end location of the drawing area.
 * It will be used by the `GPU` class when changing buffers, so there shouldn't
 * be any need to use it directly. Any primitive drawn will be shifted by the
 * offset specified in the constructor.
 */
struct DrawingOffset {
    DrawingOffset(Vertex p) : command(0xe5000000 | p.x | (p.y << 11)) {
        static_assert(sizeof(*this) == sizeof(uint32_t), "DrawingOffset is not 32 bits");
    }

  private:
    uint32_t command;
};

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
    VRAMUpload() : command(0xa0000000) {
        static_assert(sizeof(*this) == (sizeof(uint32_t) * 3), "VRAMUpload is not 96 bits");
    }

  private:
    uint32_t command;

  public:
    Rect region;
};

}  // namespace Prim

}  // namespace psyqo
