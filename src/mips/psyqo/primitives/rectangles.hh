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
    Sprite() : command(0b01100100'00000000'00000000'00000000) {}
    Sprite(Color c) : command(0b01100100'00000000'00000000'00000000 | c.packed) {}
    void setColor(Color c) { command = 0b01100100'00000000'00000000'00000000 | c.packed; }

  private:
    uint32_t command;

  public:
    Vertex position;
    TexInfo texInfo;
    Vertex size;
};
static_assert(sizeof(Sprite) == (sizeof(uint32_t) * 4), "Sprite is not 128 bits");

/**
 * @brief The Pixel primitive.
 *
 * @details This primitive will draw a single pixel. The `position` member
 * specifies the location within the screen where the pixel will be drawn.
 * The color is specified by the constructor parameter, or the `setColor`
 * method.
 */
struct Pixel {
    Pixel() : command(0b01101000'00000000'00000000'00000000) {}
    Pixel(Color c) : command(0b01101000'00000000'00000000'00000000 | c.packed) {}
    void setColor(Color c) { command = 0b01101000'00000000'00000000'00000000 | c.packed; }

  private:
    uint32_t command;

  public:
    Vertex position;
};
static_assert(sizeof(Pixel) == (sizeof(uint64_t)), "Pixel is not 64 bits");


}  // namespace Prim

}  // namespace psyqo
