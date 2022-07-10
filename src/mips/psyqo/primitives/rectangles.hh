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

struct Rectangle {
    static constexpr uint32_t BASE = 0b011'00'0 << 26;
    Rectangle() : command(BASE) {}
    Rectangle(Color c) : command(BASE | c.packed) {}
    Rectangle& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = BASE | c.packed | wasSemiTrans;
        return *this;
    }
    Rectangle& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    Rectangle& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex position;
    Vertex size;
};
static_assert(sizeof(Rectangle) == (sizeof(uint32_t) * 3), "Rectangle is not 3 words");

/**
 * @brief The Pixel primitive.
 *
 * @details This primitive will draw a single pixel. The `position` member
 * specifies the location within the screen where the pixel will be drawn.
 * The color is specified by the constructor parameter, or the `setColor`
 * method.
 */
struct Pixel {
    static constexpr uint32_t BASE = 0b011'01'0 << 26;
    Pixel() : command(BASE) {}
    Pixel(Color c) : command(BASE | c.packed) {}
    Pixel& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = BASE | c.packed | wasSemiTrans;
        return *this;
    }
    Pixel& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    Pixel& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex position;
};
static_assert(sizeof(Pixel) == (sizeof(uint64_t)), "Pixel is not 64 bits");

struct Rectangle8x8 {
    static constexpr uint32_t BASE = 0b011'10'0 << 26;
    Rectangle8x8() : command(BASE) {}
    Rectangle8x8(Color c) : command(BASE | c.packed) {}
    Rectangle8x8& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = BASE | c.packed | wasSemiTrans;
        return *this;
    }
    Rectangle8x8& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    Rectangle8x8& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex position;
};
static_assert(sizeof(Rectangle8x8) == (sizeof(uint64_t)), "Rectangle8x8 is not 64 bits");

struct Rectangle16x16 {
    static constexpr uint32_t BASE = 0b011'11'0 << 26;
    Rectangle16x16() : command(BASE) {}
    Rectangle16x16(Color c) : command(BASE | c.packed) {}
    Rectangle16x16& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = BASE | c.packed | wasSemiTrans;
        return *this;
    }
    Rectangle16x16& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    Rectangle16x16& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex position;
};
static_assert(sizeof(Rectangle16x16) == (sizeof(uint64_t)), "Rectangle16x16 is not 64 bits");

}  // namespace Prim

}  // namespace psyqo
