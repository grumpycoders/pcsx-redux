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
    static constexpr uint32_t BASE = 0b011'00'1 << 26;
    Sprite() : command(BASE) {}
    Sprite(Color c) : command(BASE | c.packed) {}
    Sprite& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = BASE | c.packed | wasSemiTrans;
        return *this;
    }
    Sprite& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    Sprite& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex position;
    TexInfo texInfo;
    Vertex size;
};
static_assert(sizeof(Sprite) == (sizeof(uint32_t) * 4), "Sprite is not 128 bits");

/**
 * @brief The 1x1 Sprite primitive.
 *
 * @details This primitive will draw a sprite of exactly 1 pixel. The `position` member
 * describes the location within the screen where the sprite will be blitted. The
 * `texInfo`member indicates where the source sprite is blitted from.
 *
 * The texture information needs to be specified with a TPage primitive beforehand.
 */
struct Sprite1x1 {
    static constexpr uint32_t BASE = 0b011'01'1 << 26;
    Sprite1x1() : command(BASE) {}
    Sprite1x1(Color c) : command(BASE | c.packed) {}
    Sprite1x1& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = BASE | c.packed | wasSemiTrans;
        return *this;
    }
    Sprite1x1& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    Sprite1x1& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex position;
    TexInfo texInfo;
};
static_assert(sizeof(Sprite1x1) == (sizeof(uint32_t) * 3), "Sprite1x1 is not 3 words");

/**
 * @brief The 8x8 Sprite primitive.
 *
 * @details This primitive will draw a sprite of 8 by 8 pixels. The `position` member
 * describes the location within the screen where the sprite will be blitted. The
 * `texInfo`member indicates where the source sprite is blitted from.
 *
 * The texture information needs to be specified with a TPage primitive beforehand.
 */
struct Sprite8x8 {
    static constexpr uint32_t BASE = 0b011'10'1 << 26;
    Sprite8x8() : command(BASE) {}
    Sprite8x8(Color c) : command(BASE | c.packed) {}
    Sprite8x8& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = BASE | c.packed | wasSemiTrans;
        return *this;
    }
    Sprite8x8& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    Sprite8x8& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex position;
    TexInfo texInfo;
};
static_assert(sizeof(Sprite8x8) == (sizeof(uint32_t) * 3), "Sprite8x8 is not 3 words");

/**
 * @brief The 16x16 Sprite primitive.
 *
 * @details This primitive will draw a sprite of 16 by 16 pixels. The `position` member
 * describes the location within the screen where the sprite will be blitted. The
 * `texInfo`member indicates where the source sprite is blitted from.
 *
 * The texture information needs to be specified with a TPage primitive beforehand.
 */
struct Sprite16x16 {
    static constexpr uint32_t BASE = 0b011'11'1 << 26;
    Sprite16x16() : command(BASE) {}
    Sprite16x16(Color c) : command(BASE | c.packed) {}
    Sprite16x16& setColor(Color c) {
        uint32_t wasSemiTrans = command & 0x02000000;
        command = BASE | c.packed | wasSemiTrans;
        return *this;
    }
    Sprite16x16& setOpaque() {
        command &= ~0x02000000;
        return *this;
    }
    Sprite16x16& setSemiTrans() {
        command |= 0x02000000;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Vertex position;
    TexInfo texInfo;
};
static_assert(sizeof(Sprite16x16) == (sizeof(uint32_t) * 3), "Sprite16x16 is not 3 words");

}  // namespace Prim

}  // namespace psyqo
