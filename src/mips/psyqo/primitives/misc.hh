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
 * @brief The FlushCache primitive.
 *
 * @details This primitive will flush the GPU's cache. It's meant to be used
 * after changing a texture or a CLUT, as the GPU has a small texture cache.
 * The primary usage should be when doing render-to-texture. The `GPU` class
 * will use it for its `uploadToVRAM` method.
 */
struct FlushCache {
    FlushCache() : command(0x01000000) {}

  private:
    uint32_t command;
};
static_assert(sizeof(FlushCache) == sizeof(uint32_t), "FlushCache is not 32 bits");

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
    FastFill() : command(0x02000000) {}
    FastFill(Color c) : command(0x02000000 | c.packed) {}
    FastFill& setColor(Color c) {
        command = 0x02000000 | c.packed;
        return *this;
    }

  private:
    uint32_t command;

  public:
    Rect rect;
};
static_assert(sizeof(FastFill) == (sizeof(uint32_t) * 3), "FastFill is not 96 bits");


}  // namespace Prim

}  // namespace psyqo
