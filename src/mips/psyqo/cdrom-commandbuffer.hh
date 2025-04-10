/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

#include <concepts>
#include <type_traits>

namespace psyqo::Hardware::CDRom {

template <typename T>
concept CDRomArgumentType = std::is_integral<T>::value;

struct CDRomCommandBuffer {
    template <CDRomArgumentType... T>
    void set(T... values) {
        size = sizeof...(values);
        recursiveSet(0, values...);
    }

    uint8_t buffer[16];
    uint8_t size = 0;

  private:
    void recursiveSet(uint8_t pos, uint8_t arg) { buffer[pos] = arg; }

    template <CDRomArgumentType... T>
    void recursiveSet(uint8_t pos, uint8_t arg, T... args) {
        buffer[pos] = arg;
        recursiveSet(pos + 1, args...);
    }
};
} // namespace psyqo::Hardware::CDRom