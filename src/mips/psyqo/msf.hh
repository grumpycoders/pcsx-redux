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

#include <compare>

namespace psyqo {

static inline constexpr uint8_t btoi(uint8_t b) { return ((b / 16) * 10) + (b % 16); }
static inline constexpr uint8_t itob(uint8_t i) { return ((i / 10) * 16) + (i % 10); }

struct MSF {
    MSF() : m(0), s(0), f(0) {}
    MSF(uint8_t m, uint8_t s, uint8_t f) : m(m), s(s), f(f) {}
    explicit MSF(uint32_t lba);
    auto operator<=>(const MSF &other) const;
    bool operator==(const MSF &other) const { return m == other.m && s == other.s && f == other.f; }
    MSF &operator++();
    MSF operator++(int) {
        MSF tmp = *this;
        ++(*this);
        return tmp;
    }
    constexpr uint32_t toLBA() const { return (m * 60 + s) * 75 + f; }
    constexpr void toBCD(uint8_t *dst) const {
        dst[0] = itob(m);
        dst[1] = itob(s);
        dst[2] = itob(f);
    }
    constexpr void fromBCD(const uint8_t *src) {
        m = btoi(src[0]);
        s = btoi(src[1]);
        f = btoi(src[2]);
    }
    void reset() { m = s = f = 0; }
    union {
        struct {
            uint8_t m;
            uint8_t s;
            uint8_t f;
            uint8_t pad;
        };
        uint8_t data[4];
    };
};

}  // namespace psyqo
