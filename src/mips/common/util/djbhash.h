/*

MIT License

Copyright (c) 2019 PCSX-Redux authors

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

#ifdef __cplusplus
#include <concepts>

namespace djb {

template <std::integral T = uint32_t>
static inline constexpr T process(T hash, const char str[], unsigned n) {
    return n ? process(((hash << 5) + hash) ^ static_cast<uint8_t>(str[0]), str + 1, n - 1) : hash;
}

template <std::integral T = uint32_t>
static inline T constexpr hash(const char* str, unsigned n) {
    return process(T(5381), str, n);
}

template <std::integral T = uint32_t, unsigned S>
static inline T constexpr hash(const char (&str)[S]) {
    return process(T(5381), str, S - 1);
}

}  // namespace djb

#endif

static inline uint32_t djbProcess(uint32_t hash, const char str[], unsigned n) {
    return n ? djbProcess(((hash << 5) + hash) ^ ((uint8_t)str[0]), str + 1, n - 1) : hash;
}

static inline uint32_t djbHash(const char* str, unsigned n) { return djbProcess(5381, str, n); }
