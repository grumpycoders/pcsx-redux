/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

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

namespace Utilities {

template <std::integral T, unsigned size = (sizeof(T) + 7) / 8>
T loadUnaligned(const uint8_t *ptr) {
    T ret = 0;
    for (unsigned i = 0; i < size; i++) {
        ret |= (ptr[i] << (i * 8));
    }
    return ret;
}

template <std::integral T, unsigned size = (sizeof(T) + 7) / 8>
void storeUnaligned(uint8_t *ptr, T value) {
    for (unsigned i = 0; i < size; i++) {
        ptr[i] = value >> (i * 8);
    }
}

}  // namespace Utilities

#endif

#ifdef __mips__
static __inline__ uint32_t load32Unaligned(const void *in, int pos) {
    const uint8_t *buffer = (const uint8_t *)in;
    uint32_t r;
    __builtin_memcpy(&r, buffer + pos, sizeof(uint32_t));
    return r;
}
#endif
