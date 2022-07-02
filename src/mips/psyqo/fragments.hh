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

#include <EASTL/array.h>
#include <stdint.h>

namespace psyqo {

namespace Fragments {

template <typename P, typename T, size_t N>
struct FixedFragment {
    FixedFragment() {
        static_assert(sizeof(*this) == (sizeof(unsigned) + sizeof(uint32_t) + sizeof(P) + sizeof(T) * N),
                      "Spurious padding in fixed fragment");
    }
    typedef T FragmentBaseType;
    const uint32_t* getFragmentDataPtr() const { return reinterpret_cast<const uint32_t*>(&prologue); }
    size_t getActualFragmentSize() const { return (sizeof(P) + sizeof(T) * count) / sizeof(uint32_t); }
    unsigned count;
    uint32_t head;
    P prologue;
    eastl::array<T, N> primitives;
};

}  // namespace Fragments

}  // namespace psyqo
