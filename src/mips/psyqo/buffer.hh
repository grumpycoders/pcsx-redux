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

#include "common/util/buffer.hh"
#include "psyqo/alloc.h"

namespace psyqo {

struct PsyqoAllocator {
    template <typename T>
    static inline T* allocate(size_t size) {
        return reinterpret_cast<T*>(psyqo_malloc(size * sizeof(T)));
    }
    static inline void deallocate(void* ptr) { psyqo_free(ptr); }
    template <typename T>
    static inline T* reallocate(void* ptr, size_t size) {
        return reinterpret_cast<T*>(psyqo_realloc(ptr, size * sizeof(T)));
    }
    template <typename T>
    static inline void copy(T* dst, const T* src, size_t size) {
        __builtin_memcpy(dst, src, size * sizeof(T));
    }
};

template <typename T>
using Buffer = Utilities::Buffer<T, PsyqoAllocator>;

}  // namespace psyqo
