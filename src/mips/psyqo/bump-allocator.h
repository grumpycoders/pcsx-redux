/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

#include "psyqo/fragment-concept.hh"
#include "psyqo/fragments.hh"
#include "psyqo/primitive-concept.hh"

namespace psyqo {

/**
 * @brief A bump allocator for fragments.
 *
 * @details This allocator is used to allocate fragments without the need for
 * dynamic memory allocation. It is useful for allocating fragments to render in a
 * complex scene, where the number of fragments isn't known at compile time.
 *
 * The allocator will need to be reset at the beginning of each frame, to ensure
 * that the memory is properly reused. Also, don't forget to double buffer the
 * allocator when chaining fragments allocated with it.
 *
 * The allocate method works with both primitives, and custom fragments. It will
 * always return a reference to the allocated fragment.
 *
 * @tparam N The size of the memory buffer in bytes.
 */
template <size_t N>
class BumpAllocator {
  public:
    template <Primitive P>
    Fragments::SimpleFragment<P> &allocate() {
        constexpr size_t size = sizeof(Fragments::SimpleFragment<P>);
        auto *ptr = m_current;
        m_current += size;
        return *new (ptr) Fragments::SimpleFragment<P>();
    }
    template <Fragment F>
    F &allocate() {
        constexpr size_t size = sizeof(F);
        auto *ptr = m_current;
        m_current += size;
        return *new (ptr) F();
    }
    void reset() { m_current = m_memory; }

  private:
    uint8_t m_memory[N] __attribute__((aligned(4)));
    uint8_t *m_current = m_memory;
};

}  // namespace psyqo
