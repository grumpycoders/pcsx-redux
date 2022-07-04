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

/**
 * @brief The fragments helpers.
 *
 * @details This namespace provides helper templates to create fragments.
 * A fragment is any structure which validates the following constraints:
 * - it must contain a uint32_t named `head` which is reserved for the usage
 *   of the `GPU` class.
 * - it must have a `size_t getActualFragmentSize()` method which returns
 *   the size of the fragment's payload in uint32_t units.
 * - the fragment payload must be immediately after the `head` field.
 *
 * The structure may have any other field for its own usage.
 *
 * Fragments are used by the `GPU` class to send a list of commands to the GPU.
 * This can be done either using the `sendFragment` call to only send a single
 * fragment, or by using the `chain` call to queue the fragments in a chain to
 * be sent later.
 */

namespace Fragments {

/**
 * @brief A maximum fixed sized fragment of similar primitives.
 *
 * @details This fragment contains a prologue, followed by a sequence of
 * identical primitives. The prologue typically is used to store a setup
 * for the rest of the primitives. The payload is a sequence of primitives
 * of identical type. The `count` field needs to be updated to reflect the
 * actual number of primitives stored in the fragment's payload.
 * @tparam P The prologue type.
 * @tparam T The primitive type.
 * @tparam N The maximum number of primitives in the payload.
 */

template <typename P, typename T, size_t N>
struct FixedFragment {
    constexpr size_t maxSize() const { return N; }
    FixedFragment() {
        static_assert(sizeof(*this) == (sizeof(unsigned) + sizeof(uint32_t) + sizeof(P) + sizeof(T) * N),
                      "Spurious padding in fixed fragment");
    }
    typedef T FragmentBaseType;
    size_t getActualFragmentSize() const { return (sizeof(P) + sizeof(T) * count) / sizeof(uint32_t); }
    unsigned count;
    uint32_t head;
    P prologue;
    eastl::array<T, N> primitives;
};

}  // namespace Fragments

}  // namespace psyqo
