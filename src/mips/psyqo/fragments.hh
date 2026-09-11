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
#include <EASTL/utility.h>
#include <stdint.h>

#include "psyqo/primitive-concept.hh"

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
 * @brief A fragment containing a single primitive.
 *
 * @details This fragment contains a single primitive. The primitive type
 * can be a compounded structure of multiple primitive types.
 * @tparam T The primitive type.
 */

struct ChainEntryPS1;
struct ChainEntryPC;

#ifdef PS1_PC_PORT
using ChainEntry = ChainEntryPC;
#else
using ChainEntry = ChainEntryPS1;
#endif

struct ChainEntryPC {
    ChainEntry* next;
    unsigned size;
    void setEndMarker() {
        next = nullptr;
        size = 0;
    }
    void set(ChainEntry* next_, unsigned size_) {
        next = next_;
        size = size_;
    }
};

struct ChainEntryPS1 {
    uintptr_t head;
    void setEndMarker() {
        head = 0xffffff;
    }
    void set(ChainEntryPS1* next, unsigned size) {
        head = (size << 24) | (next->head & 0xffffff);
    }
};

template <Primitive Prim>
struct SimpleFragment : ChainEntry {
    constexpr size_t maxSize() const { return 1; }
    template <typename... Args>
    SimpleFragment(Args &&...args) : primitive(eastl::forward<Args>(args)...) {
#ifndef PS1_PC_PORT
        static_assert(sizeof(*this) == (sizeof(uint32_t) + sizeof(Prim)), "Spurious padding in simple fragment");
#endif
    }
    explicit SimpleFragment(const SimpleFragment &) = default;
    typedef Prim FragmentBaseType;
    constexpr size_t getActualFragmentSize() const { return sizeof(Prim) / sizeof(uint32_t); }
    Prim primitive;
};

/**
 * @brief A maximum fixed sized fragment of similar primitives.
 *
 * @details This fragment is a simple sequence of identical primitives.
 * The `count` field needs to be updated to reflect the actual number
 * of primitives stored in the fragment's payload. The primitive type
 * can be a compounded structure of multiple primitive types.
 * @tparam T The primitive type.
 * @tparam N The maximum number of primitives in the payload.
 */

template <Primitive Prim, size_t N>
struct FixedFragment : ChainEntry {
    constexpr size_t maxSize() const { return N; }
    FixedFragment() {
#ifndef PS1_PC_PORT
        static_assert(sizeof(*this) == (sizeof(unsigned) + sizeof(uintptr_t) + sizeof(Prim) * N),
                      "Spurious padding in fixed fragment");
#endif
    }
    explicit FixedFragment(const FixedFragment &) = default;
    typedef Prim FragmentBaseType;
    size_t getActualFragmentSize() const { return (sizeof(Prim) * count) / sizeof(uint32_t); }
    eastl::array<Prim, N> primitives;
    unsigned count = N;
};

/**
 * @brief A maximum fixed sized fragment of similar primitives.
 *
 * @details This fragment contains a prologue, followed by a sequence of
 * identical primitives. The prologue typically is used to store a setup
 * for the rest of the primitives. The payload is a sequence of primitives
 * of identical type. The `count` field needs to be updated to reflect the
 * actual number of primitives stored in the fragment's payload. The primitive
 * type can be a compounded structure of multiple primitive types.
 * @tparam P The prologue type.
 * @tparam T The primitive type.
 * @tparam N The maximum number of primitives in the payload.
 */

template <Primitive P, Primitive Prim, size_t N>
struct FixedFragmentWithPrologue : ChainEntry {
    constexpr size_t maxSize() const { return N; }
    FixedFragmentWithPrologue() {
#ifndef PS1_PC_PORT
        static_assert(sizeof(*this) == (sizeof(unsigned) + sizeof(uintptr_t) + sizeof(P) + sizeof(Prim) * N),
                      "Spurious padding in fixed fragment");
#endif
    }
    explicit FixedFragmentWithPrologue(const FixedFragmentWithPrologue &) = default;
    typedef Prim FragmentBaseType;
    size_t getActualFragmentSize() const { return (sizeof(P) + sizeof(Prim) * count) / sizeof(uint32_t); }
    P prologue;
    eastl::array<Prim, N> primitives;
    unsigned count = N;
};

}  // namespace Fragments

}  // namespace psyqo
