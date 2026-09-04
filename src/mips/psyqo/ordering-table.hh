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

#include <EASTL/algorithm.h>
#include <stdint.h>

#include "psyqo/fragment-concept.hh"
#include "psyqo/fragments.hh"
#include "psyqo/shared.hh"

namespace psyqo {

class GPU;

class OrderingTableBase {
  public:
    static void clear(psyqo::Fragments::ChainEntry* table, size_t size);
};

/**
 * @brief The ordering table. Used to sort fragments before sending them to the GPU.
 *
 * @details This class is used to sort fragments before sending them to the GPU.
 * The GPU will then process the fragments in the order specified by the ordering
 * table. Since the PS1 GPU doesn't have any depth buffer, the ordering table is
 * used to roughly sort the fragments by their Z value. Each fragment is assigned
 * a "bucket" based on its Z value. The fragments inside a bucket are NOT sorted.
 * The `GPU` class `chain` function can be used to schedule an ordering table
 * to be sent to the GPU.
 *
 * @tparam N The number of buckets in the ordering table. The larger the number,
 * the more precise the sorting will be, but the more memory will be used.
 */
template <size_t N = 4096, Safe safety = Safe::Yes>
class OrderingTable : public OrderingTableBase {
  public:
    OrderingTable() { clear(); }

    /**
     * @brief Clears the ordering table.
     *
     * @details This function clears the ordering table. The table is automatically
     * cleared by the `GPU` class after it has been sent to the GPU, so this function
     * is only useful if you want to clear the ordering table without sending it to
     * the GPU, which should be a rare use case.
     */
    void clear() { OrderingTableBase::clear(m_table, N); }

    /**
     * @brief Inserts a fragment into the ordering table.
     *
     * @details This function inserts a fragment into the ordering table. The fragment
     * will be inserted into the bucket corresponding to its Z value. Any value outside
     * of the range [0, N - 1] will be clamped to the nearest valid value when `safety`
     * is set to `Safe::Yes`, which is the default.
     *
     * @param frag The fragment to insert.
     * @param z The Z value of the fragment.
     */
    template <Fragment Frag>
    void insert(Frag& frag, int32_t z) {
        // TODO: cater for big packets
        auto* table = m_table + 1;
        if constexpr (safety == Safe::Yes) {
            z = eastl::clamp(z, int32_t(0), int32_t(N - 1));
        }
#ifdef PS1_PC_PORT
        frag.set(table[z].next, frag.getActualFragmentSize());
        table[z].set(&frag, 0);
#else
        frag.set(&table[z], frag.getActualFragmentSize());
        table[z].head = reinterpret_cast<uint32_t>(&frag) & 0xffffff;
#endif
    }

    // NOTE: can't use from other classes (PCGPU) otherwise
    psyqo::Fragments::ChainEntry m_table[N + 1];

  private:
    friend class GPU;
};

}  // namespace psyqo
