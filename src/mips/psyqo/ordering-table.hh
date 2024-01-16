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

namespace psyqo {

class GPU;

class OrderingTableBase {
  protected:
    static void clear(uint32_t* table, size_t size);
    static void insert(uint32_t* table, int32_t size, uint32_t* head, uint32_t shiftedFragmentSize, int32_t z);
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
template <size_t N = 4096>
class OrderingTable : private OrderingTableBase {
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
     * of the range [0, N - 1] will be clamped to the nearest valid value.
     *
     * @param frag The fragment to insert.
     * @param z The Z value of the fragment.
     */
    template <Fragment Frag>
    void insert(Frag& frag, int32_t z) {
        // TODO: cater for big packets
        OrderingTableBase::insert(m_table, N, &frag.head, uint32_t(frag.getActualFragmentSize() << 24), z);
    }

  private:
    uint32_t m_table[N + 1];
    friend class GPU;
};

}  // namespace psyqo
