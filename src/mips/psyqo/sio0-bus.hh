/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

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

namespace psyqo {

/**
 * @brief Ownership arbiter for the SIO0 serial bus.
 *
 * @details The controller (pad) and the memory card share a single SIO0 bus
 * and cannot drive it at the same time: two owners clocking the line at once
 * corrupt each other's transfers. A memory card transaction can span several
 * frames (the card introduces multi-thousand-cycle gaps before some of its
 * acknowledges), so it must own the bus for its WHOLE duration, not just one
 * byte or one sector at a time.
 *
 * This is that lock. A memory card operation takes it for the entire
 * transaction; `AdvancedPad` (and `SimplePad`) consult `owned()` each frame and
 * skip polling while it is held, so the pad never touches the bus mid-card-op.
 * The count is re-entrant: a filesystem operation holds it across all of its
 * sector transfers even though each blocking sector transfer also takes it.
 *
 * There is a single bus, so the state is static; only one transaction is ever
 * in flight. It is only ever mutated from the main thread (operations start and
 * end synchronously); the asynchronous transfer engine itself does not touch
 * it, so no IRQ-context mutation occurs.
 */
class SIO0Bus {
  public:
    /**
     * @brief Takes ownership of the bus for the calling transaction.
     */
    static void acquire() { s_depth = s_depth + 1; }

    /**
     * @brief Releases one level of ownership taken by `acquire`.
     */
    static void release() {
        if (s_depth) s_depth = s_depth - 1;
    }

    /**
     * @brief Returns whether the bus is currently owned by a card transaction.
     */
    static bool owned() { return s_depth != 0; }

    /**
     * @brief RAII helper that owns the bus for the lifetime of the object.
     *
     * @details Used at the entry of a memory card operation; the bus stays
     * owned until the operation's stack frame (or coroutine frame) unwinds.
     */
    struct Lock {
        Lock() { acquire(); }
        ~Lock() { release(); }
        Lock(const Lock &) = delete;
        Lock &operator=(const Lock &) = delete;
    };

  private:
    static inline volatile uint32_t s_depth = 0;
};

}  // namespace psyqo
