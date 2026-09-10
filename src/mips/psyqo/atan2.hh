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

#include "psyqo/trigonometry.hh"

namespace psyqo {

/**
 * @brief Fixed point atan2.
 *
 * @details Returns the angle of the vector (x, y), following the standard C
 * convention: zero at the +X axis, counter-clockwise positive, result in
 * (-1.0_pi, 1.0_pi]. That range round-trips into `cos` and `sin` with no caller
 * fixup, because those normalize through a uint32_t modulo which handles
 * two's-complement negatives correctly.
 *
 * This is a free function rather than a `Trig<>` member on purpose: it needs no
 * cosine table, so it costs nothing to anyone who never calls it, and it does not
 * drag a `Trig<>` instantiation in with it. It is not templated on precision
 * either, because `Angle` is always `FixedPoint<10>` no matter how `Trig<>` was
 * instantiated.
 *
 * The arguments are plain integers and only their ratio matters, so feed it
 * whatever units you have. atan2(5, 5) and atan2(10, 10) agree by construction.
 */
[[nodiscard]] Angle atan2(int32_t y, int32_t x);

}  // namespace psyqo
