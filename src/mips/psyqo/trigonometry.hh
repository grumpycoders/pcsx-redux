/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

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

#include "psyqo/fixed-point.hh"

namespace psyqo {

namespace TrigInternals {

void generateTable(eastl::array<int32_t, 512>& table, unsigned precisionBits);

}

/**
 * @brief A fixed point angle.
 *
 * @details This is a fixed point angle. Its value is in fractions of Pi.
 * In other words, 1.0 is 180 degrees, 0.5 is 90 degrees, and so on.
 */
typedef FixedPoint<10> Angle;

namespace trig_literals {

/**
 * @brief A user-defined literal for angle values.
 *
 * @param angle The angle in fractions of Pi.
 * @return consteval Angle The constructed angle.
 */
consteval Angle operator""_pi(long double angle) { return angle; }

}  // namespace trig_literals

/**
 * @brief A trigonometry table.
 *
 * @details This is a trigonometry table. It is used to calculate
 * sine and cosine values for angles. It is constructed with a
 * template parameter that specifies the number of bits of
 * precision to use for the table. The default is 12 bits.
 *
 * @tparam precisionBits The number of bits of precision to use
 * for the FixedPoint values in the table.
 */
template <unsigned precisionBits = 12>
class Trig {
  public:
    Trig() { TrigInternals::generateTable(table, precisionBits); }

    /**
     * @brief Calculate the cosine of an angle.
     *
     * @param a The angle to calculate the cosine of.
     * @return FixedPoint<precisionBits> The cosine of the angle.
     */
    FixedPoint<precisionBits> cos(Angle a) const {
        using namespace trig_literals;
        uint32_t t = a.value;

        t %= (2.0_pi).value;
        a.value = t;
        int32_t r;

        if (a < 0.5_pi) {
            r = table[t];
        } else if (a < 1.0_pi) {
            r = -table[(1.0_pi).value - 1 - t];
        } else if (a < 1.5_pi) {
            r = -table[t - (1.0_pi).value];
        } else {
            r = table[(2.0_pi).value - 1 - t];
        }

        FixedPoint<precisionBits> ret;
        ret.value = r;
        return ret;
    }

    /**
     * @brief Calculate the sine of an angle.
     *
     * @param a The angle to calculate the sine of.
     * @return FixedPoint<precisionBits> The sine of the angle.
     */
    FixedPoint<precisionBits> sin(Angle a) const {
        using namespace trig_literals;
        return cos(a - 0.5_pi);
    }

  private:
    eastl::array<int32_t, 512> table;
};

}  // namespace psyqo
