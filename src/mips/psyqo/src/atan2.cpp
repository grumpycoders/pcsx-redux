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

#include "psyqo/atan2.hh"

namespace {

/**
 * @brief Compile-time arctangent, for table generation only.
 *
 * @details Euler's accelerated arctangent series, which converges quickly over
 * the whole of [0, 1] where the naive Taylor series does not. Never runs on the
 * target: it exists so the table below can be computed rather than transcribed.
 */
consteval long double atanForTable(long double x) {
    long double x2 = x * x;
    long double d = 1.0L + x2;
    long double z = x2 / d;
    long double term = 1.0L;
    long double sum = 0.0L;
    for (int n = 0; n < 96; n++) {
        sum += term;
        long double k = 2.0L * (n + 1);
        term *= (k / (k + 1.0L)) * z;
    }
    return (x / d) * sum;
}

/**
 * @brief atan(i / 32) for i in [0, 32], in Angle units.
 *
 * @details 33 entries in 66 bytes of int16_t, which is deliberate and measured:
 * `Angle` is `FixedPoint<10>`, so one output step is already 0.176 degrees, and
 * every table from 17 entries upward sits on that quantization floor. Going to
 * 513 entries costs a kilobyte and buys 0.07 degrees. If you ever need better
 * than a quarter degree here, the lever is a wider `Angle`, not a longer table.
 */
struct Atan2Table {
    int16_t v[33];
    consteval Atan2Table() : v() {
        constexpr long double pi = 3.14159265358979323846264338327950288L;
        for (int i = 0; i <= 32; i++) {
            long double a = atanForTable((long double)i / 32.0L) / pi;
            v[i] = (int16_t)(a * 1024.0L + 0.5L);
        }
    }
};

inline constexpr Atan2Table c_atan2Table{};

}  // namespace

psyqo::Angle psyqo::atan2(int32_t y, int32_t x) {
    if ((x == 0) && (y == 0)) return Angle(int32_t(0), Angle::RAW);
    int32_t ax = x < 0 ? -x : x;
    int32_t ay = y < 0 ? -y : y;
    // Octant reduction: always divide the smaller by the larger, so the ratio is
    // in [0, 1] and the denominator can never be zero once both are not.
    bool steep = ay > ax;
    int32_t num = steep ? ax : ay;
    int32_t den = steep ? ay : ax;
    // Only the ratio matters, so shift both down until the numerator can carry 13
    // extra bits inside an int32_t. This keeps the whole thing off __divdi3, which
    // the R3000 does not have, and costs nothing in accuracy: what we drop is below
    // the table's own resolution long before it is below Angle's.
    while (den >= (1 << 18)) {
        den >>= 1;
        num >>= 1;
    }
    int32_t scaled = (num << 13) / den;  // 32 steps, 8 fractional bits
    int32_t idx = scaled >> 8;
    int32_t frac = scaled & 0xff;
    int32_t a;
    if (idx >= 32) {
        a = c_atan2Table.v[32];
    } else {
        int32_t lo = c_atan2Table.v[idx];
        int32_t hi = c_atan2Table.v[idx + 1];
        a = lo + (((hi - lo) * frac) >> 8);
    }
    // Fold the octant back out, then the quadrant, then the sign.
    if (steep) a = 512 - a;  // 0.5_pi in Angle raw units
    if (x < 0) a = 1024 - a;
    if (y < 0) a = -a;
    return Angle(a, Angle::RAW);
}
