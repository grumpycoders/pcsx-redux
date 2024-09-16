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

#include <concepts>
#include <type_traits>

#include "psyqo/fixed-point.hh"
#include "psyqo/primitives/common.hh"

namespace psyqo {

template <unsigned N, unsigned precisionBits = 12, std::integral T = int32_t>
    requires((N >= 2) && (N <= 4))
struct Vector {
    typedef FixedPoint<precisionBits, T> FixedPointType;
    FixedPoint<precisionBits, T> x, y;
    struct EmptyZ {};
    [[no_unique_address]] std::conditional_t<(N > 2), FixedPoint<precisionBits, T>, EmptyZ> z;
    struct EmptyW {};
    [[no_unique_address]] std::conditional_t<(N > 3), FixedPoint<precisionBits, T>, EmptyW> w;
    constexpr FixedPointType& get(unsigned i) {
        if constexpr (N == 2) {
            return (i == 0) ? x : y;
        } else if constexpr (N == 3) {
            return (i == 0) ? x : (i == 1) ? y : z;
        } else if constexpr (N == 4) {
            return (i == 0) ? x : (i == 1) ? y : (i == 2) ? z : w;
        }
    }
    constexpr const FixedPointType& get(unsigned i) const {
        if constexpr (N == 2) {
            return (i == 0) ? x : y;
        } else if constexpr (N == 3) {
            return (i == 0) ? x : (i == 1) ? y : z;
        } else if constexpr (N == 4) {
            return (i == 0) ? x : (i == 1) ? y : (i == 2) ? z : w;
        }
    }
    constexpr FixedPointType& operator[](unsigned i) { return get(i); }
    constexpr operator Vertex() const
        requires((N == 2) && std::is_signed<T>::value)
    {
        return {{.x = x.template integer<int16_t>(), .y = y.template integer<int16_t>()}};
    }
    constexpr Vector& operator+=(const Vector& rhs) {
        for (unsigned i = 0; i < N; i++) {
            get(i) += rhs.get(i);
        }
        return *this;
    }
    constexpr Vector& operator-=(const Vector& rhs) {
        for (unsigned i = 0; i < N; i++) {
            get(i) -= rhs.get(i);
        }
        return *this;
    }
    constexpr Vector& operator*=(const FixedPointType& rhs) {
        for (unsigned i = 0; i < N; i++) {
            get(i) *= rhs;
        }
        return *this;
    }
    constexpr Vector& operator/=(const FixedPointType& rhs) {
        for (unsigned i = 0; i < N; i++) {
            get(i) /= rhs;
        }
        return *this;
    }
    template <std::integral U>
    constexpr Vector& operator*=(U rhs) {
        for (unsigned i = 0; i < N; i++) {
            get(i) *= rhs;
        }
        return *this;
    }
    template <std::integral U>
    constexpr Vector& operator/=(U rhs) {
        for (unsigned i = 0; i < N; i++) {
            get(i) /= rhs;
        }
        return *this;
    }
    constexpr Vector operator-() const {
        Vector result;
        for (unsigned i = 0; i < N; i++) {
            result.get(i) = -get(i);
        }
        return result;
    }
    constexpr Vector operator+(const Vector& rhs) const {
        Vector result;
        for (unsigned i = 0; i < N; i++) {
            result.get(i) = get(i) + rhs.get(i);
        }
        return result;
    }
    constexpr Vector operator-(const Vector& rhs) const {
        Vector result;
        for (unsigned i = 0; i < N; i++) {
            result.get(i) = get(i) - rhs.get(i);
        }
        return result;
    }
    constexpr Vector operator*(const FixedPointType& rhs) const {
        Vector result;
        for (unsigned i = 0; i < N; i++) {
            result.get(i) = get(i) * rhs;
        }
        return result;
    }
    constexpr Vector operator/(const FixedPointType& rhs) const {
        Vector result;
        for (unsigned i = 0; i < N; i++) {
            result.get(i) = get(i) / rhs;
        }
        return result;
    }
    template <std::integral U>
    constexpr Vector operator*(U rhs) const {
        Vector result;
        for (unsigned i = 0; i < N; i++) {
            result.get(i) = get(i) * rhs;
        }
        return result;
    }
    template <std::integral U>
    constexpr Vector operator/(U rhs) const {
        Vector result;
        for (unsigned i = 0; i < N; i++) {
            result.get(i) = get(i) / rhs;
        }
        return result;
    }
    static constexpr Vector ZERO()
        requires(N <= 3)
    {
        Vector result;
        for (unsigned i = 0; i < N; i++) {
            result.get(i) = FixedPointType(0.0);
        }
        return result;
    }
    static constexpr Vector ONE()
        requires(N <= 3)
    {
        Vector result;
        for (unsigned i = 0; i < N; i++) {
            result.get(i) = FixedPointType(1.0);
        }
        return result;
    }
    static constexpr Vector UP()
        requires(N <= 3)
    {
        Vector result;
        for (unsigned i = 0; i < N; i++) {
            result.get(i) = (i == 1) ? FixedPointType(1.0) : FixedPointType(0.0);
        }
        return result;
    }
    static constexpr Vector DOWN()
        requires(N <= 3)
    {
        Vector result;
        for (unsigned i = 0; i < N; i++) {
            result.get(i) = (i == 1) ? -FixedPointType(1.0) : FixedPointType(0.0);
        }
        return result;
    }
    static constexpr Vector LEFT()
        requires(N <= 3)
    {
        Vector result;
        for (unsigned i = 0; i < N; i++) {
            result.get(i) = (i == 0) ? -FixedPointType(1.0) : FixedPointType(0.0);
        }
        return result;
    }
    static constexpr Vector RIGHT()
        requires(N <= 3)
    {
        Vector result;
        for (unsigned i = 0; i < N; i++) {
            result.get(i) = (i == 0) ? FixedPointType(1.0) : FixedPointType(0.0);
        }
        return result;
    }
    static constexpr Vector FORWARD()
        requires(N == 3)
    {
        Vector result;
        for (unsigned i = 0; i < N; i++) {
            result.get(i) = (i == 2) ? FixedPointType(1.0) : FixedPointType(0.0);
        }
        return result;
    }
    static constexpr Vector BACKWARD()
        requires(N == 3)
    {
        Vector result;
        for (unsigned i = 0; i < N; i++) {
            result.get(i) = (i == 2) ? -FixedPointType(1.0) : FixedPointType(0.0);
        }
        return result;
    }
};

typedef Vector<2> Vec2;
typedef Vector<3> Vec3;
typedef Vector<4> Vec4;

static_assert(sizeof(Vec2) == 8);
static_assert(sizeof(Vec3) == 12);
static_assert(sizeof(Vec4) == 16);

}  // namespace psyqo
