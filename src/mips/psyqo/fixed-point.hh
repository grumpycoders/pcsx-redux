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

#include <EASTL/functional.h>
#include <stdint.h>

#include <compare>
#include <concepts>
#include <type_traits>

namespace psyqo {

namespace FixedPointInternals {

uint32_t iDiv(uint64_t rem, uint32_t base, unsigned precisionBits);
int32_t dDiv(int32_t a, int32_t b, unsigned precisionBits);
void printInt(uint32_t value, const eastl::function<void(char)>&, unsigned precisionBits);

}  // namespace FixedPointInternals

/**
 * @brief Fixed point number type.
 *
 * @details This is a fixed point number type with a configurable number
 * of fractional bits. The default is 12 fractional bits, which is
 * suitable for representing 3D coordinates in the PSX's 20.12 fixed
 * point format. The number of fractional bits can be changed by
 * specifying a different value for the template parameter
 * `precisionBits`. The underlying integer type can also be changed
 * by specifying a different type for the template parameter `T`.
 * The default is `int32_t`, but `int16_t`, `uint32_t`, `uint16_t`
 * are also supported. The template behaves as a value type, and
 * supports most of the usual arithmetic operators. Its size is the
 * same as the underlying integer type.
 *
 * @tparam precisionBits The number of fractional bits to use.
 * @tparam T The underlying integer type to use.
 */
template <unsigned precisionBits = 12, std::integral T = int32_t>
class FixedPoint {
    using signedUpType = std::conditional<sizeof(T) == 4, int64_t, int32_t>::type;
    using unsignedUpType = std::conditional<sizeof(T) == 4, uint64_t, uint32_t>::type;
    using upType = std::conditional<std::is_signed<T>::value, signedUpType, unsignedUpType>::type;

  public:
    /**
     * @brief The raw value of the fixed point number.
     *
     * @details This is the raw value of the fixed point number, and
     * can be used to access the underlying integer type directly, which
     * can be useful for some operations.
     */
    T value;
    T raw() const { return value; }

    /**
     * @brief The scale of the fixed point number.
     *
     */
    static constexpr unsigned scale = 1 << precisionBits;

    /**
     * @brief Constructs a fixed point number from an integer and a
     * fraction.
     */
    explicit constexpr FixedPoint(T integer, T fraction) : value(integer * scale + fraction) {
        static_assert(sizeof(T) == 4 || sizeof(T) == 2);
        static_assert(precisionBits > 0);
    }

    /**
     * @brief Constructs a fixed point number from a floating point
     * number.
     *
     * @details Note that this is a `consteval` function, so it can
     * only be used with compile-time constants. This is intentional,
     * as the conversion from floating point to fixed point is
     * basically impossible to do at runtime without using floating
     * point arithmetic, which is not available on the PSX.
     */
    consteval FixedPoint(long double ld) {
        static_assert(std::is_signed<T>::value || (ld >= 0));
        bool negative = ld < 0;
        T integer = negative ? -ld : ld;
        T fraction = ld * scale - integer * scale + (negative ? -0.5 : 0.5);
        value = integer * scale + fraction;
    }

    constexpr FixedPoint() : value(0) {}
    constexpr FixedPoint(const FixedPoint&) = default;
    constexpr FixedPoint(FixedPoint&&) = default;
    constexpr FixedPoint& operator=(const FixedPoint&) = default;

    enum Raw { RAW };
    constexpr FixedPoint(T raw, Raw) : value(raw) {}

    /**
     * @brief Construct a new Fixed Point number from a different
     * fixed point number.
     */
    template <unsigned otherPrecisionBits = 12, std::integral U = int32_t>
    explicit FixedPoint(FixedPoint<otherPrecisionBits, U> other) {
        if constexpr (precisionBits == otherPrecisionBits) {
            value = T(other.value);
        } else if constexpr (precisionBits > otherPrecisionBits) {
            value = T(other.value << (precisionBits - otherPrecisionBits));
        } else if constexpr (precisionBits < otherPrecisionBits) {
            value = T(other.value >> (otherPrecisionBits - precisionBits));
        }
    }

    /**
     * @brief Returns the integer part of the fixed point number.
     *
     * @details This returns the integer part of the fixed point,
     * rounded to the nearest integer. Note that this is not the same
     * as truncating the fixed point number, as it rounds to the
     * nearest integer, rather than towards zero.
     *
     * @tparam factor The factor to scale the integer part by. This
     * defaults to 1, which means that the integer part is returned
     * as-is. It can be used to return the integer part scaled by
     * some factor, which can be useful for some operations.
     * The codegen for this will be bad if the factor is not a
     * power of 2.
     * @return constexpr T The integer part of the fixed point number.
     */
    template <size_t factor = 1>
    constexpr T integer() const {
        if constexpr (std::is_signed<T>::value) {
            if (value < 0) {
                return T(value - scale / (2 * factor)) / T(scale / factor);
            }
        }
        return T(value + scale / (2 * factor)) / T(scale / factor);
    }

    template <std::integral U>
    constexpr U integer() const {
        if constexpr (std::is_signed<T>::value) {
            if (value < 0) {
                return U((value - scale / 2) / scale);
            }
        }
        return U((value + scale / 2) / scale);
    }

    /**
     * @brief Prints out the fixed point number.
     *
     * @details This prints out the fixed point number using the provided
     * function for emitting characters out. Note that the formatting is
     * pretty basic for now, and only supports printing out the number in
     * decimal format, with no padding or precision setting. Maximum
     * displayed precision is 5 decimal places.
     *
     * @param charPrinter A function that prints a single character, to
     * be used to print the fixed point number.
     */
    void print(const eastl::function<void(char)>& charPrinter) const {
        T copy = value;
        if constexpr (std::is_signed<T>::value) {
            if (copy < 0) {
                charPrinter('-');
                copy = -copy;
            }
        }
        FixedPointInternals::printInt(copy, charPrinter, precisionBits);
    }

    constexpr FixedPoint abs() const {
        FixedPoint ret = *this;
        if constexpr (std::is_signed<T>::value) {
            if (ret.value < 0) {
                ret.value = -ret.value;
            }
        }
        return ret;
    }

    constexpr FixedPoint operator+(FixedPoint other) const {
        FixedPoint ret = *this;
        ret.value += other.value;
        return ret;
    }

    template <std::integral U>
    constexpr FixedPoint operator+(U other) const {
        FixedPoint ret = *this;
        ret.value += other * scale;
        return ret;
    }

    constexpr FixedPoint operator-(FixedPoint other) const {
        FixedPoint ret = *this;
        ret.value -= other.value;
        return ret;
    }

    template <std::integral U>
    constexpr FixedPoint operator-(U other) const {
        FixedPoint ret = *this;
        ret.value -= other * scale;
        return ret;
    }

    constexpr FixedPoint operator*(FixedPoint other) const {
        upType t = value;
        t *= other.value;
        t /= scale;
        FixedPoint ret;
        ret.value = t;
        return ret;
    }

    template <std::integral U>
    constexpr FixedPoint operator*(U other) const {
        FixedPoint ret = *this;
        ret.value *= other;
        return ret;
    }

    constexpr FixedPoint operator/(FixedPoint other) const {
        FixedPoint ret;
        if constexpr (sizeof(T) == 4) {
            if constexpr (std::is_signed<T>::value) {
                ret.value = FixedPointInternals::dDiv(value, other.value, precisionBits);
            } else if constexpr (!std::is_signed<T>::value) {
                ret.value = FixedPointInternals::iDiv(value, other.value, precisionBits);
            }
        } else if constexpr (sizeof(T) == 2) {
            upType t = value;
            t *= scale;
            t /= other.value;
            ret.value = t;
        }
        return ret;
    }

    template <std::integral U>
    constexpr FixedPoint operator/(U other) const {
        FixedPoint ret = *this;
        ret.value /= other;
        return ret;
    }

    constexpr FixedPoint operator-() const {
        FixedPoint ret = *this;
        ret.value = -ret.value;
        return ret;
    }

    constexpr FixedPoint& operator+=(FixedPoint other) {
        value += other.value;
        return *this;
    }

    template <std::integral U>
    constexpr FixedPoint& operator+=(U other) {
        value += other * scale;
        return *this;
    }

    constexpr FixedPoint& operator-=(FixedPoint other) {
        value -= other.value;
        return *this;
    }

    template <std::integral U>
    constexpr FixedPoint& operator-=(U other) {
        value -= other * scale;
        return *this;
    }

    constexpr FixedPoint& operator*=(FixedPoint other) {
        upType t = value;
        t *= other.value;
        t /= scale;
        value = t;
        return *this;
    }

    template <std::integral U>
    constexpr FixedPoint& operator*=(U other) {
        value *= other;
        return *this;
    }

    constexpr FixedPoint& operator/=(FixedPoint other) {
        if constexpr (sizeof(T) == 4) {
            if constexpr (std::is_signed<T>::value) {
                value = FixedPointInternals::dDiv(value, other.value, precisionBits);
            } else if constexpr (!std::is_signed<T>::value) {
                value = FixedPointInternals::iDiv(value, other.value, precisionBits);
            }
        } else if constexpr (sizeof(T) == 2) {
            upType t = value;
            t *= scale;
            t /= other.value;
            value = t;
        }
        return *this;
    }

    template <std::integral U>
    constexpr FixedPoint& operator/=(U other) {
        value /= other;
        return *this;
    }

    auto operator<=>(const FixedPoint& other) const = default;

    constexpr FixedPoint operator<<(unsigned shift) const {
        FixedPoint ret = *this;
        ret.value <<= shift;
        return ret;
    }

    constexpr FixedPoint operator>>(unsigned shift) const {
        FixedPoint ret = *this;
        ret.value >>= shift;
        return ret;
    }

    constexpr FixedPoint& operator<<=(unsigned shift) {
        value <<= shift;
        return *this;
    }

    constexpr FixedPoint& operator>>=(unsigned shift) {
        value >>= shift;
        return *this;
    }

    constexpr FixedPoint operator++() {
        value += scale;
        return *this;
    }

    constexpr FixedPoint operator++(int) {
        FixedPoint ret = *this;
        value += scale;
        return ret;
    }

    constexpr FixedPoint operator--() {
        value -= scale;
        return *this;
    }

    constexpr FixedPoint operator--(int) {
        FixedPoint ret = *this;
        value -= scale;
        return ret;
    }

    constexpr bool operator!() const { return value == 0; }
};

template <unsigned precisionBits = 12, std::integral T = int32_t, std::integral U = int32_t>
constexpr FixedPoint<precisionBits, T> operator+(U a, FixedPoint<precisionBits, T> b) {
    return b + a;
}

template <unsigned precisionBits = 12, std::integral T = int32_t, std::integral U = int32_t>
constexpr FixedPoint<precisionBits, T> operator-(U a, FixedPoint<precisionBits, T> b) {
    return -b + a;
}

template <unsigned precisionBits = 12, std::integral T = int32_t, std::integral U = int32_t>
constexpr FixedPoint<precisionBits, T> operator*(U a, FixedPoint<precisionBits, T> b) {
    return b * a;
}

template <unsigned precisionBits = 12, std::integral T = int32_t, std::integral U = int32_t>
constexpr FixedPoint<precisionBits, T> operator/(U a, FixedPoint<precisionBits, T> b) {
    FixedPoint<precisionBits, T> ret;
    if constexpr (sizeof(T) == 4) {
        if constexpr (std::is_signed<T>::value || std::is_signed<U>::value) {
            ret.value = FixedPointInternals::dDiv(a * FixedPoint<precisionBits, T>::scale, b.raw(), precisionBits);
        } else if constexpr (!std::is_signed<T>::value && !std::is_signed<U>::value) {
            ret.value = FixedPointInternals::iDiv(a * FixedPoint<precisionBits, T>::scale, b.raw(), precisionBits);
        }
    } else if constexpr (sizeof(T) == 2) {
        ret.value = a * FixedPoint<precisionBits, T>::scale / b.raw();
    }
    return ret;
}

namespace fixed_point_literals {

/**
 * @brief User-defined literal for constructing a 20.12 fixed point number.
 *
 * @param value The value to construct the fixed point number from.
 * @return consteval FixedPoint<> The constructed fixed point number.
 */
consteval FixedPoint<> operator""_fp(long double value) { return value; }

}  // namespace fixed_point_literals

}  // namespace psyqo
