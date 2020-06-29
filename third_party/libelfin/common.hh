// Copyright (c) 2013 Austin T. Clements. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

#ifndef _ELFPP_COMMON_HH_
#define _ELFPP_COMMON_HH_

#define ELFPP_BEGIN_NAMESPACE namespace elf {
#define ELFPP_END_NAMESPACE }
#define ELFPP_BEGIN_INTERNAL namespace internal {
#define ELFPP_END_INTERNAL }

#include <cstdint>

ELFPP_BEGIN_NAMESPACE

/**
 * A byte ordering.
 */
enum class byte_order { native, lsb, msb };

/**
 * Return either byte_order::lsb or byte_order::msb.  If the argument
 * is byte_order::native, it will be resolved to whatever the native
 * byte order is.
 */
static inline byte_order resolve_order(byte_order o) {
    static const union {
        int i;
        char c[sizeof(int)];
    } test = {1};

    if (o == byte_order::native) return test.c[0] == 1 ? byte_order::lsb : byte_order::msb;
    return o;
}

template <typename T>
T byteswap(T v) {
    static_assert(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8, "cannot byteswap type");
    switch (sizeof(T)) {
        case 1:
            return v;
        case 2: {
            std::uint16_t x = (std::uint16_t)v;
            return (T)(((x & 0xFF) << 8) | (x >> 8));
        }
        case 4: {
            std::uint32_t x = (std::uint32_t)v;
            return (T)((((uint32_t)byteswap((uint16_t)(x & 0xffff))) << 16) | (((uint32_t)byteswap((uint16_t)(x >> 16)))));
        }
        case 8: {
            std::uint64_t x = (std::uint64_t)v;
            return (T)((((uint64_t)byteswap((uint32_t)(x & 0xffffffff))) << 32) | (((uint64_t)byteswap((uint32_t)(x >> 32)))));
        }
    }
}

/**
 * Return v converted from one byte order to another.
 */
template <typename T>
T swizzle(T v, byte_order from, byte_order to) {
    static_assert(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8, "cannot swizzle type");

    from = resolve_order(from);
    to = resolve_order(to);

    if (from == to) return v;
    return byteswap(v);
}

ELFPP_BEGIN_INTERNAL

/**
 * OrderPick selects between Native, LSB, and MSB based on ord.
 */
template <byte_order ord, typename Native, typename LSB, typename MSB>
struct OrderPick;

template <typename Native, typename LSB, typename MSB>
struct OrderPick<byte_order::native, Native, LSB, MSB> {
    typedef Native T;
};

template <typename Native, typename LSB, typename MSB>
struct OrderPick<byte_order::lsb, Native, LSB, MSB> {
    typedef LSB T;
};

template <typename Native, typename LSB, typename MSB>
struct OrderPick<byte_order::msb, Native, LSB, MSB> {
    typedef MSB T;
};

ELFPP_END_INTERNAL

ELFPP_END_NAMESPACE

#endif
