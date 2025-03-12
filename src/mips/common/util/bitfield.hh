/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

#include <concepts>
#include <type_traits>

#include "util.h"

namespace Utilities {

namespace BitFieldInternal {

template <typename T>
concept IntegralLike = std::is_integral_v<T> || std::is_enum_v<T>;

template <IntegralLike T>
struct DefaultBitSize {
    static constexpr unsigned size = sizeof(T) * 8;
};

template <>
struct DefaultBitSize<bool> {
    static constexpr unsigned size = 1;
};

template <typename... T>
struct ComputeStorage {
    static constexpr unsigned size() { return (sizeInBits() + 7) / 8; }

  private:
    static constexpr unsigned sizeInBits() { return recSize<0, T...>(); }
    template <unsigned index>
    static constexpr unsigned recSize() {
        return 0;
    }
    template <unsigned index, typename One, typename... Rest>
    static constexpr unsigned recSize() {
        return One::Width + recSize<index + 1, Rest...>();
    }
};

template <typename Target, typename... T>
struct ComputeOffset {
    static constexpr unsigned offset() { return recOffset<0, T...>(); }

  private:
    template <unsigned index>
    static constexpr unsigned recOffset() {
        return 0;
    }
    template <unsigned index, typename One, typename... Rest>
    static constexpr unsigned recOffset() {
        if constexpr (std::is_same_v<Target, One>) {
            return 0;
        } else {
            return recOffset<index + 1, Rest...>() + One::Width;
        }
    }
};

template <std::integral T, std::integral U = T>
using SignedType = typename std::conditional_t<std::is_signed_v<T>, std::make_signed_t<U>, std::make_unsigned_t<U>>;

template <unsigned span>
using StorageType = typename std::conditional_t<
    span <= 8, uint8_t,
    typename std::conditional_t<span <= 16, uint16_t, typename std::conditional_t<span <= 32, uint32_t, void>>>;

template <unsigned span, std::integral T>
using SignedStorageType = SignedType<T, StorageType<span>>;

template <unsigned Offset, unsigned Width, unsigned storageSize, std::integral T>
struct BitFieldHelper {
    static constexpr unsigned offset = Offset;
    static constexpr unsigned width = Width;
    static constexpr unsigned firstByteOffset = offset / 8;
    static constexpr unsigned lastByteOffset = (offset + width - 1) / 8;
    static constexpr unsigned bytesCount = lastByteOffset - firstByteOffset + 1;
    static constexpr unsigned shift = offset % 8;
    static constexpr uint32_t mask = (1 << width) - 1;
    static constexpr bool isAlignedAndSafe =
        ((firstByteOffset % sizeof(T)) == 0) && (firstByteOffset + sizeof(T)) <= storageSize;
    static constexpr bool fullBytes = ((width % 8) == 0) && ((offset % 8) == 0);
    BitFieldHelper() {
        static_assert(bytesCount <= 4, "Type too large");
        static_assert(width > 0, "Width must be greater than 0");
        static_assert(width <= 32, "Width must be less than or equal to 32");
        static_assert(offset + width <= storageSize * 8, "Offset + Width must be less than or equal to storage size");
    }
};

enum Dummy : int;

}  // namespace BitFieldInternal

/**
 * @brief A bit field element to be used in a BitField.
 *
 * @tparam T The type of the field. This can be any integral type or enum type.
 * @tparam width The width of the field in bits.
 */
template <BitFieldInternal::IntegralLike T, unsigned width = BitFieldInternal::DefaultBitSize<T>::size>
struct BitSpan {
    static constexpr unsigned Width = width;
    using Type = T;
    using Underlying =
        std::conditional_t<std::is_enum_v<T>,
                           std::underlying_type_t<std::conditional_t<std::is_enum_v<T>, T, BitFieldInternal::Dummy>>,
                           T>;
};

/**
 * @brief A bit field that can hold multiple bit field elements of different types.
 *
 * @details This class is used to hold multiple bit field elements of different types. The
 * elements are stored in a single byte array, and the offsets of each element are computed
 * at compile time. The elements can be accessed using the get() and set() methods.
 * The get() method returns the value of the element, and the set() method sets the value
 * of the element. The bit field elements are stored in the order they are defined in the template
 * parameter pack. The order of the elements is important, as the offsets are computed based on the order
 * of the elements. The maximum size of a single element is technically 32 bits, but this
 * actually varies depending on the alignment of the element. One element can only span a maximum
 * of 4 bytes. There is no limit on the number of elements that can be stored in the bit field.
 *
 * @tparam... T The types of the bit field elements. These need to be BitSpan types.
 */
template <typename... T>
struct BitField {
    template <typename Field>
    constexpr Field::Type get() const {
        constexpr unsigned offset = BitFieldInternal::ComputeOffset<Field, T...>::offset();
        auto ret = get<offset, Field::Width,
                       BitFieldInternal::SignedStorageType<(offset % 8) + Field::Width, typename Field::Underlying>>();
        return static_cast<Field::Type>(ret);
    }
    template <typename Field>
    constexpr void set(Field::Type v_) {
        constexpr unsigned offset = BitFieldInternal::ComputeOffset<Field, T...>::offset();
        auto v = static_cast<Field::Underlying>(v_);
        set<offset, Field::Width,
            BitFieldInternal::SignedStorageType<(offset % 8) + Field::Width, typename Field::Underlying>>(v);
    }
    void clear() {
        for (unsigned i = 0; i < sizeof(storage); i++) {
            storage[i] = 0;
        }
    }

  private:
    template <unsigned offset, unsigned width, std::integral U>
    constexpr U get() const {
        using helper = BitFieldInternal::BitFieldHelper<offset, width, sizeof(storage), U>;
        if constexpr (helper::isAlignedAndSafe) {
            return reinterpret_cast<const U*>(storage)[helper::firstByteOffset / sizeof(U)] >> helper::shift &
                   helper::mask;
        } else {
            return (loadUnaligned<U, helper::bytesCount>(storage + helper::firstByteOffset) >> helper::shift) &
                   helper::mask;
        }
        return 0;
    }
    template <unsigned offset, unsigned width, std::integral U>
    constexpr void set(U v) {
        using helper = BitFieldInternal::BitFieldHelper<offset, width, sizeof(storage), U>;
        if constexpr (helper::fullBytes) {
            if constexpr (helper::bytesCount == 1) {
                storage[helper::firstByteOffset] = static_cast<uint8_t>(v);
            } else if constexpr (helper::bytesCount == 2) {
                if constexpr (helper::isAlignedAndSafe) {
                    *reinterpret_cast<U*>(storage + helper::firstByteOffset) = v;
                } else {
                    storeUnaligned<U>(storage + helper::firstByteOffset, v);
                }
            } else if constexpr (helper::bytesCount == 3) {
                if constexpr ((helper::firstByteOffset % 2) == 0) {
                    *reinterpret_cast<uint16_t*>(storage + helper::firstByteOffset) = static_cast<uint16_t>(v);
                    storage[helper::firstByteOffset + 2] = static_cast<uint8_t>(v >> 16);
                } else {
                    storage[helper::firstByteOffset] = static_cast<uint8_t>(v);
                    *reinterpret_cast<uint16_t*>(storage + helper::firstByteOffset + 1) = static_cast<uint16_t>(v >> 8);
                }
            } else if constexpr (helper::bytesCount == 4) {
                if constexpr (helper::isAlignedAndSafe) {
                    *reinterpret_cast<U*>(storage + helper::firstByteOffset) = v;
                } else {
                    storeUnaligned<U>(storage + helper::firstByteOffset, v);
                }
            }
        } else if constexpr (helper::isAlignedAndSafe) {
            U* ptr = reinterpret_cast<U*>(storage);
            ptr[helper::firstByteOffset / sizeof(U)] &= ~(helper::mask << helper::shift);
            ptr[helper::firstByteOffset / sizeof(U)] |= (v & helper::mask) << helper::shift;
        } else {
            U span = loadUnaligned<U, helper::bytesCount>(storage + helper::firstByteOffset);
            span &= ~(helper::mask << helper::shift);
            span |= (v & helper::mask) << helper::shift;
            storeUnaligned<U, helper::bytesCount>(storage + helper::firstByteOffset, span);
        }
    }
    uint8_t storage[BitFieldInternal::ComputeStorage<T...>::size()] = {0};
};

}  // namespace Utilities
