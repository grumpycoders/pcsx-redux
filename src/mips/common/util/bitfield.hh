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

#include <stdint.h>

#include <concepts>
#include <type_traits>

#include "util.h"

namespace Utilities {

namespace BitFieldInternal {

template <typename T>
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

}  // namespace BitFieldInternal

template <std::integral T, unsigned width = BitFieldInternal::DefaultBitSize<T>::size>
struct BitSpan {
    static constexpr unsigned Width = width;
    using Underlying = T;
};

template <typename... T>
struct BitField {
    template <typename One>
    constexpr typename One::Underlying get() {
        if constexpr (std::is_signed_v<typename One::Underlying>) {
            return get<BitFieldInternal::ComputeOffset<One, T...>::offset(), One::Width, signed>();
        } else if constexpr (std::is_unsigned_v<typename One::Underlying>) {
            return get<BitFieldInternal::ComputeOffset<One, T...>::offset(), One::Width, unsigned>();
        }
        return 0;
    }
    template <typename One>
    constexpr void set(typename One::Underlying v) {
        if constexpr (std::is_signed_v<typename One::Underlying>) {
            set<BitFieldInternal::ComputeOffset<One, T...>::offset(), One::Width, signed>(v);
        } else if constexpr (std::is_unsigned_v<typename One::Underlying>) {
            set<BitFieldInternal::ComputeOffset<One, T...>::offset(), One::Width, unsigned>(v);
        }
    }

  private:
    template <unsigned offset, unsigned width, std::integral U>
    constexpr U get() {
        constexpr unsigned firstByteOffset = offset / 8;
        constexpr unsigned lastByteOffset = (offset + width - 1) / 8;
        constexpr unsigned shift = offset % 8;
        constexpr uint32_t mask = (1 << width) - 1;
        if constexpr ((firstByteOffset % 4) == 0) {
            return reinterpret_cast<const U*>(storage)[firstByteOffset / 4] >> shift & mask;
        } else if constexpr ((firstByteOffset % 4) != 0) {
            return (loadUnaligned<U>(storage + firstByteOffset, lastByteOffset - firstByteOffset + 1) >> shift) & mask;
        }
        return 0;
    }
    template <unsigned offset, unsigned width, std::integral U>
    constexpr void set(U v) {
        constexpr unsigned firstByteOffset = offset / 8;
        constexpr unsigned lastByteOffset = (offset + width - 1) / 8;
        constexpr unsigned shift = offset % 8;
        constexpr uint32_t mask = (1 << width) - 1;
        if constexpr ((firstByteOffset % 4) == 0) {
            U* ptr = reinterpret_cast<U*>(storage);
            ptr[firstByteOffset / 4] &= ~(mask << shift);
            ptr[firstByteOffset / 4] |= (v & mask) << shift;
        } else if constexpr ((firstByteOffset % 4) != 0) {
            U span = loadUnaligned<U>(storage + firstByteOffset, lastByteOffset - firstByteOffset + 1);
            span &= ~(mask << shift);
            span |= (v & mask) << shift;
            storeUnaligned<U>(storage + firstByteOffset, span, lastByteOffset - firstByteOffset + 1);
        }
    }
    uint8_t storage[BitFieldInternal::ComputeStorage<T...>::size()];
};

}  // namespace Utilities
