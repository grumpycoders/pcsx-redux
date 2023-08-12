/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#pragma once

#include <bit>
#include <concepts>
#include <version>

namespace PCSX {

namespace PolyFill {

// MacOS / AppleClang is bad.
template <class T>
concept IntegralConcept = std::is_integral<T>::value;

template <IntegralConcept T>
static constexpr T byteSwap(T val) {
#if defined(__cpp_lib_byteswap) && (__cpp_lib_byteswap >= 202110L)
    return std::byteswap<T>(val);
#else
    if constexpr (sizeof(T) == 1) {
        return val;
    } else {
        T ret = 0;
        for (size_t i = 0; i < sizeof(T); i++) {
            ret |= static_cast<T>(static_cast<uint8_t>(val >> (i * 8)) << ((sizeof(T) - i - 1) * 8));
        }
        return ret;
    }
#endif
}

}

}
