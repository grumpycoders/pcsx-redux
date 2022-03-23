/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include <stdint.h>

#include <bit>
#include <string>
#include <tuple>

#include "support/file.h"
#include "support/slice.h"
#include "typestring.hh"

namespace PCSX {

namespace BinStruct {

template <typename wireType>
struct LEBasicFieldType {
    typedef wireType type;
    static void deserialize(IO<File> *file, Slice &slice) {
        type val = file->read<type>();
        Slice addend;
        addend.borrow(&val, sizeof(val));
        slice += addend;
    }
    static void serialize(IO<File> *file, const Slice &slice, size_t offset) {
        const uint8_t *buffer = slice.data();
        file->write<type>(*reinterpret_cast<const type *>(buffer + offset));
    }
    static type get(const Slice &slice, size_t offset) {
        const uint8_t *buffer = slice.data();
        return *reinterpret_cast<const type *>(buffer + offset);
    }
    static constexpr bool fixedSize() { return true; }
};

struct Int8 : public LEBasicFieldType<int8_t> {
    static constexpr char const typeName[] = "int8_t";
};

struct Int16 : public LEBasicFieldType<int16_t> {
    static constexpr char const typeName[] = "int16_t";
};

struct Int32 : public LEBasicFieldType<int32_t> {
    static constexpr char const typeName[] = "int32_t";
};

struct Int64 : public LEBasicFieldType<int64_t> {
    static constexpr char const typeName[] = "int64_t";
};

struct UInt8 : public LEBasicFieldType<uint8_t> {
    static constexpr char const typeName[] = "uint8_t";
};

struct UInt16 : public LEBasicFieldType<uint16_t> {
    static constexpr char const typeName[] = "uint16_t";
};

struct UInt32 : public LEBasicFieldType<uint32_t> {
    static constexpr char const typeName[] = "uint32_t";
};

struct UInt64 : public LEBasicFieldType<uint64_t> {
    static constexpr char const typeName[] = "uint64_t";
};

template <typename name, typename... fields>
class Struct;
template <char... C, typename... fields>
class Struct<irqus::typestring<C...>, fields...> : private std::tuple<fields...> {
    using myself = Message<irqus::typestring<C...>, fields...>;
    using base = std::tuple<fields...>;

  public:
    static constexpr bool isStruct = true;
    using type = myself;
    Struct() {}
    Struct(const Slice &slice) : m_data(slice) {}
    Struct(Slice &&slice) : m_data(slice) {}
    using name = irqus::typestring<C...>;
    static constexpr char const typeName[sizeof...(C) + 1] = {C..., '\0'};
    const Slice &getSlice() const { return m_data; }
    Slice &&moveSlice() { return std::move(m_data); }

  private:
    Slice m_data;
};

}  // namespace BinStruct

}  // namespace PCSX
