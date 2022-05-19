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
#include <type_traits>

#include "support/file.h"
#include "typestring.hh"

namespace PCSX {

namespace BinStruct {

template <typename wireType, std::endian endianess>
struct BasicFieldType {
    typedef wireType type;

  private:
    using myself = BasicFieldType<type, endianess>;

  public:
    operator type() const { return value; }
    myself &operator=(const type &v) {
        value = v;
        return *this;
    }
    void serialize(IO<File> f) const { f->write<type, endianess>(value); }
    void deserialize(IO<File> f) { value = f->read<type, endianess>(); }
    void reset() { value = type(); }
    type value;
};

struct Int8 : public BasicFieldType<int8_t, std::endian::little> {
    static constexpr char const typeName[] = "int8_t";
};

struct Int16 : public BasicFieldType<int16_t, std::endian::little> {
    static constexpr char const typeName[] = "int16_t";
};

struct Int32 : public BasicFieldType<int32_t, std::endian::little> {
    static constexpr char const typeName[] = "int32_t";
};

struct Int64 : public BasicFieldType<int64_t, std::endian::little> {
    static constexpr char const typeName[] = "int64_t";
};

struct UInt8 : public BasicFieldType<uint8_t, std::endian::little> {
    static constexpr char const typeName[] = "uint8_t";
};

struct UInt16 : public BasicFieldType<uint16_t, std::endian::little> {
    static constexpr char const typeName[] = "uint16_t";
};

struct UInt32 : public BasicFieldType<uint32_t, std::endian::little> {
    static constexpr char const typeName[] = "uint32_t";
};

struct UInt64 : public BasicFieldType<uint64_t, std::endian::little> {
    static constexpr char const typeName[] = "uint64_t";
};

struct BEInt8 : public BasicFieldType<int8_t, std::endian::big> {
    static constexpr char const typeName[] = "int8_t";
};

struct BEInt16 : public BasicFieldType<int16_t, std::endian::big> {
    static constexpr char const typeName[] = "int16_t";
};

struct BEInt32 : public BasicFieldType<int32_t, std::endian::big> {
    static constexpr char const typeName[] = "int32_t";
};

struct BEInt64 : public BasicFieldType<int64_t, std::endian::big> {
    static constexpr char const typeName[] = "int64_t";
};

struct BEUInt8 : public BasicFieldType<uint8_t, std::endian::big> {
    static constexpr char const typeName[] = "uint8_t";
};

struct BEUInt16 : public BasicFieldType<uint16_t, std::endian::big> {
    static constexpr char const typeName[] = "uint16_t";
};

struct BEUInt32 : public BasicFieldType<uint32_t, std::endian::big> {
    static constexpr char const typeName[] = "uint32_t";
};

struct BEUInt64 : public BasicFieldType<uint64_t, std::endian::big> {
    static constexpr char const typeName[] = "uint64_t";
};

struct NString {
    static constexpr char const typeName[] = "NString";
    operator std::string_view() const { return value; }
    NString &operator=(const std::string_view &v) {
        value = v;
        return *this;
    }
    NString &operator=(const std::string &v) {
        value = v;
        return *this;
    }
    NString &operator=(std::string &&v) {
        value = std::move(v);
        return *this;
    }
    void serialize(IO<File> f) const {
        f->write<uint8_t>(value.size());
        f->write(value.data(), value.size());
    }
    void deserialize(IO<File> f) {
        auto N = f->read<uint8_t>();
        value.resize(N);
        f->read(value.data(), N);
    }
    void reset() { value.clear(); }
    std::string value;
};

template <size_t S>
struct CString {
    static constexpr char const typeName[] = "CString";
    typedef std::string_view type;
    operator type() const { return {value, S}; }
    CString<S> operator=(const type &v) {
        memcpy(value, v.data(), S);
        return *this;
    }
    void set(const type &v) { memcpy(value, v.data(), S); }
    void serialize(IO<File> f) const { f->write(value, S); }
    void deserialize(IO<File> f) { f->read(value, S); }
    void reset() { memset(value, 0, S); }
    char value[S];
};

template <typename FieldType, typename name>
struct Field;
template <typename FieldType, char... C>
struct Field<FieldType, irqus::typestring<C...>> : public FieldType {
    Field() {}
    typedef irqus::typestring<C...> fieldName;
};

template <typename StructType, typename name>
struct StructField;
template <typename StructType, char... C>
struct StructField<StructType, irqus::typestring<C...>> : public StructType {
    StructField() {}
    typedef irqus::typestring<C...> fieldName;
};

template <typename name, typename... fields>
class Struct;
template <char... C, typename... fields>
class Struct<irqus::typestring<C...>, fields...> : private std::tuple<fields...> {
    using myself = Struct<irqus::typestring<C...>, fields...>;
    using base = std::tuple<fields...>;

  public:
    template <typename field>
    constexpr const field &get() const {
        return std::get<field>(*this);
    }
    template <typename field>
    constexpr field &get() {
        return std::get<field>(*this);
    }
    constexpr void reset() { reset<0, fields...>(); }
    void serialize(IO<File> f) const { serialize<0, fields...>(f); }
    void deserialize(IO<File> f) { deserialize<0, fields...>(f); }

  private:
    template <size_t index>
    constexpr void reset() {}
    template <size_t index, typename FieldType, typename... nestedFields>
    constexpr void reset() {
        FieldType &setting = std::get<index>(*this);
        setting.reset();
        reset<index + 1, nestedFields...>();
    }
    template <size_t index>
    void serialize(IO<File> f) const {}
    template <size_t index, typename FieldType, typename... nestedFields>
    void serialize(IO<File> f) const {
        std::get<index>(*this).serialize(f);
        serialize<index + 1, nestedFields...>(f);
    }
    template <size_t index>
    void deserialize(IO<File> f) {}
    template <size_t index, typename FieldType, typename... nestedFields>
    void deserialize(IO<File> f) {
        std::get<index>(*this).deserialize(f);
        deserialize<index + 1, nestedFields...>(f);
    }
};

}  // namespace BinStruct

}  // namespace PCSX
