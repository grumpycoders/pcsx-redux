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
#include "support/slice.h"
#include "typestring.hh"

namespace PCSX {

namespace BinStruct {

template <typename wireType, std::endian endianess>
struct BasicFieldType {
    typedef wireType type;
    static void deserialize(IO<File> file, Slice &slice) {
        type val = file->read<type, endianess>();
        Slice addend;
        addend.borrow(&val, sizeof(val));
        slice += addend;
    }
    static void serialize(IO<File> file, const Slice &slice, size_t offset) {
        const uint8_t *buffer = slice.data<uint8_t>();
        file->write<type, endianess>(*reinterpret_cast<const type *>(buffer + offset));
    }
    static type get(const Slice &slice, size_t offset) {
        const uint8_t *buffer = slice.data<uint8_t>();
        return *reinterpret_cast<const type *>(buffer + offset);
    }
    static void set(Slice &slice, size_t offset, type val) {
        uint8_t *buffer = slice.data<uint8_t>();
        *reinterpret_cast<type *>(buffer + offset) = val;
    }
    static constexpr size_t size() { return sizeof(type); }
    static constexpr bool fixedSize() { return true; }
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
    typedef std::string_view type;
    static void deserialize(IO<File> file, Slice &slice) {
        uint8_t N = file->byte();
        std::string t(N + 1, '\0');
        t[0] = N;
        file->read(t.data() + 1, N);
        Slice addend(std::move(t));
        slice += addend;
    }
    static void serialize(IO<File> file, const Slice &slice, size_t offset) {
        const uint8_t *buffer = slice.data<uint8_t>();
        uint8_t N = buffer[offset];
        file->write(buffer + offset, N + 1);
    }
    static std::string_view get(const Slice &slice, size_t offset) {
        const uint8_t *buffer = slice.data<uint8_t>() + offset;
        uint8_t N = *buffer++;
        return std::string_view(reinterpret_cast<const char *>(buffer), N);
    }
    static void set(Slice &slice, size_t offset, std::string_view val) {
        auto size = std::min(val.size(), std::string_view::size_type(255));
        slice.resize(offset + size + 1);
        uint8_t *buffer = slice.data<uint8_t>();
        buffer[offset] = val.size();
        memcpy(buffer + offset + 1, val.data(), size);
    }
    static constexpr size_t size() { return 1; }
    static constexpr bool fixedSize() { return false; }
};

template <size_t S>
struct CString {
    static constexpr char const typeName[] = "CString";
    typedef std::string_view type;
    static void deserialize(IO<File> file, Slice &slice) {
        std::string t(S, '\0');
        file->read(t.data(), S);
        Slice addend(std::move(t));
        slice += addend;
    }
    static void serialize(IO<File> file, const Slice &slice, size_t offset) {
        const uint8_t *buffer = slice.data<uint8_t>();
        file->write(buffer + offset, S);
    }
    static std::string_view get(const Slice &slice, size_t offset) {
        const uint8_t *buffer = slice.data<uint8_t>() + offset;
        return std::string_view(reinterpret_cast<const char *>(buffer), S);
    }
    static void set(Slice &slice, size_t offset, std::string_view val) {
        uint8_t *buffer = slice.data<uint8_t>();
        memcpy(buffer + offset, val.data(), std::min(val.size(), S));
        if (val.size() < S) {
            memset(buffer + offset + val.size(), 0, S - val.size());
        }
    }
    static constexpr size_t size() { return S; }
    static constexpr bool fixedSize() { return true; }
};

template <typename FieldType, typename name>
struct Field;
template <typename FieldType, char... C>
struct Field<FieldType, irqus::typestring<C...>> : public FieldType {
    using type = typename FieldType::type;
    Field() {}
    typedef irqus::typestring<C...> fieldName;
};

template <typename StructType, typename name>
struct StructField;
template <typename StructType, char... C>
struct StructField<StructType, irqus::typestring<C...>> : public StructType {
    using type = typename StructType::type;
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
    static constexpr bool isStruct = true;
    using type = myself;
    Struct() { verifyIntegrity(); }
    Struct(const Slice &slice) : m_data(slice) { verifyIntegrity(); }
    Struct(Slice &&slice) : m_data(slice) { verifyIntegrity(); }
    using name = irqus::typestring<C...>;
    static constexpr char const typeName[sizeof...(C) + 1] = {C..., '\0'};
    const Slice &getSlice() const { return m_data; }
    Slice &&moveSlice() { return std::move(m_data); }
    void deserialize(IO<File> file) {
        m_data = std::string();
        deserialize<0, fields...>(file);
    }
    template <class T>
    typename T::type get() const {
        static_assert(hasFieldType<T>());
        size_t offset = offsetOf<T>();
        if (m_data.size() <= offset) throw std::runtime_error("Internal slice not big enough");
        return T::get(m_data, offset);
    }
    static constexpr bool fixedSize() { return fixedSize<0, fields...>(); }
    static constexpr size_t size() { return size<0, fields...>(); }

  private:
    template <size_t index>
    static constexpr bool fixedSize() {
        return true;
    }
    template <size_t index, typename FieldType, typename... nestedFields>
    static constexpr bool fixedSize() {
        return FieldType::fixedSize() && fixedSize<index + 1, nestedFields...>();
    }
    template <size_t index>
    static constexpr size_t size() {
        return 0;
    }
    template <size_t index, typename FieldType, typename... nestedFields>
    static constexpr size_t size() {
        return FieldType::size() + size<index + 1, nestedFields...>();
    }
    template <size_t index>
    void deserialize(IO<File> file) {}
    template <size_t index, typename FieldType, typename... nestedFields>
    void deserialize(IO<File> file) {
        FieldType::deserialize(file, m_data);
        deserialize<index + 1, nestedFields...>(file);
    }
    template <size_t index>
    static constexpr size_t countVariableFields() {
        return 0;
    }
    template <size_t index, typename FieldType, typename... nestedFields>
    static constexpr size_t countVariableFields() {
        return (FieldType::fixedSize() ? 0 : 1) + countVariableFields<index + 1, nestedFields...>();
    }
    template <size_t index>
    static constexpr size_t locateVariableField() {
        return index;
    }
    template <size_t index, typename FieldType, typename... nestedFields>
    static constexpr size_t locateVariableField() {
        return FieldType::fixedSize() ? locateVariableField<index + 1, nestedFields...>() : index;
    }
    static constexpr void verifyIntegrity() {
        static_assert(countVariableFields<0, fields...>() <= 1);
        static_assert(locateVariableField<0, fields...>() >= (sizeof...(fields) - 1));
    }
    template <typename FieldTypeTest>
    static constexpr bool hasFieldType() {
        return std::disjunction<std::is_same<FieldTypeTest, fields>...>::value;
    }
    template <size_t index>
    static constexpr size_t offsetOf(size_t target) {
        return 0;
    }
    template <size_t index, typename FieldType, typename... nestedFields>
    static constexpr size_t offsetOf(size_t target) {
        size_t ret = FieldType::size();
        if (index != target) ret += offsetOf<index + 1, nestedFields...>(target);
        return ret;
    }
    template <typename T, size_t index>
    static constexpr size_t offsetOf() {
        return 0;
    }
    template <typename T, size_t index, typename FieldType, typename... nestedFields>
    static constexpr size_t offsetOf() {
        if constexpr (std::is_same<T, FieldType>::value) {
            if constexpr (index == 0) {
                return 0;
            } else {
                return offsetOf<0, fields...>(index - 1);
            }
        } else {
            return offsetOf<T, index + 1, nestedFields...>();
        }
    }
    template <typename T>
    static constexpr size_t offsetOf() {
        return offsetOf<T, 0, fields...>();
    }
    Slice m_data;
};

}  // namespace BinStruct

}  // namespace PCSX
