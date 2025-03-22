/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

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

#include <bit>
#include <stdexcept>
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

struct BEInt16 : public BasicFieldType<int16_t, std::endian::big> {
    static constexpr char const typeName[] = "int16_t";
};

struct BEInt32 : public BasicFieldType<int32_t, std::endian::big> {
    static constexpr char const typeName[] = "int32_t";
};

struct BEInt64 : public BasicFieldType<int64_t, std::endian::big> {
    static constexpr char const typeName[] = "int64_t";
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
    CString &operator=(const type &v) {
        memcpy(value, v.data(), S);
        return *this;
    }
    void set(const type &v, char padding = 0) {
        value[S] = 0;
        auto toCopy = std::min(S, v.size());
        memcpy(value, v.data(), toCopy);
        if (toCopy < S) {
            memset(value + toCopy, padding, S - toCopy);
        }
    }
    void serialize(IO<File> f) const { f->write(value, S); }
    void deserialize(IO<File> f) {
        value[S] = 0;
        f->read(value, S);
    }
    void reset() { memset(value, 0, S + 1); }
    char value[S + 1];
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

template <typename FieldType, typename name, size_t N>
struct RepeatedField;
template <typename FieldType, char... C, size_t N>
struct RepeatedField<FieldType, irqus::typestring<C...>, N> {
    RepeatedField() {}
    typedef irqus::typestring<C...> fieldName;
    FieldType value[N];
    FieldType &operator[](size_t i) {
        if (i >= N) throw std::out_of_range("Index out of range");
        return value[i];
    }
    const FieldType &operator[](size_t i) const {
        if (i >= N) throw std::out_of_range("Index out of range");
        return value[i];
    }
    void serialize(IO<File> f) const {
        for (size_t i = 0; i < N; i++) {
            value[i].serialize(f);
        }
    }
    void deserialize(IO<File> f) {
        for (size_t i = 0; i < N; i++) {
            value[i].deserialize(f);
        }
    }
    void reset() {
        for (size_t i = 0; i < N; i++) {
            value[i].reset();
        }
    }
};

template <typename FieldType, typename name, size_t N>
struct RepeatedStruct;
template <typename FieldType, char... C, size_t N>
struct RepeatedStruct<FieldType, irqus::typestring<C...>, N> {
    RepeatedStruct() {}
    typedef irqus::typestring<C...> fieldName;
    FieldType value[N];
    FieldType &operator[](size_t i) {
        if (i >= N) throw std::out_of_range("Index out of range");
        return value[i];
    }
    const FieldType &operator[](size_t i) const {
        if (i >= N) throw std::out_of_range("Index out of range");
        return value[i];
    }
    void serialize(IO<File> f) const {
        for (size_t i = 0; i < N; i++) {
            value[i].serialize(f);
        }
    }
    void deserialize(IO<File> f) {
        for (size_t i = 0; i < N; i++) {
            value[i].deserialize(f);
        }
    }
    void reset() {
        for (size_t i = 0; i < N; i++) {
            value[i].reset();
        }
    }
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
        FieldType &field = std::get<index>(*this);
        field.reset();
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
