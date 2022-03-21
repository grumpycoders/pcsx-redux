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

#include <string>
#include <tuple>

#include "typestring.hh"

namespace PCSX {

namespace BinStruct {

class OutOfBoundError {};

class InSlice {
  public:
    constexpr uint64_t bytesLeft() { return m_size - m_ptr; }
    InSlice(const uint8_t *data, uint64_t size) : m_data(data), m_size(size) {}
    InSlice getSubSlice(uint64_t size) {
        boundsCheck(size);
        m_ptr += size;
        return InSlice(m_data + m_ptr - size, size);
    }
    constexpr uint8_t getU8() {
        boundsCheck(1);
        return getU8Safe();
    }
    constexpr uint16_t getU16() {
        boundsCheck(2);
        uint16_t ret = static_cast<uint16_t>(getU8Safe());
        ret |= static_cast<uint16_t>(getU8Safe()) << 8;
        return ret;
    }
    constexpr uint32_t getU32() {
        boundsCheck(4);
        uint32_t ret = static_cast<uint32_t>(getU8Safe());
        ret |= static_cast<uint32_t>(getU8Safe()) << 8;
        ret |= static_cast<uint32_t>(getU8Safe()) << 16;
        ret |= static_cast<uint32_t>(getU8Safe()) << 24;
        return ret;
    }
    constexpr uint64_t getU64() {
        boundsCheck(8);
        uint64_t ret = static_cast<uint64_t>(getU8Safe());
        ret |= static_cast<uint64_t>(getU8Safe()) << 8;
        ret |= static_cast<uint64_t>(getU8Safe()) << 16;
        ret |= static_cast<uint64_t>(getU8Safe()) << 24;
        ret |= static_cast<uint64_t>(getU8Safe()) << 32;
        ret |= static_cast<uint64_t>(getU8Safe()) << 40;
        ret |= static_cast<uint64_t>(getU8Safe()) << 48;
        ret |= static_cast<uint64_t>(getU8Safe()) << 56;
        return ret;
    }
    std::string getBytes(uint64_t size) {
        skipBytes(size);
        return std::string(reinterpret_cast<const char *>(m_data + m_ptr - size), size);
    }
    void getBytes(uint8_t *data, uint64_t size) {
        skipBytes(size);
        memcpy(data, m_data + m_ptr - size, size);
    }
    constexpr void skipBytes(uint64_t size) {
        boundsCheck(size);
        m_ptr += size;
    }

  private:
    const uint8_t *m_data;
    const uint64_t m_size;
    uint64_t m_ptr = 0;

    constexpr uint8_t getU8Safe() { return m_data[m_ptr++]; }

    constexpr void boundsCheck(uint64_t size) const {
        if (m_ptr + size > m_size) throw OutOfBoundError();
    }
};

class OutSlice {
  public:
    void putU8(uint8_t value) { m_data += std::string(reinterpret_cast<const char *>(&value), 1); }
    void putU16(uint16_t value) {
        putU8(value & 0xff);
        value >>= 8;
        putU8(value & 0xff);
    }
    void putU32(uint32_t value) {
        putU16(value & 0xffff);
        value >>= 16;
        putU16(value & 0xffff);
    }
    void putU64(uint64_t value) {
        putU32(value & 0xffffffff);
        value >>= 32;
        putU32(value & 0xffffffff);
    }
    void putBytes(const uint8_t *bytes, uint64_t size) {
        m_data += std::string(reinterpret_cast<const char *>(bytes), size);
    }
    void putBytes(const std::string &str) { m_data += str; }
    void putSlice(OutSlice *slice) { m_data += slice->m_data; }
    std::string finalize() { return std::move(m_data); }

  private:
    std::string m_data;
};

template <typename wireType>
struct FieldType {
    typedef wireType type;
    FieldType() {}
    FieldType(const type &init) : value(init) {}
    FieldType(type &&init) : value(std::move(init)) {}
    type value = wireType();
    void reset() { value = type(); }
};

#if 0
struct Int8 : public FieldType<int8_t> {
    void serialize(OutSlice *slice) const { slice->putU8(static_cast<uint8_t>(value)); }
    constexpr void deserialize(InSlice *slice) { value = static_cast<int8_t>(slice->getU8()); }
    static constexpr char const typeName[] = "int8_t";
};
#endif

struct Int16 : public FieldType<int16_t> {
    void serialize(OutSlice *slice) const { slice->putU16(static_cast<uint16_t>(value)); }
    constexpr void deserialize(InSlice *slice) { value = static_cast<int16_t>(slice->getU16()); }
    static constexpr char const typeName[] = "int16_t";
};

struct Int32 : public FieldType<int32_t> {
    void serialize(OutSlice *slice) const { slice->putU32(static_cast<uint32_t>(value)); }
    constexpr void deserialize(InSlice *slice) { value = static_cast<int32_t>(slice->getU32()); }
    static constexpr char const typeName[] = "int32_t";
};

struct Int64 : public FieldType<int64_t> {
    void serialize(OutSlice *slice) const { slice->putU64(static_cast<uint64_t>(value)); }
    constexpr void deserialize(InSlice *slice) { value = static_cast<int64_t>(slice->getU64()); }
    static constexpr char const typeName[] = "int64_t";
};

struct UInt8 : public FieldType<uint8_t> {
    void serialize(OutSlice *slice) const { slice->putU8(value); }
    constexpr void deserialize(InSlice *slice) { value = static_cast<uint8_t>(slice->getU8()); }
    static constexpr char const typeName[] = "uint8_t";
};

struct UInt16 : public FieldType<uint16_t> {
    void serialize(OutSlice *slice) const { slice->putU16(value); }
    constexpr void deserialize(InSlice *slice, unsigned) { value = slice->getU16(); }
    static constexpr char const typeName[] = "uint16_t";
};

struct UInt32 : public FieldType<uint32_t> {
    void serialize(OutSlice *slice) const { slice->putU32(value); }
    constexpr void deserialize(InSlice *slice, unsigned) { value = slice->getU32(); }
    static constexpr char const typeName[] = "uint32_t";
};

struct UInt64 : public FieldType<uint64_t> {
    void serialize(OutSlice *slice) const { slice->putU64(value); }
    constexpr void deserialize(InSlice *slice, unsigned) { value = slice->getU64(); }
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
    Message() {}
    Message(const fields &...values) : base(values...) {}
    Message(fields &&...values) : base(std::move(values)...) {}
    using name = irqus::typestring<C...>;
    static constexpr char const typeName[sizeof...(C) + 1] = {C..., '\0'};
};

}  // namespace BinStruct

}  // namespace PCSX
