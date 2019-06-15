/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

#include "typestring.hh"

namespace PCSX {

class OutOfBoundError {};

namespace Protobuf {

class InSlice {
  public:
    uint64_t bytesLeft() { return m_size - m_ptr; }
    InSlice(const uint8_t *data, uint64_t size) : m_data(data), m_size(size) {}
    InSlice getSubSlice(uint64_t size) const {
        boundsCheck(size);
        return InSlice(m_data + m_ptr, size);
    }
    uint8_t getU8() {
        boundsCheck(1);
        return getU8Safe();
    }
    uint16_t getU16() {
        boundsCheck(2);
        uint16_t ret = static_cast<uint16_t>(getU8Safe());
        ret |= static_cast<uint16_t>(getU8Safe()) << 8;
        return ret;
    }
    uint32_t getU32() {
        boundsCheck(4);
        uint32_t ret = static_cast<uint32_t>(getU8Safe());
        ret |= static_cast<uint32_t>(getU8Safe()) << 8;
        ret |= static_cast<uint32_t>(getU8Safe()) << 16;
        ret |= static_cast<uint32_t>(getU8Safe()) << 24;
        return ret;
    }
    uint32_t getU64() {
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
    void skipBytes(uint64_t size) {
        boundsCheck(size);
        m_ptr += size;
    }
    uint64_t getVarInt() {
        uint64_t ret = 0;
        uint8_t b;
        unsigned shift = 0;
        do {
            b = getU8();
            ret |= static_cast<uint64_t>(b & 0x7f) << shift;
            shift += 7;
        } while ((b & 0x80) == 0x80);
        return ret;
    }

  private:
    const uint8_t *m_data;
    const uint64_t m_size;
    uint64_t m_ptr = 0;

    inline uint8_t getU8Safe() { return m_data[m_ptr++]; }

    void boundsCheck(uint64_t size) const {
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
    void putVarInt(uint64_t value) {
        uint8_t b;
        do {
            b = value & 0x7f;
            value >>= 7;
            putU8(b | (value ? 0x80 : 0x00));
        } while (value);
    }
    std::string finalize() { return std::move(m_data); }

  private:
    std::string m_data;
};

template <typename type, unsigned wireTypeValue>
struct FieldType {
    type value;
    void reset() { value = type(); }
    static constexpr unsigned wireType = wireTypeValue;
    static constexpr bool matches(unsigned otherWireType) { return wireType == otherWireType; }
};

struct FieldTypeInt32 : public FieldType<int32_t, 0> {
    void serialize(OutSlice *slice) { slice->putVarInt(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getVarInt(); }
};

struct FieldTypeInt64 : public FieldType<int64_t, 0> {
    void serialize(OutSlice *slice) { slice->putVarInt(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getVarInt(); }
};

struct FieldTypeUInt32 : public FieldType<uint32_t, 0> {
    void serialize(OutSlice *slice) { slice->putVarInt(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getVarInt(); }
};

struct FieldTypeUInt64 : public FieldType<uint64_t, 0> {
    void serialize(OutSlice *slice) { slice->putVarInt(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getVarInt(); }
};

struct FieldTypeSInt32 : public FieldType<int32_t, 0> {
    void serialize(OutSlice *slice) { slice->putVarInt((value << 1) ^ (value >> 31)); }
    void deserialize(InSlice *slice, unsigned) {
        value = slice->getVarInt();
        value = (value >> 1) ^ -(value & 1);
    }
};

struct FieldTypeSInt64 : public FieldType<int64_t, 0> {
    void serialize(OutSlice *slice) { slice->putVarInt((value << 1) ^ (value >> 63)); }
    void deserialize(InSlice *slice, unsigned) {
        value = slice->getVarInt();
        value = (value >> 1) ^ -(value & 1);
    }
};

struct FieldTypeBool : public FieldType<bool, 0> {
    void serialize(OutSlice *slice) { slice->putVarInt(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getVarInt(); }
};

#if 0
template<typename enumType>
struct FieldTypeEnum : FieldType<enumType, 0> {
    void serialize(OutSlice * slice) {
        slice->putVarInt(value);
    }
    void deserialize(InSlice * slice, unsigned) {
        value = static_cast<enumType>(slice->getVarInt());
    }
};
#endif

struct FieldTypeFixed64 : public FieldType<uint64_t, 1> {
    void serialize(OutSlice *slice) { slice->putU64(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getU64(); }
};

struct FieldTypeSFixed64 : public FieldType<int64_t, 1> {
    void serialize(OutSlice *slice) { slice->putU64(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getU64(); }
};

struct FieldTypeDouble : public FieldType<double, 1> {
    void serialize(OutSlice *slice) {
        union {
            double d;
            uint64_t v;
        } u;
        u.d = value;
        slice->putU64(u.v);
    }
    void deserialize(InSlice *slice, unsigned) {
        union {
            double d;
            uint64_t v;
        } u;
        u.v = slice->getU64();
        value = u.d;
    }
};

struct FieldTypeString : public FieldType<std::string, 2> {
    void serialize(OutSlice *slice) {
        slice->putVarInt(value.size());
        slice->putBytes(value);
    }
    void deserialize(InSlice *slice, unsigned) { value = slice->getBytes(slice->getVarInt()); }
};

struct FieldTypeBytes : public FieldType<std::string, 2> {
    void serialize(OutSlice *slice) {
        slice->putVarInt(value.size());
        slice->putBytes(value);
    }
    void deserialize(InSlice *slice, unsigned) { value = slice->getBytes(slice->getVarInt()); }
};

struct FieldTypeFixed32 : public FieldType<uint32_t, 5> {
    void serialize(OutSlice *slice) { slice->putU32(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getU32(); }
};

struct FieldTypeSFixed32 : public FieldType<int32_t, 5> {
    void serialize(OutSlice *slice) { slice->putU32(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getU32(); }
};

struct FieldTypeFloat : public FieldType<float, 5> {
    void serialize(OutSlice *slice) {
        union {
            float f;
            uint32_t v;
        } u;
        u.f = value;
        slice->putU32(u.v);
    }
    void deserialize(InSlice *slice, unsigned) {
        union {
            double f;
            uint64_t v;
        } u;
        u.v = slice->getU32();
        value = u.f;
    }
};

class CorruptedWireFormat {};

template <typename FieldType, typename name, uint64_t fieldNumberValue>
struct Field;
template <typename FieldType, char... C, uint64_t fieldNumberValue>
struct Field<FieldType, irqus::typestring<C...>, fieldNumberValue> : public FieldType {
    static constexpr uint64_t fieldNumber = fieldNumberValue;
    typedef irqus::typestring<C...> name;
};

template <typename FieldType, typename name, uint64_t fieldNumberValue>
struct RepeatedField;
template <typename FieldType, char... C, uint64_t fieldNumberValue>
struct RepeatedField<FieldType, irqus::typestring<C...>, fieldNumberValue> {
    static constexpr uint64_t fieldNumber = fieldNumberValue;
    std::vector<FieldType> value;
    void reset() { value.clear(); }
    static constexpr bool matches(unsigned wireType) { return wireType == 2 || FieldType::matches(wireType); }
    void serialize(OutSlice *slice) {
        OutSlice subSlice;
        for (const auto &v : value) {
            v.serialize(&subSlice);
        }
        std::string subSliceData = subSlice.finalize();
        slice->putVarInt(subSliceData.size());
        slice->putBytes(subSliceData);
    }
    void deserialize(InSlice *slice, unsigned wireType) {
        uint64_t n = 1;
        if (FieldType::wireType != wireType) n = slice->getVarInt();
        for (uint64_t i = 0; i < n; i++) {
            FieldType field;
            field.deserialize(slice);
            value.push_back(field);
        }
    }
};

template <typename MessageType, uint64_t fieldNumberValue>
struct MessageField : public MessageType {
    static constexpr bool matches(unsigned wireType) { return wireType == 2; }
    static constexpr unsigned wireType = 2;
    static constexpr uint64_t fieldNumber = fieldNumberValue;
    void serialize(OutSlice *slice) {
        OutSlice subSlice;
        MessageType::serialize(&subSlice);
        std::string subSliceData = subSlice.finalize();
        slice->putVarInt(subSliceData.size());
        slice->putBytes(subSliceData);
    }
    void deserialize(InSlice *slice) {
        InSlice subSlice = slice->getSubSlice(slice->getVarInt());
        MessageType::deserialize(subSlice);
    }
};

template <typename name, typename... fields>
class Message;
template <char... C, typename... fields>
class Message<irqus::typestring<C...>, fields...> : private std::tuple<fields...> {
  public:
    constexpr void reset() { reset<0, fields...>(); }
    template <typename field>
    constexpr const field &get() const {
        return std::get<field>(*this);
    }
    template <typename field>
    constexpr field &get() {
        return std::get<field>(*this);
    }
    void serialize(OutSlice *slice) { serialize<0, fields...>(slice); }
    constexpr void deserialize(InSlice *slice) {
        while (slice->bytesLeft()) {
            uint64_t fieldNumber = slice->getVarInt();
            unsigned wireType = fieldNumber & 7;
            fieldNumber >>= 3;
            deserialize<0, fields...>(fieldNumber, wireType, slice);
        }
    }

  private:
    template <size_t index>
    void reset() {}
    template <size_t index, typename FieldType, typename... nestedFields>
    void reset() {
        std::get<index>().reset();
        reset<index + 1, nestedFields...>();
    }
    constexpr bool hasField(uint64_t fieldNumber) { return hasField<0, fields...>(fieldNumber); }
    template <size_t index>
    constexpr bool hasField(unsigned fieldNumber) {
        return false;
    }
    template <size_t index, typename FieldType, typename... nestedFields>
    constexpr bool hasField(unsigned fieldNumber) {
        if (FieldType::fieldNumber == fieldNumber) return true;
        return hasField<index + 1, nestedFields...>(fieldNumber);
    }
    template <size_t index>
    constexpr void serialize(OutSlice *slice) {}
    template <size_t index, typename FieldType, typename... nestedFields>
    constexpr void serialize(OutSlice *slice) {
        FieldType &field = std::get<index>(*this);
        slice->putVarInt((FieldType::fieldNumber << 3) | FieldType::wireType);
        field.serialize(slice);
        serialize<index + 1, nestedFields...>(slice);
    }
    template <size_t index>
    constexpr void deserialize(uint64_t fieldNumber, unsigned wireType, InSlice *slice) {
        // Unknown field, skip it.
        switch (wireType) {
            case 0:
                slice->getVarInt();
                break;
            case 1:
                slice->getU64();
                break;
            case 2:
                slice->skipBytes(slice->getVarInt());
                break;
            case 5:
                slice->getU32();
                break;
            default:
                throw CorruptedWireFormat();
        }
    }
    template <size_t index, typename FieldType, typename... nestedFields>
    constexpr void deserialize(uint64_t fieldNumber, unsigned wireType, InSlice *slice) {
        FieldType &field = std::get<index>(*this);
        if (FieldType::fieldNumber == fieldNumber) {
            if (!FieldType::matches(wireType)) throw CorruptedWireFormat();
            field.deserialize(slice, wireType);
        } else {
            deserialize<index + 1, nestedFields...>(fieldNumber, wireType, slice);
        }
    }
};

}  // namespace Protobuf

}  // namespace PCSX
