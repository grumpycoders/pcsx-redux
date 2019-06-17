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

#include <memory.h>
#include <stdint.h>

#include <map>
#include <memory>
#include <ostream>
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
    uint64_t getU64() {
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

template <typename innerType, unsigned wireTypeValue>
struct FieldType {
    typedef innerType type;
    FieldType(){};
    FieldType(const type &init) : value(init) {}
    FieldType(type &&init) : value(init) {}
    type value = innerType();
    void reset() { value = type(); }
    static constexpr unsigned wireType = wireTypeValue;
    static constexpr bool matches(unsigned otherWireType) { return wireType == otherWireType; }
    constexpr bool hasData() const { return value == innerType(); }
};

struct Int32 : public FieldType<int32_t, 0> {
    void serialize(OutSlice *slice) const { slice->putVarInt(value); }
    void deserialize(InSlice *slice, unsigned) { value = static_cast<int32_t>(slice->getVarInt()); }
    static constexpr char const typeName[] = "int32";
};

struct Int64 : public FieldType<int64_t, 0> {
    void serialize(OutSlice *slice) const { slice->putVarInt(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getVarInt(); }
    static constexpr char const typeName[] = "int64";
};

struct UInt32 : public FieldType<uint32_t, 0> {
    void serialize(OutSlice *slice) const { slice->putVarInt(value); }
    void deserialize(InSlice *slice, unsigned) { value = static_cast<uint32_t>(slice->getVarInt()); }
    static constexpr char const typeName[] = "uint32";
};

struct UInt64 : public FieldType<uint64_t, 0> {
    void serialize(OutSlice *slice) const { slice->putVarInt(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getVarInt(); }
    static constexpr char const typeName[] = "uint64";
};

struct SInt32 : public FieldType<int32_t, 0> {
    void serialize(OutSlice *slice) const { slice->putVarInt((value << 1) ^ (value >> 31)); }
    void deserialize(InSlice *slice, unsigned) {
        value = static_cast<int32_t>(slice->getVarInt());
        value = (value >> 1) ^ -(value & 1);
    }
    static constexpr char const typeName[] = "sint32";
};

struct SInt64 : public FieldType<int64_t, 0> {
    void serialize(OutSlice *slice) const { slice->putVarInt((value << 1) ^ (value >> 63)); }
    void deserialize(InSlice *slice, unsigned) {
        value = slice->getVarInt();
        value = (value >> 1) ^ -(value & 1);
    }
    static constexpr char const typeName[] = "sint64";
};

struct Bool : public FieldType<bool, 0> {
    void serialize(OutSlice *slice) const { slice->putVarInt(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getVarInt(); }
    static constexpr char const typeName[] = "bool";
};

struct Fixed64 : public FieldType<uint64_t, 1> {
    void serialize(OutSlice *slice) const { slice->putU64(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getU64(); }
    static constexpr char const typeName[] = "fixed64";
};

struct SFixed64 : public FieldType<int64_t, 1> {
    void serialize(OutSlice *slice) const { slice->putU64(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getU64(); }
    static constexpr char const typeName[] = "sfixed64";
};

struct Double : public FieldType<double, 1> {
    void serialize(OutSlice *slice) const {
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
    static constexpr char const typeName[] = "double";
};

struct String : public FieldType<std::string, 2> {
    void serialize(OutSlice *slice) const {
        slice->putVarInt(value.size());
        slice->putBytes(value);
    }
    void deserialize(InSlice *slice, unsigned) { value = slice->getBytes(slice->getVarInt()); }
    static constexpr char const typeName[] = "string";
};

struct Bytes : public FieldType<std::string, 2> {
    void serialize(OutSlice *slice) const {
        slice->putVarInt(value.size());
        slice->putBytes(value);
    }
    void deserialize(InSlice *slice, unsigned) { value = slice->getBytes(slice->getVarInt()); }
    static constexpr char const typeName[] = "bytes";
};

template <size_t amount>
struct FixedBytes {
    ~FixedBytes() { free(value); }
    FixedBytes() {}
    FixedBytes(const FixedBytes &s) {
        free(value);
        value = nullptr;
        if (!s.value) return;
        allocate();
        memcpy(value, s.value, amount);
    }
    FixedBytes(FixedBytes &&s) {
        if (!s.value) return;
        value = s.value;
        s.value = nullptr;
    }
    void serialize(OutSlice *slice) const {
        slice->putVarInt(amount);
        slice->putBytes(value, amount);
    }
    void deserialize(InSlice *slice, unsigned) {
        uint64_t size = slice->getVarInt();
        if (size > amount) throw OutOfBoundError();
        value = reinterpret_cast<uint8_t *>(malloc(amount));
        slice->getBytes(value, size);
    }
    static constexpr char const typeName[] = "bytes";
    uint8_t *value = nullptr;
    void allocate() {
        if (!value) value = reinterpret_cast<uint8_t *>(malloc(amount));
    }
    void copyFrom(const uint8_t *src) {
        allocate();
        memcpy(value, src, amount);
    }
    void copyTo(uint8_t *dst) const { memcpy(dst, value, amount); }
    typedef uint8_t *type;
    void reset() { memset(value, 0, amount); }
    static constexpr unsigned wireType = 2;
    static constexpr bool matches(unsigned otherWireType) { return otherWireType == 2; }
    constexpr bool hasData() const { return value; }
};

struct Fixed32 : public FieldType<uint32_t, 5> {
    void serialize(OutSlice *slice) const { slice->putU32(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getU32(); }
    static constexpr char const typeName[] = "fixed32";
};

struct SFixed32 : public FieldType<int32_t, 5> {
    void serialize(OutSlice *slice) const { slice->putU32(value); }
    void deserialize(InSlice *slice, unsigned) { value = slice->getU32(); }
    static constexpr char const typeName[] = "sfixed32";
};

struct Float : public FieldType<float, 5> {
    void serialize(OutSlice *slice) const {
        union {
            float f;
            uint32_t v;
        } u;
        u.f = value;
        slice->putU32(u.v);
    }
    void deserialize(InSlice *slice, unsigned) {
        union {
            float f;
            uint64_t v;
        } u;
        u.v = slice->getU32();
        value = u.f;
    }
    static constexpr char const typeName[] = "float";
};

class CorruptedWireFormat {};

template <typename FieldType, typename name, uint64_t fieldNumberValue>
struct Field;
template <typename FieldType, char... C, uint64_t fieldNumberValue>
struct Field<FieldType, irqus::typestring<C...>, fieldNumberValue> : public FieldType {
  private:
    using type = typename FieldType::type;

  public:
    Field() {}
    Field(type init) { FieldType::value = init; }
    static constexpr uint64_t fieldNumber = fieldNumberValue;
    typedef irqus::typestring<C...> fieldName;
    static void dumpSchema(std::ostream &stream) {
        stream << "    " << FieldType::typeName << " " << fieldName::data() << " = " << fieldNumberValue << ";"
               << std::endl;
    }
};

template <typename FieldType, typename name, uint64_t fieldNumberValue>
struct FieldRef;
template <typename FieldType, char... C, uint64_t fieldNumberValue>
struct FieldRef<FieldType, irqus::typestring<C...>, fieldNumberValue> : public FieldType {
  private:
    using type = typename FieldType::type;

  public:
    FieldRef(type &dest) : ref(dest) {}
    static constexpr uint64_t fieldNumber = fieldNumberValue;
    typedef irqus::typestring<C...> fieldName;
    static void dumpSchema(std::ostream &stream) {
        stream << "    " << FieldType::typeName << " " << fieldName::data() << " = " << fieldNumberValue << ";"
               << std::endl;
    }
    void serialize(OutSlice *slice) const {
        FieldType *field = reinterpret_cast<FieldType *>(&ref);
        field->serialize(slice);
    }
    void deserialize(InSlice *slice, unsigned wireType) {
        FieldType *field = reinterpret_cast<FieldType *>(&ref);
        field->deserialize(slice, wireType);
    }
    void reset() {}

  private:
    type &ref;
    type copy;
};

template <typename FieldType, typename name, uint64_t fieldNumberValue>
struct RepeatedField;
template <typename FieldType, char... C, uint64_t fieldNumberValue>
struct RepeatedField<FieldType, irqus::typestring<C...>, fieldNumberValue> {
    static constexpr uint64_t fieldNumber = fieldNumberValue;
    static constexpr unsigned wireType = 2;
    typedef irqus::typestring<C...> fieldName;
    static void dumpSchema(std::ostream &stream) {
        stream << "    repeated " << FieldType::typeName << " " << fieldName::data() << " = " << fieldNumberValue << ";"
               << std::endl;
    }
    std::vector<FieldType> value;
    void reset() { value.clear(); }
    static constexpr bool matches(unsigned wireType) { return wireType == 2 || FieldType::matches(wireType); }
    void serialize(OutSlice *slice) const {
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
    constexpr bool hasData() const { return !value.empty(); }
};

template <size_t amount, typename FieldType, typename name, uint64_t fieldNumberValue>
struct RepeatedFieldRef;
template <size_t amount, typename FieldType, char... C, uint64_t fieldNumberValue>
struct RepeatedFieldRef<amount, FieldType, irqus::typestring<C...>, fieldNumberValue> {
    using innerType = typename FieldType::type;
    RepeatedFieldRef(const RepeatedFieldRef &s) : ref(s.ref), count(s.count) {}
    RepeatedFieldRef(RepeatedFieldRef &&s) : ref(s.ref), count(s.count) {}
    RepeatedFieldRef(innerType *init) : ref(init) {}
    static constexpr uint64_t fieldNumber = fieldNumberValue;
    static constexpr unsigned wireType = 2;
    typedef irqus::typestring<C...> fieldName;
    static void dumpSchema(std::ostream &stream) {
        stream << "    repeated " << FieldType::typeName << " " << fieldName::data() << " = " << fieldNumberValue << ";"
               << std::endl;
    }
    innerType *ref;
    size_t count = 0;
    void reset() { memset(ref, 0, sizeof(FieldType) * amount); }
    static constexpr bool matches(unsigned wireType) { return wireType == 2 || FieldType::matches(wireType); }
    void serialize(OutSlice *slice) const {
        OutSlice subSlice;
        for (size_t i = 0; i < amount; i++) {
            FieldType *field = reinterpret_cast<FieldType *>(ref + i);
            field->serialize(&subSlice);
        }
        std::string subSliceData = subSlice.finalize();
        slice->putVarInt(subSliceData.size());
        slice->putBytes(subSliceData);
    }
    void deserialize(InSlice *slice, unsigned wireType) {
        uint64_t n = 1;
        if (FieldType::wireType != wireType) n = slice->getVarInt();
        if ((n + count) > amount) throw OutOfBoundError();
        count += n;
        for (uint64_t i = 0; i < n; i++) {
            FieldType *field = reinterpret_cast<FieldType *>(ref + count++);
            field->deserialize(slice);
        }
    }
    constexpr bool hasData() const { return true; }
};

template <typename MessageType, typename name, uint64_t fieldNumberValue>
struct MessageField;
template <typename MessageType, char... C, uint64_t fieldNumberValue>
struct MessageField<MessageType, irqus::typestring<C...>, fieldNumberValue> : public MessageType {
    MessageField() : MessageType() {}
    MessageField(const MessageType &value) : MessageType(value) {}
    MessageField(MessageType &value) : MessageType(value) {}
    template <typename... fields>
    MessageField(const fields &... values) : MessageType(values...) {}
    template <typename... fields>
    MessageField(fields &&... values) : MessageType(values...) {}
    static constexpr bool matches(unsigned wireType) { return wireType == 2; }
    static constexpr unsigned wireType = 2;
    static constexpr uint64_t fieldNumber = fieldNumberValue;
    typedef irqus::typestring<C...> fieldName;
    static void dumpSchema(std::ostream &stream) {
        stream << "    " << MessageType::name::data() << " " << fieldName::data() << " = " << fieldNumberValue << ";"
               << std::endl;
    }
    void serialize(OutSlice *slice) const {
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
    using myself = Message<irqus::typestring<C...>, fields...>;
    using base = std::tuple<fields...>;

  public:
    static constexpr bool isMessage = true;
    using type = myself;
    Message() { verifyIntegrity<0, fields...>(); }
    Message(const fields &... values) : base(values...) { verifyIntegrity<0, fields...>(); }
    Message(fields &&... values) : base(values...) { verifyIntegrity<0, fields...>(); }
    using name = irqus::typestring<C...>;
    static constexpr char const typeName[sizeof...(C) + 1] = {C..., '\0'};
    static void dumpSchema(std::ostream &stream) {
        stream << "message " << name::data() << " {" << std::endl;
        dumpSchema<0, fields...>(stream);
    }
    constexpr void reset() { reset<0, fields...>(); }
    template <typename FieldType>
    constexpr const FieldType &get() const {
        // std::static_assert(hasFieldType<FieldType>());
        return std::get<FieldType>(*this);
    }
    template <typename FieldType>
    constexpr FieldType &get() {
        return std::get<FieldType>(*this);
    }
    void serialize(OutSlice *slice) const { serialize<0, fields...>(slice); }
    constexpr void deserialize(InSlice *slice) {
        while (slice->bytesLeft()) {
            uint64_t fieldNumber = slice->getVarInt();
            unsigned wireType = fieldNumber & 7;
            fieldNumber >>= 3;
            deserialize<0, fields...>(fieldNumber, wireType, slice);
        }
    }
    constexpr bool hasData() const { return hasData<0, fields...>(); }

  private:
    template <size_t index>
    static void dumpSchema(std::ostream &stream) {
        stream << "}" << std::endl << std::endl;
    }
    template <size_t index, typename FieldType, typename... nestedFields>
    static void dumpSchema(std::ostream &stream) {
        FieldType::dumpSchema(stream);
        dumpSchema<index + 1, nestedFields...>(stream);
    }
    template <size_t index>
    void reset() {}
    template <size_t index, typename FieldType, typename... nestedFields>
    void reset() {
        std::get<index>().reset();
        reset<index + 1, nestedFields...>();
    }
    template <size_t index>
    static constexpr void verifyIntegrity() {}
    template <size_t index, typename FieldType, typename... nestedFields>
    static constexpr void verifyIntegrity() {
        // std::static_assert(!hasField<index, nestedFields...>(FieldType::fieldNumber));
        verifyIntegrity<index + 1, nestedFields...>();
    }
    template <size_t index>
    static constexpr bool hasField(uint64_t fieldNumber) {
        return false;
    }
    template <size_t index, typename FieldType, typename... nestedFields>
    static constexpr bool hasField(uint64_t fieldNumber) {
        if (FieldType::fieldNumber == fieldNumber) return true;
        return hasField<index + 1, nestedFields...>(fieldNumber);
    }
    template<typename FieldType>
    static constexpr bool hasFieldType() {
        return hasFieldType<FieldType, 0, fields...>();
    }
    template<typename FieldType, size_t index>
    static constexpr bool hasFieldType() {
        return false;
    }
    template <typename FieldTypeTest, size_t index, typename FieldType, typename... nestedFields>
    static constexpr bool hasFieldType() {
        if (std::is_same<FieldTypeTest, FieldType>()) return true;
        return hasFieldType<FieldTypeTest, index + 1, nestedFields>();
    }
    template <size_t index>
    constexpr void serialize(OutSlice *slice) const {}
    template <size_t index, typename FieldType, typename... nestedFields>
    constexpr void serialize(OutSlice *slice) const {
        const FieldType &field = std::get<index>(*this);
        if (field.hasData()) {
            slice->putVarInt((FieldType::fieldNumber << 3) | FieldType::wireType);
            field.serialize(slice);
        }
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
    template <size_t index>
    constexpr bool hasData() const {
        return false;
    }
    template <size_t index, typename FieldType, typename... nestedFields>
    constexpr bool hasData() const {
        const FieldType &field = std::get<index>(*this);
        if (field.hasData()) return true;
        return hasData<index + 1, nestedFields...>();
    }
};

template <typename... fields>
class ProtoFile : private std::tuple<fields...> {
  public:
    static void dumpSchema(std::ostream &stream) {
        stream << "syntax = \"proto3\";" << std::endl << std::endl;
        dumpSchema<0, fields...>(stream);
    }

  private:
    static constexpr bool isMessage = false;
    template <size_t index>
    static void dumpSchema(std::ostream &stream) {}
    template <size_t index, typename FieldType, typename... nestedFields>
    static void dumpSchema(std::ostream &stream) {
        FieldType::dumpSchema(stream);
        dumpSchema<index + 1, nestedFields...>(stream);
    }
};

}  // namespace Protobuf

}  // namespace PCSX
