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

#include "support/binstruct.h"

#include "gtest/gtest.h"
#include "support/file.h"
#include "support/typestring-wrapper.h"

using namespace PCSX;
using namespace PCSX::BinStruct;

typedef Field<UInt8, TYPESTRING("field1")> Field1;
typedef Field<BEUInt16, TYPESTRING("befield2")> Field2;
typedef Field<UInt32, TYPESTRING("field3")> Field3;
typedef Field<CString<12>, TYPESTRING("astring")> Field4;
typedef Field<NString, TYPESTRING("anotherstring")> Field5;
typedef Struct<TYPESTRING("AStruct"), Field1, Field2, Field3, Field4, Field5> Struct1;

TEST(BasicBinStruct, Deserialize) {
    Struct1 s1;
    IO<File> f(new BufferFile(FileOps::READWRITE));

    f->write<uint8_t>(42);
    f->write<uint16_t>(0x1234);
    f->write<uint32_t>(28);
    f->writeString("Hello World!");
    f->write<uint8_t>(3);
    f->writeString("Hi!");

    s1.deserialize(f);

    EXPECT_EQ(s1.get<Field1>(), 42);
    EXPECT_EQ(s1.get<Field2>(), 0x3412);
    EXPECT_EQ(s1.get<Field3>(), 28);
    EXPECT_EQ(std::string_view(s1.get<Field4>()), "Hello World!");
    EXPECT_EQ(s1.get<Field5>().value, "Hi!");
}

TEST(BasicBinStruct, Serialize) {
    Struct1 s1;
    s1.get<Field1>().value = 42;
    s1.get<Field2>().value = 0x3412;
    s1.get<Field3>().value = 28;
    s1.get<Field4>().set("Hello World!");
    s1.get<Field5>().value = "Hi!";

    IO<File> f(new BufferFile(FileOps::READWRITE));
    s1.serialize(f);
    EXPECT_EQ(f->read<uint8_t>(), 42);
    EXPECT_EQ(f->read<uint16_t>(), 0x1234);
    EXPECT_EQ(f->read<uint32_t>(), 28);
    EXPECT_EQ(f->readString(12), "Hello World!");
    EXPECT_EQ(f->read<uint8_t>(), 3);
    EXPECT_EQ(f->readString(3), "Hi!");
}

typedef Field<UInt32, TYPESTRING("superfield1")> SuperField1;
typedef Field<CString<7>, TYPESTRING("superfield2")> SuperField2;
typedef StructField<Struct1, TYPESTRING("substruct")> SuperField3;
typedef Struct<TYPESTRING("Struct2"), SuperField1, SuperField2, SuperField3> Struct2;

TEST(NestedBinStruct, Deserialize) {
    Struct2 s2;
    IO<File> f(new BufferFile(FileOps::READWRITE));

    f->write<uint32_t>(0x12345678);
    f->writeString("1234567");
    f->write<uint32_t>(42);
    f->write<uint8_t>(3);
    f->writeString("Hello");
    f->write<uint8_t>(5);
    f->writeString("World!");

    s2.deserialize(f);
    auto& s1 = s2.get<SuperField3>();

    EXPECT_EQ(s2.get<SuperField1>(), 0x12345678);
    EXPECT_EQ(std::string_view(s2.get<SuperField2>()), "1234567");
    EXPECT_EQ(s1.get<Field1>(), 42);
    EXPECT_EQ(s1.get<Field2>(), 0x3412);
    EXPECT_EQ(s1.get<Field3>(), 28);
    EXPECT_EQ(std::string_view(s1.get<Field4>()), "Hello World!");
    EXPECT_EQ(s1.get<Field5>().value, "Hi!");
}
