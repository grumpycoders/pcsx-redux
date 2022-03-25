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
#include "support/file.h"
#include "support/typestring-wrapper.h"

#include "gtest/gtest.h"

using namespace PCSX;
using namespace PCSX::BinStruct;

typedef Field<UInt8, TYPESTRING("field1")> Field1;
typedef Field<UInt32, TYPESTRING("field2")> Field2;
typedef Field<CString<12>, TYPESTRING("astring")> Field3;
typedef Field<NString, TYPESTRING("anotherstring")> Field4;
typedef Struct<TYPESTRING("AStruct"), Field1, Field2, Field3, Field4> Struct1;

TEST(BinStruct, Deserialize) {
    Struct1 s1;
    IO<File> f(new BufferFile(FileOps::READWRITE));

    f->write<uint8_t>(42);
    f->write<uint32_t>(28);
    f->writeString("Hello World!");
    f->write<uint8_t>(3);
    f->writeString("Hi!");

    s1.deserialize(f);

    EXPECT_EQ(s1.get<Field1>(), 42);
    EXPECT_EQ(s1.get<Field2>(), 28);
    EXPECT_EQ(s1.get<Field3>(), "Hello World!");
    EXPECT_EQ(s1.get<Field4>(), "Hi!");
}
