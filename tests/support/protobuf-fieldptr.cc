/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include <stdint.h>
#include <string.h>

#include <string>

#include "gtest/gtest.h"
#include "support/protobuf.h"
#include "support/typestring-wrapper.h"

namespace {

namespace Protobuf = PCSX::Protobuf;

typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("counter"), 1> Counter;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<16>, TYPESTRING("blob"), 2> Blob;
typedef Protobuf::Message<TYPESTRING("Old"), Counter> Old;
typedef Protobuf::Message<TYPESTRING("New"), Counter, Blob> New;

}  // namespace

// A message written before a FieldPtr field existed has no bytes for it. Committing
// it must leave the destination alone rather than copy from the absent field.
TEST(ProtobufFieldPtr, AbsentFieldLeavesDestination) {
    Old old;
    old.get<Counter>().value = 42;
    Protobuf::OutSlice out;
    old.serialize(&out);
    std::string data = out.finalize();

    uint8_t dest[16];
    memset(dest, 0x5a, sizeof(dest));
    New msg{Counter{}, Blob{dest}};
    Protobuf::InSlice in(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    msg.deserialize(&in, 0);
    msg.commit();

    EXPECT_EQ(msg.get<Counter>().value, 42u);
    for (unsigned i = 0; i < sizeof(dest); i++) EXPECT_EQ(dest[i], 0x5a) << "byte " << i;
}

// The present case still copies.
TEST(ProtobufFieldPtr, PresentFieldCommits) {
    uint8_t src[16];
    for (unsigned i = 0; i < sizeof(src); i++) src[i] = static_cast<uint8_t>(i * 3 + 1);
    New saved{Counter{7}, Blob{src}};
    Protobuf::OutSlice out;
    saved.serialize(&out);
    std::string data = out.finalize();

    uint8_t dest[16] = {};
    New msg{Counter{}, Blob{dest}};
    Protobuf::InSlice in(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    msg.deserialize(&in, 0);
    msg.commit();

    EXPECT_EQ(msg.get<Counter>().value, 7u);
    EXPECT_EQ(memcmp(dest, src, sizeof(src)), 0);
}
