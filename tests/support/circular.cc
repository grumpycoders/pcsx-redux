/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include "support/circular.h"

#include <stdint.h>

#include "gtest/gtest.h"

TEST(Circular, Basic) {
    PCSX::Circular<uint32_t> circ;

    uint32_t data[500];

    for (unsigned i = 0; i < 500; i++) {
        data[i] = i;
    }

    bool success;
    size_t size;

    success = circ.enqueue(data, 500);
    EXPECT_TRUE(success);

    size = circ.buffered();
    EXPECT_EQ(size, 500);
    size = circ.available();
    EXPECT_EQ(size, circ.BUFFER_SIZE - 500);

    size = circ.dequeue(data, 300);
    EXPECT_EQ(size, 300);

    for (unsigned i = 0; i < 300; i++) {
        EXPECT_EQ(data[i], i);
    }

    size = circ.dequeue(data, 300);
    EXPECT_EQ(size, 200);

    for (unsigned i = 0; i < 200; i++) {
        EXPECT_EQ(data[i], i + 300);
    }
}
