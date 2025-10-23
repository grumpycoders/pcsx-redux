/***************************************************************************
 *   Copyright (C) 2025 PCSX-Redux authors                                 *
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

#include <ctime>
#include <fmt/chrono.h>
#include "support/version.h"
#include "gtest/gtest.h"

using namespace PCSX;

class VersionInfoTest: public ::testing::Test {
protected:
    VersionInfo vi{
        "06fdac53",
        159,
        "06fdac536d1d8301fdc626fe89d1084a3ad241ad",
        1737185273,
    };
    static std::string formatWithStdLocal(std::time_t ts, const char* fmt_str) {
        auto tm_ptr = std::localtime(&ts);
        if (!tm_ptr) {
            return {};
        }
        return fmt::format(fmt::runtime(fmt_str), *tm_ptr);
    }
};

TEST_F(VersionInfoTest, TimestampFormatsDateAndTime) {
    auto format = "{:%Y-%m-%d %H:%M:%S}";
    EXPECT_EQ(vi.formatTimestamp(format), formatWithStdLocal(vi.timestamp, format));
}

TEST_F(VersionInfoTest, TimestampNullFormatReturnsNullString) {
    EXPECT_EQ(vi.formatTimestamp(""), "");
}

TEST_F(VersionInfoTest, TimestampFormatNoPlaceholderReturnsCopy) {
    EXPECT_EQ(vi.formatTimestamp("abc"), "abc");
}

TEST_F(VersionInfoTest, TimestampFormatReturnsNonPlaceholderText) {
    auto format = "123 {}";
    EXPECT_EQ(vi.formatTimestamp(format), formatWithStdLocal(vi.timestamp, format));
}

TEST_F(VersionInfoTest, TimestampFormatHandlesNegativeNumber) {
    vi.timestamp = -1;
    EXPECT_EQ(vi.formatTimestamp("{}"), formatWithStdLocal(vi.timestamp, "{}"));
}