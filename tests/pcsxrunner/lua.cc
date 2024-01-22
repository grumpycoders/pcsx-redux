/***************************************************************************
 *   Copyright (C) 2024 PCSX-Redux authors                                 *
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

#include "gtest/gtest.h"
#include "main/main.h"

static const char prefix[] = R"(
    os.exit = PCSX.quit
    package.path = package.path .. ';../../../third_party/luaunit/?.lua'
    package.path = package.path .. ';./third_party/luaunit/?.lua'
    package.path = package.path .. ';../../../tests/lua/?.lua'
    package.path = package.path .. ';./tests/lua/?.lua'
)";

TEST(LuaBasic, Interpreter) {
    MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode", "-interpreter",
                        "-luacov", "-exec", prefix, "-exec", "require 'basic'");
    int ret = invoker.invoke();
    EXPECT_EQ(ret, 0);
}

TEST(LuaBasic, Dynarec) {
    MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode", "-dynarec", "-luacov",
                        "-exec", prefix, "-exec", "require 'basic'");
    int ret = invoker.invoke();
    EXPECT_EQ(ret, 0);
}
