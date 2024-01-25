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
package.path = package.path
    .. ';../../../third_party/luaunit/?.lua'
    .. ';./third_party/luaunit/?.lua'
    .. ';../../../?.lua'
    .. ';./?.lua'
)";

static const char suffix[] = R"(
coroutine.resume(coroutine.create(function()
    PCSX.quit(require('luaunit').LuaUnit.new():runSuite '--verbose')
end))
)";

template <typename... Args>
int runLuaInt(Args... args) {
    MainInvoker invoker("-no-ui", "-cli", "-bios", "src/mips/openbios/openbios.bin", "-testmode", "-interpreter", "-luacov",
                        "-exec", prefix, args..., "-exec", suffix);
    return invoker.invoke();
}

template <typename... Args>
int runLuaDyn(Args... args) {
    MainInvoker invoker("-no-ui", "-cli", "-bios", "src/mips/openbios/openbios.bin", "-testmode", "-dynarec", "-luacov",
                        "-exec", prefix, args..., "-exec", suffix);
    return invoker.invoke();
}

static int runLuaIntTest(const char* name) {
    std::string req = "require '";
    req += name;
    req += "'";
    return runLuaInt("-exec", req.c_str());
}

static int runLuaDynTest(const char* name) {
    std::string req = "require '";
    req += name;
    req += "'";
    return runLuaDyn("-exec", req.c_str());
}

TEST(LuaBasic, Interpreter) { EXPECT_EQ(runLuaIntTest("tests.lua.basic"), 0); }
TEST(LuaBasic, Dynarec) { EXPECT_EQ(runLuaDynTest("tests.lua.basic"), 0); }
TEST(LuaFile, Interpreter) { EXPECT_EQ(runLuaIntTest("tests.lua.file"), 0); }
TEST(LuaFile, Dynarec) { EXPECT_EQ(runLuaDynTest("tests.lua.file"), 0); }
