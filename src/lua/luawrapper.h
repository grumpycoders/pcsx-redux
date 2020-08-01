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

#include <functional>
#include <map>
#include <string>

#include "core/psxemulator.h"
#include "lua.hpp"

namespace PCSX {

class Lua {
  public:
    typedef int (*openlualib_t)(lua_State* L);

    Lua();
    Lua(lua_State* L) : L(L) {}
    Lua(Lua&& oL) noexcept : L(oL.L) { oL.L = nullptr; }
    Lua(const Lua& oL) : L(oL.L) {}

    Lua& operator=(Lua&& oL) noexcept;

    typedef int (*lua_CallWrapper)(lua_State*, lua_CFunction);

    int ref(int t = -2) { return luaL_ref(L, t); }
    void unref(int ref, int t = -1) { luaL_unref(L, t, ref); }

    void close();
    void open_base();
    void open_bit();
    void open_debug();
    void open_ffi();
    void open_jit();
    void open_math();
    void open_package();
    void open_string();
    void open_table();

    int wrap_open(openlualib_t open) {
        int n = gettop();
        int r = open(L);
        while (n < gettop()) pop();
        return r;
    }
    void openlib(const std::string& libname, const struct luaL_Reg* l, int nup) {
        luaL_openlib(L, libname.c_str(), l, nup);
    }

    void setCallWrap(lua_CallWrapper wrapper);
    void declareFunc(const char* funcName, lua_CFunction f, int tableIdx = LUA_GLOBALSINDEX);
    void declareFunc(const char* funcName, std::function<int(Lua)> f, int tableIdx = LUA_GLOBALSINDEX);
    void declareFunc(const std::string& funcName, lua_CFunction f, int tableIdx = LUA_GLOBALSINDEX) {
        declareFunc(funcName.c_str(), f, tableIdx);
    }
    void declareFunc(const std::string& funcName, std::function<int(Lua)> f, int tableIdx = LUA_GLOBALSINDEX) {
        declareFunc(funcName.c_str(), f, tableIdx);
    }

    void call(const char* funcName, int tableIdx = LUA_GLOBALSINDEX, int nArgs = 0);
    void call(int nArgs = 0);
    void pcall(int nArgs = 0);

    void push() {
        checkstack();
        lua_pushnil(L);
    }
    void push(lua_Number n) {
        checkstack();
        lua_pushnumber(L, n);
    }
    void push(const std::string& s) {
        checkstack();
        lua_pushlstring(L, s.c_str(), s.length());
    }
    void push(bool b) {
        checkstack();
        lua_pushboolean(L, b);
    }
    template <size_t S>
    void push(const char (&str)[S]) {
        checkstack();
        lua_pushlstring(L, str, S - 1);
    }
    void push(const char* str, ssize_t size = -1) {
        if (size < 0) size = strlen(str);
        checkstack();
        lua_pushlstring(L, str, size);
    }
    void push(void* p) {
        checkstack();
        lua_pushlightuserdata(L, p);
    }
    void push(lua_CFunction f, int n = 0) {
        checkstack();
        lua_pushcclosure(L, f, n);
    }
    void pop(int idx = 1) { lua_pop(L, idx); }
    int checkstack(int extra = 1) { return lua_checkstack(L, extra); }

    int next(int t = -2) { return lua_next(L, t); }
    void copy(int i = -1) {
        checkstack();
        lua_pushvalue(L, i);
    }
    void remove(int i = 1) { lua_remove(L, i); }
    void insert(int i = 1) {
        checkstack();
        lua_insert(L, i);
    }
    void replace(int i = 1) { lua_replace(L, i); }
    void newtable() {
        checkstack();
        lua_newtable(L);
    }
    void* newuser(size_t s) {
        checkstack();
        return lua_newuserdata(L, s);
    }
    void settable(int tableIdx = -3, bool raw = false);
    void gettable(int tableIdx = -2, bool raw = false);
    void rawseti(int idx, int tableIdx = -2) { lua_rawseti(L, tableIdx, idx); }
    void rawgeti(int idx, int tableIdx = -1) { lua_rawgeti(L, tableIdx, idx); }
    void setvar() { lua_settable(L, LUA_GLOBALSINDEX); }
    int gettop() { return lua_gettop(L); }
    void getglobal(const char* name);
    void pushLuaContext();
    void error(const char* msg);
    void error(const std::string& msg) { error(msg.c_str()); }

    int type(int i = -1) { return lua_type(L, i); }
    std::string typestring(int i = -1) {
        static const std::map<int, std::string> strings = {
            {LUA_TNIL, "nil"},           {LUA_TNUMBER, "number"}, {LUA_TBOOLEAN, "boolean"},
            {LUA_TSTRING, "string"},     {LUA_TTABLE, "table"},   {LUA_TFUNCTION, "function"},
            {LUA_TUSERDATA, "userdata"}, {LUA_TTHREAD, "thread"}, {LUA_TLIGHTUSERDATA, "lightuserdata"}};
        return strings.find(lua_type(L, i))->second;
    }
    bool isnil(int i = -1) { return lua_isnil(L, i); }
    bool isboolean(int i = -1) { return lua_isboolean(L, i); }
    bool isnumber(int i = -1) { return lua_isnumber(L, i); }
    bool isstring(int i = -1) { return lua_isstring(L, i); }
    bool istable(int i = -1) { return lua_istable(L, i); }
    bool isfunction(int i = -1) { return lua_isfunction(L, i); }
    bool iscfunction(int i = -1) { return lua_iscfunction(L, i); }
    bool isuserdata(int i = -1) { return lua_isuserdata(L, i); }
    bool islightuserdata(int i = -1) { return lua_islightuserdata(L, i); }
    bool isobject(int i = -1);

    int upvalue(int i) { return lua_upvalueindex(i); }

    bool toboolean(int i = -1) { return lua_toboolean(L, i); }
    lua_Number tonumber(int i = -1) { return lua_tonumber(L, i); }
    std::string tostring(int i = -1);
    lua_CFunction tocfunction(int i = -1) { return lua_tocfunction(L, i); }
    void* touserdata(int i = -1) { return lua_touserdata(L, i); }

    void concat(int n = 2) { lua_concat(L, n); }

    void displayStack(bool error = false);

    std::string escapeString(const std::string&);
    void load(const std::string& str, const std::string& name, bool docall = true);
    int yield(int nresults = 0) { return lua_yield(L, nresults); }
    bool yielded() { return lua_status(L) == LUA_YIELD; }
    int getmetatable(int i = -1) {
        checkstack();
        return lua_getmetatable(L, i);
    }
    int setmetatable(int i = -2) { return lua_setmetatable(L, i); }
    int sethook(lua_Hook func, int mask, int count) { return lua_sethook(L, func, mask, count); }

    lua_State* getState() { return L; }

  private:
    lua_State* L;
};

}  // namespace PCSX
