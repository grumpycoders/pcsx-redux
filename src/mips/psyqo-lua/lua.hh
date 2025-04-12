/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#pragma once

extern "C" {
#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
}

#include "EASTL/string_view.h"
#include "psyqo/fixed-point.hh"

namespace psyqo {

struct Lua {
    using lua_CPPFunction = int (*)(Lua);

    Lua();
    Lua(lua_State* L) : L(L) {}
    Lua(Lua&& oL) noexcept : L(oL.L) { oL.L = nullptr; }
    Lua(const Lua& oL) : L(oL.L) {}

    Lua& operator=(Lua&& oL) noexcept;

    void close();

    // Get the lua state, for use in C functions when a wrapper method isn't available
    lua_State* getState() { return L; }

    // Stack Manipulation
    int getTop() { return lua_gettop(L); }
    void setTop(int idx) { lua_settop(L, idx); }
    void pop(int n = 1) { lua_settop(L, -(n)-1); }
    void clearStack() { lua_settop(L, 0); }
    void remove(int idx) { lua_remove(L, idx); }
    void insert(int idx) { lua_insert(L, idx); }
    void replace(int idx) { lua_replace(L, idx); }
    void copy(int fromidx, int toidx) { lua_copy(L, fromidx, toidx); }
    void copy(int fromidx) { lua_pushvalue(L, fromidx); }
    void checkStack(int sz, const char* msg = nullptr) { luaL_checkstack(L, sz, msg); }
    int getabsolute(int index) {
        if ((index < 0) && (index > LUA_REGISTRYINDEX)) return getTop() + index + 1;
        return index;
    }

    // Push values
    void push() { lua_pushnil(L); }
    void push(bool b) { lua_pushboolean(L, b); }
    void pushNumber(lua_Number n) { lua_pushnumber(L, n); }
    void push(std::nullptr_t) { lua_pushlightuserdata(L, nullptr); }
    void push(const char* s, size_t len) { lua_pushlstring(L, s, len); }
    template <size_t S>
    void push(const char (&s)[S]) {
        lua_pushlstring(L, s, S - 1);
    }
    void push(eastl::string_view s) { lua_pushlstring(L, s.data(), s.size()); }
    void vpushf(const char* fmt, va_list ap) { lua_pushvfstring(L, fmt, ap); }
    void pushf(const char* fmt, ...);
    void push(lua_CFunction f, int closure = 0) { lua_pushcclosure(L, f, closure); }
    void push(lua_CPPFunction f);
    void push(void* p) { lua_pushlightuserdata(L, p); }
    void pushGlobalTable() { lua_pushglobaltable(L); }

    // FixedPoint operations
    void push(FixedPoint<> fp);
    FixedPoint<> toFixedPoint(int idx);
    bool isFixedPoint(int idx);
    FixedPoint<> checkFixedPoint(int idx);
    FixedPoint<> optFixedPoint(int idx, FixedPoint<> def = {});

    // Get values
    bool toBoolean(int idx) { return lua_toboolean(L, idx); }
    lua_Number toNumber(int idx, bool* isnum = nullptr);
    const char* toString(int idx, size_t* len = nullptr) { return lua_tolstring(L, idx, len); }
    size_t rawLen(int idx) { return lua_rawlen(L, idx); }
    lua_CFunction toCFunction(int idx) { return lua_tocfunction(L, idx); }
    template <typename T = void>
    T* toUserdata(int idx) {
        return reinterpret_cast<T*>(lua_touserdata(L, idx));
    }
    lua_State* toThread(int idx) { return lua_tothread(L, idx); }
    const void* toPointer(int idx) { return lua_topointer(L, idx); }

    // Type checking
    int type(int idx) { return lua_type(L, idx); }
    const char* typeName(int tp) { return lua_typename(L, tp); }
    bool isNil(int idx) { return lua_isnil(L, idx); }
    bool isNone(int idx) { return lua_isnone(L, idx); }
    bool isNoneOrNil(int idx) { return lua_isnoneornil(L, idx); }
    bool isBoolean(int idx) { return lua_isboolean(L, idx); }
    bool isNumber(int idx) { return lua_isnumber(L, idx); }
    bool isString(int idx) { return lua_isstring(L, idx); }
    bool isTable(int idx) { return lua_istable(L, idx); }
    bool isFunction(int idx) { return lua_isfunction(L, idx); }
    bool isCFunction(int idx) { return lua_iscfunction(L, idx); }
    bool isUserdata(int idx) { return lua_isuserdata(L, idx); }
    bool isLightUserdata(int idx) { return lua_islightuserdata(L, idx); }
    bool isThread(int idx) { return lua_isthread(L, idx); }

    // Table operations
    void newTable() { lua_newtable(L); }
    void createTable(int narr, int nrec) { lua_createtable(L, narr, nrec); }
    void getTable(int idx) { lua_gettable(L, idx); }
    void getField(int idx, const char* k) { lua_getfield(L, idx, k); }
    void getGlobal(const char* name) { lua_getglobal(L, name); }
    void setTable(int idx) { lua_settable(L, idx); }
    void setField(int idx, const char* k) { lua_setfield(L, idx, k); }
    void setGlobal(const char* name) { lua_setglobal(L, name); }
    void rawGet(int idx) { lua_rawget(L, idx); }
    void rawGetI(int idx, int n) { lua_rawgeti(L, idx, n); }
    void rawGetP(int idx, const void* p) { lua_rawgetp(L, idx, p); }
    void rawSet(int idx) { lua_rawset(L, idx); }
    void rawSetI(int idx, int n) { lua_rawseti(L, idx, n); }
    void rawSetP(int idx, const void* p) { lua_rawsetp(L, idx, p); }
    int next(int idx) { return lua_next(L, idx); }

    // Metatable operations
    int newMetatable(const char* tname) { return luaL_newmetatable(L, tname); }
    void getMetatable(const char* tname) { luaL_getmetatable(L, tname); }
    int getMetatable(int objindex) { return lua_getmetatable(L, objindex); }
    int setMetatable(int objindex) { return lua_setmetatable(L, objindex); }

    // Function calling
    void call(int nargs, int nresults = LUA_MULTRET) { lua_call(L, nargs, nresults); }
    int pcall(int nargs, int nresults = LUA_MULTRET);

    // Loading and executing
    int loadBuffer(const char* buff, size_t sz, const char* chunkname = nullptr) {
        return luaL_loadbuffer(L, buff, sz, chunkname);
    }
    template <size_t S>
    int loadBuffer(const char (&buff)[S], const char* chunkname = nullptr) {
        return luaL_loadbuffer(L, buff, S - 1, chunkname);
    }

    // Memory management
    void* newUserdata(size_t sz) { return lua_newuserdata(L, sz); }

    // Reference system
    int ref(int t = LUA_REGISTRYINDEX) { return luaL_ref(L, t); }
    void unref(int t, int ref) { return luaL_unref(L, t, ref); }

    // Garbage collection
    int gc(int what, int data = 0) { return lua_gc(L, what, data); }

    // Error handling and helpers
    int error(const char* fmt, ...);
    int argError(int narg, const char* extramsg) { return luaL_argerror(L, narg, extramsg); }
    void checkType(int narg, int t) { luaL_checktype(L, narg, t); }
    void checkAny(int narg) { luaL_checkany(L, narg); }
    lua_Number checkNumber(int narg) { return luaL_checknumber(L, narg); }
    lua_Number optNumber(int narg, lua_Number def) { return luaL_optnumber(L, narg, def); }
    const char* checkString(int narg) { return luaL_checkstring(L, narg); }
    const char* optString(int narg, const char* def) { return luaL_optstring(L, narg, def); }
    const char* checkLString(int narg, size_t* len) { return luaL_checklstring(L, narg, len); }
    const char* optLString(int narg, const char* def, size_t* len) { return luaL_optlstring(L, narg, def, len); }
    void* checkUdata(int narg, const char* tname) { return luaL_checkudata(L, narg, tname); }
    void argCheck(bool cond, int narg, const char* extramsg) { luaL_argcheck(L, cond, narg, extramsg); }
    int checkOption(int narg, const char* def, const char* const lst[]) { return luaL_checkoption(L, narg, def, lst); }
    bool checkBoolean(int narg) {
        luaL_checktype(L, narg, LUA_TBOOLEAN);
        return lua_toboolean(L, narg);
    }
    bool optBoolean(int narg, bool def) { return lua_isnoneornil(L, narg) ? def : lua_toboolean(L, narg); }

    // Debug interface
    int getStack(int level, lua_Debug* ar) { return lua_getstack(L, level, ar); }
    int getInfo(const char* what, lua_Debug* ar) { return lua_getinfo(L, what, ar); }
    const char* getLocal(const lua_Debug* ar, int n) { return lua_getlocal(L, ar, n); }
    const char* setLocal(const lua_Debug* ar, int n) { return lua_setlocal(L, ar, n); }

    // Coroutine functions
    int yield(int nresults) { return lua_yield(L, nresults); }
    int resume(Lua from, int narg) { return lua_resume(L, from.L, narg); }
    int status() { return lua_status(L); }

  private:
    lua_State* L;
    void setupFixedPointMetatable();
    static int traceback(lua_State* L);
};

}  // namespace psyqo
