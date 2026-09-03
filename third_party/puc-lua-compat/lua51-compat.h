/* Lua 5.1 -> 5.4 compat shim for Redux's host layer.  WASM PROBE, local.
 *
 * Design choice, and it is the whole point: Redux's Lua CALL SITES do not move.
 * Every 5.1-only name the sweep found is defined here in terms of 5.4, so
 * `src/lua/luawrapper.h` and its ~116 dependent translation units compile
 * unchanged and the LuaJIT build never sees this file. A wasm Redux is a SECOND
 * Lua backend, not a migration off LuaJIT.
 *
 * The measured surface this covers (whole-tree -fsyntax-only sweep, 2026-09-02):
 *   LUA_GLOBALSINDEX  464 occurrences in luawrapper.h + 9 outside it
 *   lua_objlen        116 (i.e. once in luawrapper.h, x116 TUs)
 *   luaL_openlib      116
 *   lua_getfenv       116
 *   lua_setfenv       116  (+116 "cannot initialize return object of type
 *                           'int' with an rvalue of type 'void'", same line)
 *   lua_open, luaopen_bit/ffi/jit, LUAJIT_MODE_WRAPCFUNC, lua_resume  1 each
 */
#ifndef PCSX_LUA51_COMPAT_H
#define PCSX_LUA51_COMPAT_H

#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"

/* ---- LUA_GLOBALSINDEX --------------------------------------------------
 * 5.2 removed the pseudo-index. The sentinel must sit OUTSIDE the range
 * Lua::getabsolute() treats as relative - it tests
 *     (index < 0) && (index > LUA_REGISTRYINDEX)
 * so anything <= LUA_REGISTRYINDEX passes through untouched, which is exactly
 * how the real -10002 behaved against 5.1's -10000. A small negative sentinel
 * would silently be rewritten as a stack offset. That comparison is the one
 * landmine in this whole port.
 */
#define LUA_GLOBALSINDEX (LUA_REGISTRYINDEX - 1)

/* Push the globals table and return its absolute stack index, so a caller can
 * feed a real index to the 5.4 API. */
static inline int pcsx_compat_pushglobals(lua_State *L) {
    lua_pushglobaltable(L);
    return lua_gettop(L);
}

/* ⛔ THE PREVIOUS VERSION OF THIS BLOCK WAS A MACRO THAT WAS NEVER INSTANTIATED.
 * PCSX_COMPAT_TABLEOP was defined and then used nowhere, so every
 * lua_gettable/lua_settable/lua_rawgeti/lua_rawseti carrying LUA_GLOBALSINDEX
 * reached real 5.4 with a pseudo-index it does not have. 5.4 resolves that to
 * nil and panics: "unprotected error in call to Lua API (attempt to index a nil
 * value)" - which is verbatim what the browser reported, twice, once per
 * crt-lottes shader, because shader-editor.cc fetches _G through
 * lua_gettable(L, LUA_GLOBALSINDEX) to build each sandbox's __index.
 *
 * AND ONE MACRO COULD NOT HAVE SERVED THEM ANYWAY: these ops pop different
 * numbers of values (gettable 1, settable 2, rawgeti 0, rawseti 1), so the
 * insert position and the index arithmetic differ per op. Written out
 * individually below, each verified against real PUC-Lua for net stack delta,
 * result type, and an untouched guard value underneath.
 *
 * Each #define comes AFTER the function that implements it, so the call inside
 * the body is the real 5.4 API rather than a recursive expansion.
 */

/* [.., key] -> [.., value] */
static inline void pcsx_compat_gettable(lua_State *L, int idx) {
    if (idx != LUA_GLOBALSINDEX) { lua_gettable(L, idx); return; }
    lua_pushglobaltable(L);   /* [.., key, G] */
    lua_insert(L, -2);        /* [.., G, key] */
    lua_gettable(L, -2);      /* [.., G, value] */
    lua_remove(L, -2);        /* [.., value] */
}

/* [.., key, value] -> [..] */
static inline void pcsx_compat_settable(lua_State *L, int idx) {
    if (idx != LUA_GLOBALSINDEX) { lua_settable(L, idx); return; }
    lua_pushglobaltable(L);   /* [.., key, value, G] */
    lua_insert(L, -3);        /* [.., G, key, value] */
    lua_settable(L, -3);      /* [.., G] */
    lua_pop(L, 1);            /* [..] */
}

/* [..] -> [.., value] */
static inline void pcsx_compat_rawgeti(lua_State *L, int idx, lua_Integer n) {
    if (idx != LUA_GLOBALSINDEX) { lua_rawgeti(L, idx, n); return; }
    lua_pushglobaltable(L);
    lua_rawgeti(L, -1, n);    /* [.., G, value] */
    lua_remove(L, -2);        /* [.., value] */
}

/* [.., value] -> [..] */
static inline void pcsx_compat_rawseti(lua_State *L, int idx, lua_Integer n) {
    if (idx != LUA_GLOBALSINDEX) { lua_rawseti(L, idx, n); return; }
    lua_pushglobaltable(L);   /* [.., value, G] */
    lua_insert(L, -2);        /* [.., G, value] */
    lua_rawseti(L, -2, n);    /* [.., G] */
    lua_pop(L, 1);            /* [..] */
}

#define lua_gettable pcsx_compat_gettable
#define lua_settable pcsx_compat_settable
#define lua_rawgeti  pcsx_compat_rawgeti
#define lua_rawseti  pcsx_compat_rawseti

/* ---- names 5.2+ renamed or dropped ------------------------------------- */
#define lua_objlen(L, i) lua_rawlen((L), (i))
#define lua_open()       luaL_newstate()
#define lua_strlen(L, i) lua_rawlen((L), (i))

/* 5.1's luaL_openlib(L, name, l, nup): with a name it creates/finds the global
 * table; with NULL it sets the functions into the table at the top. */
static inline void luaL_openlib(lua_State *L, const char *libname,
                                const luaL_Reg *l, int nup) {
    if (libname) {
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setglobal(L, libname);
        lua_insert(L, -(nup + 2));
    }
    luaL_setfuncs(L, l, nup);
    if (libname) { /* leave the table on top, as 5.1 does */
    }
}

/* ---- getfenv / setfenv -------------------------------------------------
 * 5.2 replaced per-function environments with the _ENV upvalue. For a Lua
 * closure that is upvalue 1 whenever the function references any global -
 * MEASURED true for both crt-lottes shader chunks, and lua_setupvalue returns
 * NULL rather than lying when it is not, so the caller can tell.
 *
 * ⚠ SIGNATURE NOTE: 5.1's lua_setfenv returns int (0 on failure), and
 * luawrapper.h:240 does `return lua_setfenv(L, index);`. That is the source of
 * the 116 "cannot initialize return object of type 'int' with an rvalue of type
 * 'void'" errors - so this MUST return int, not void, or the call sites move.
 */
static inline int lua_setfenv(lua_State *L, int idx) {
    const char *name = lua_setupvalue(L, idx, 1);
    if (name == NULL) {
        lua_pop(L, 1); /* lua_setupvalue leaves the value on failure */
        return 0;
    }
    return 1;
}

static inline void lua_getfenv(lua_State *L, int idx) {
    if (lua_getupvalue(L, idx, 1) == NULL) lua_pushnil(L);
}

/* ---- SIGNATURE changes, which no identifier grep can see ----------------
 * These are the ones I flagged this morning as invisible to presence-checking:
 * the NAME still exists in 5.4, so nothing reports it missing - only the
 * compiler catches them. Both were found exactly that way.
 *
 * lua_sethook returns int in 5.1 and VOID in 5.4, and luawrapper.h:235 does
 * `int sethook(...) { return lua_sethook(...); }`. That single line is the
 * source of all 116 "cannot initialize return object of type 'int' with an
 * rvalue of type 'void'" - one site, x116 translation units.
 * A function-like macro naming itself expands once and then stops, so this
 * does not recurse.
 */
#define lua_sethook(L, f, m, c) (lua_sethook((L), (f), (m), (c)), 1)

/* 5.1: lua_resume(L, narg).  5.4: lua_resume(L, from, nargs, int *nresults).
 * The extra out-parameter is real information 5.1 never had; discarding it here
 * preserves the 5.1 call shape, and any caller that wants the result count has
 * to be ported properly rather than shimmed. */
static inline int pcsx_compat_resume(lua_State *L, int narg) {
    int nres = 0;
    return lua_resume(L, NULL, narg, &nres);
}
#define lua_resume(L, narg) pcsx_compat_resume((L), (narg))

/* ---- LuaJIT-only surface ----------------------------------------------- */
#define LUAJIT_MODE_WRAPCFUNC 0x0100
static inline int luaJIT_setmode(lua_State *L, int idx, int mode) {
    (void)L; (void)idx; (void)mode;
    return 1; /* no JIT to configure; report success so callers proceed */
}

/* `bit` is a LuaJIT extension. Redux uses it at ~57 sites, none in the two
 * shader files, so it is not on the v1 path - but the C-side opener must exist
 * for src/lua to link. A real port supplies LuaBitOp or a ~20-line native shim. */
int luaopen_bit(lua_State *L);
int luaopen_ffi(lua_State *L);
int luaopen_jit(lua_State *L);

#endif /* PCSX_LUA51_COMPAT_H */
