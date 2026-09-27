/* WASM PROBE SHIM: PUC-Lua ships no lua.hpp; LuaJIT's includes luajit.h. */
extern "C" {
#include "lauxlib.h"
#include "lua.h"
#include "luajit.h"
#include "lualib.h"
#include "lua51-compat.h"
}
