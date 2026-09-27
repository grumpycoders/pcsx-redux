/* WASM PROBE SHIM (local, uncommitted). Redux includes "lua.hpp", LuaJIT's
 * lua.hpp includes luajit.h, and luajit.h is GENERATED at build time by
 * third_party/luajit/xmake.lua:115 (minilua host/genversion.lua). The minilua
 * target is guarded on is_arch("x64","x86_64","arm64.*","mips64"), so on wasm32
 * it never runs and the header never exists - which is why 118 files reported
 * "luajit.h file not found" and NOT because those 118 files are each
 * wasm-incompatible. This shim removes that single blocker so the sweep can see
 * the SECOND layer: the actual Lua 5.1 -> 5.4 API deltas. */
#ifndef _LUAJIT_H
#define _LUAJIT_H
#include "lua.h"
#define LUAJIT_VERSION      "LuaJIT 2.1.0-puc-compat-shim"
#define LUAJIT_VERSION_NUM  20100
#define LUAJIT_VERSION_SYM  luaJIT_version_2_1_0
#define LUAJIT_COPYRIGHT    "Copyright (C) 2005-2026 Mike Pall"
#define LUAJIT_URL          "https://luajit.org/"
#define LUAJIT_MODE_OFF     0
#define LUAJIT_MODE_ON      1
#define LUAJIT_MODE_ENGINE  0x0200
/* luaJIT_setmode is supplied by lua51-compat.h as a static inline; declaring
 * it here too produced 117 "static declaration follows non-static declaration". */
#endif
