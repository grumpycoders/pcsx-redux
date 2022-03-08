/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include "lua/luafile.h"

#include "lua/luawrapper.h"
#include "support/file.h"

namespace {

struct LuaBreakpoint {
    PCSX::IO<PCSX::File> wrapper;
};

enum FileOps {
    READ,
    TRUNCATE,
    CREATE,
    READWRITE,
};

}  // namespace

template <typename T, size_t S>
static void registerSymbol(PCSX::Lua* L, const char (&name)[S], const T ptr) {
    L->push<S>(name);
    L->push((void*)ptr);
    L->settable();
}

#define REGISTER(L, s) registerSymbol(L, #s, s)

static void registerAllSymbols(PCSX::Lua* L) {
    L->push("_CLIBS");
    L->gettable(LUA_REGISTRYINDEX);
    if (L->isnil()) {
        L->pop();
        L->newtable();
        L->push("_CLIBS");
        L->copy(-2);
        L->settable(LUA_REGISTRYINDEX);
    }
    L->push("SUPPORTFILE");
    L->newtable();
    L->settable();
    L->pop();
}

void PCSX::LuaFFI::open_file(Lua* L) {
    static int lualoader = 1;
    static const char* pcsxFFI = (
#include "lua/fileffi.lua"
    );
    registerAllSymbols(L);
    L->load(pcsxFFI, "internal:lua/fileffi.lua");
}
