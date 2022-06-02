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

#include "lua/extra.h"

#include "lua/luawrapper.h"

void PCSX::LuaFFI::open_extra(Lua L) {
    static int lualoader = 1;
    static const char* pprint = (
#include "pprint.lua/pprint.lua"
    );
    static const char* reflectFFI = (
#include "ffi-reflect/reflect.lua"
    );
    L.load(pprint, "internal:pprinter.lua/pprint.lua");
    L.load(reflectFFI, "internal:ffi-reflect/reflect.lua");
}
