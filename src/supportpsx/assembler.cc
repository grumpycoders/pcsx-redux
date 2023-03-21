/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
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

#include "supportpsx/assembler.h"

#include "lua/luawrapper.h"

void PCSX::LuaSupportPSX::open_assembler(Lua L) {
    static int lualoader = 8;
    static const char* assembler = (
#include "supportpsx/assembler/assembler.lua"
    );
    static const char* registers = (
#include "supportpsx/assembler/registers.lua"
    );
    static const char* simple = (
#include "supportpsx/assembler/simple.lua"
    );
    static const char* loadstore = (
#include "supportpsx/assembler/loadstore.lua"
    );
    static const char* extra = (
#include "supportpsx/assembler/extra.lua"
    );
    static const char* gte = (
#include "supportpsx/assembler/gte.lua"
    );
    static const char* pseudo = (
#include "supportpsx/assembler/pseudo.lua"
    );
    static const char* symbols = (
#include "supportpsx/assembler/symbols.lua"
    );
    L.load(assembler, "internal:supportpsx/assembler/assembler.lua");
    L.load(registers, "internal:supportpsx/assembler/registers.lua");
    L.load(simple, "internal:supportpsx/assembler/simple.lua");
    L.load(loadstore, "internal:supportpsx/assembler/loadstore.lua");
    L.load(extra, "internal:supportpsx/assembler/extra.lua");
    L.load(gte, "internal:supportpsx/assembler/gte.lua");
    L.load(pseudo, "internal:supportpsx/assembler/pseudo.lua");
    L.load(symbols, "internal:supportpsx/assembler/symbols.lua");
}
