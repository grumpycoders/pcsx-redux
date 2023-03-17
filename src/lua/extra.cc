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

#include "lua-protobuf/pb.h"
#include "lua/luawrapper.h"

void PCSX::LuaFFI::open_extra(Lua L) {
    L.getfieldtable("_LOADED", LUA_REGISTRYINDEX);
    luaopen_pb(L.getState());
    L.setfield("pb", -3);
    L.pop();
    luaopen_pb_io(L.getState());
    L.setfield("pb.io");
    luaopen_pb_conv(L.getState());
    L.setfield("pb.conv");
    luaopen_pb_slice(L.getState());
    L.setfield("pb.slice");
    luaopen_pb_buffer(L.getState());
    L.setfield("pb.buffer");
    luaopen_pb_unsafe(L.getState());
    L.setfield("pb.unsafe");

    static int lualoader = 1;
    static const char* pprint = (
#include "pprint.lua/pprint.lua"
    );
    static const char* reflectFFI = (
#include "ffi-reflect/reflect.lua"
    );
    static const char* protobufLexer = (
#include "lua-protobuf/lexer.lua"
    );
    static const char* protobufTopLevel = (
#include "lua-protobuf/toplevel.lua"
    );
    static const char* descriptorPB = (
#include "lua-protobuf/descriptor.pb.lua"
    );
    static const char* protoc = (
#include "lua-protobuf/protoc.lua"
    );
    L.load(pprint, "internal:pprinter.lua/pprint.lua");
    L.load(reflectFFI, "internal:ffi-reflect/reflect.lua");

    L.load(protobufLexer, "internal:lua-protobuf/lexer.lua");
    L.setfield("pb.Lexer");

    L.load(protobufTopLevel, "internal:lua-protobuf/toplevel.lua");
    L.setfield("pb.TopLevel");

    L.load(descriptorPB, "internal:lua-protobuf/descriptor.pb.lua");
    L.setfield("pb.Descriptor");

    L.load(protoc, "internal:lua-protobuf/protoc.lua");
    L.setfield("protoc");

    L.pop();
}
