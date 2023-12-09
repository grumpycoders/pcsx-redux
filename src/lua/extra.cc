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

#include <filesystem>
#include <string_view>
#include <vector>

#include "lua-protobuf/pb.h"
#include "lua/luafile.h"
#include "lua/luawrapper.h"
#include "support/file.h"
#include "support/strings-helpers.h"
#include "support/zip.h"

namespace {

std::vector<PCSX::ZipArchive> s_archives;
PCSX::File* load(std::string_view name, std::string_view from, bool inArchives = true) {
    bool doRelative = false;
    if (!from.empty() && (from[0] == '@')) {
        from = from.substr(1);
        doRelative = true;
    }
    std::filesystem::path fromPath(from);
    std::filesystem::path absolutePath(name);
    std::filesystem::path relativePath(fromPath.parent_path() / name);
    relativePath = std::filesystem::weakly_canonical(relativePath);

    PCSX::File* file = nullptr;

    if (inArchives) {
        for (auto archivei = s_archives.rbegin(); archivei != s_archives.rend(); archivei++) {
            auto& archive = *archivei;
            if (doRelative) {
                file = archive.openFile(relativePath.string());
                if (!file->failed()) return file;
                delete file;
            }
            file = archive.openFile(absolutePath.string());
            if (!file->failed()) return file;
            delete file;
        }
    } else {
        for (auto archivei = s_archives.rbegin(); archivei != s_archives.rend(); archivei++) {
            auto& archive = *archivei;
            std::filesystem::path fromPath(from);
            std::filesystem::path relativePath(archive.archiveFilename().parent_path() / name);
            relativePath = std::filesystem::weakly_canonical(relativePath);
            file = archive.openFile(relativePath.string());
            if (!file->failed()) return file;
            delete file;
            file = archive.openFile(absolutePath.string());
            if (!file->failed()) return file;
            delete file;
        }
    }

    if (doRelative) {
        file = new PCSX::PosixFile(relativePath);
        if (!file->failed()) return file;
        delete file;
    }
    return new PCSX::PosixFile(absolutePath);
}

}  // namespace

PCSX::ZipArchive& PCSX::LuaFFI::addArchive(Lua L, IO<File> file) {
    auto& newArchive = s_archives.emplace_back(file);
    if (newArchive.failed()) {
        s_archives.pop_back();
        throw std::runtime_error("Invalid zip file");
    }
    IO<File> autoexec = newArchive.openFile("autoexec.lua");
    if (!autoexec->failed()) {
        std::string code = autoexec->readString(autoexec->size());
        L.load(code, fmt::format("{}:@autoexec.lua", file->filename().string()).c_str());
    }
    return newArchive;
}

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

    static int lualoader = 7;
    static const char* pprint = (
#include "pprint.lua/pprint.lua"
    );
    static const char* pprint_internals = (
#include "pprint.lua/pprint-internals.lua"
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
    L.load(pprint_internals, "internal:pprinter.lua/pprint-internals.lua");
    L.load(reflectFFI, "internal:ffi-reflect/reflect.lua");

    L.load(protobufLexer, "internal:lua-protobuf/lexer.lua");
    L.setfield("pb.Lexer");

    L.load(protobufTopLevel, "internal:lua-protobuf/toplevel.lua");
    L.setfield("pb.TopLevel");

    L.load(descriptorPB, "internal:lua-protobuf/descriptor.pb.lua");
    L.setfield("pb.Descriptor");

    L.load(protoc, "internal:lua-protobuf/protoc.lua");
    L.setfield("protoc");

    L.load(R"(
Support.extra = {

loadfile = function(name)
    return loadstring(Support._internal.loadfile(name), '@' .. name)
end,

dofile = function(name)
    local func, msg = loadstring(Support._internal.loadfile(name), '@' .. name)
    if func then return func() end
    error(msg)
end,
}

Support.extra.open = function(name)
    return Support.File._createFileWrapper(ffi.cast('LuaFile*', Support._internal.open(name)))
end
)",
           "internal:extra.lua");

    L.getfieldtable("Support", LUA_GLOBALSINDEX);
    L.getfieldtable("extra");
    L.declareFunc(
        "addArchive",
        [](lua_State* L_) -> int {
            Lua L(L_);
            auto ar = L.getinfo("S");
            auto name = L.tostring();
            IO<File> file = load(name, ar.has_value() ? ar->source : "");
            if (file->failed()) return L.error("Unable to locate archive file");
            addArchive(L, file);
            return 0;
        },
        -1);
    L.pop();
    L.getfieldtable("_internal");
    L.declareFunc(
        "open",
        [](lua_State* L_) -> int {
            Lua L(L_);
            auto ar = L.getinfo("S", 1);
            auto name = L.tostring();
            IO<File> file = load(name, ar.has_value() ? ar->source : "");
            L.push(new LuaFile(file));
            return 1;
        },
        -1);
    L.declareFunc(
        "loadfile",
        [](lua_State* L_) -> int {
            Lua L(L_);
            auto ar = L.getinfo("S", 2);
            auto name = L.tostring();
            IO<File> file = load(name, ar.has_value() ? ar->source : "");
            if (file->failed()) return L.error("Unable to locate file");
            L.push(file->readString(file->size()));
            return 1;
        },
        -1);
    L.pop();
    L.pop();

    L.pop();
}
