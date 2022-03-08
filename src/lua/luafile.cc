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
#include "support/uvfile.h"

namespace {

struct LuaFile {
    LuaFile(PCSX::IO<PCSX::File> file) : file(file) {}
    PCSX::IO<PCSX::File> file;
};

enum FileOps {
    READ,
    TRUNCATE,
    CREATE,
    READWRITE,
};

void deleteFile(LuaFile* wrapper) { delete wrapper; }

LuaFile* openFile(const char* filename, FileOps type) {
    switch (type) {
        case READ:
            return new LuaFile(new PCSX::UvFile(filename));
        case TRUNCATE:
            return new LuaFile(new PCSX::UvFile(filename, PCSX::FileOps::TRUNCATE));
        case CREATE:
            return new LuaFile(new PCSX::UvFile(filename, PCSX::FileOps::CREATE));
        case READWRITE:
            return new LuaFile(new PCSX::UvFile(filename, PCSX::FileOps::READWRITE));
    }
}
void closeFile(LuaFile* wrapper) { wrapper->file->close(); }

uint32_t readFileRawPtr(LuaFile* wrapper, void* dst, uint32_t size) { return wrapper->file->read(dst, size); }
uint32_t readFileBuffer(LuaFile* wrapper, void* buffer) {
    uint32_t* pSize = reinterpret_cast<uint32_t*>(buffer);
    uint8_t* data = reinterpret_cast<uint8_t*>(pSize + 1);
    return *pSize = wrapper->file->read(data, *pSize);
}

uint32_t writeFileRawPtr(LuaFile* wrapper, const const uint8_t* data, uint32_t size) {
    return wrapper->file->write(data, size);
}
uint32_t writeFileBuffer(LuaFile* wrapper, const void* buffer) {
    const uint32_t* pSize = reinterpret_cast<const uint32_t*>(buffer);
    const uint8_t* data = reinterpret_cast<const uint8_t*>(pSize + 1);
    return wrapper->file->write(data, *pSize);
}

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
    L->push("SUPPORT_FILE");
    L->newtable();

    REGISTER(L, deleteFile);

    REGISTER(L, openFile);
    REGISTER(L, closeFile);

    REGISTER(L, readFileRawPtr);
    REGISTER(L, readFileBuffer);
    REGISTER(L, writeFileRawPtr);
    REGISTER(L, writeFileBuffer);
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
