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

#include "supportpsx/binlua.h"

#include <stdint.h>

#include <vector>

#include "lua/luafile.h"
#include "lua/luawrapper.h"
#include "supportpsx/binloader.h"
#include "supportpsx/n2e-d.h"
#include "supportpsx/ps1-packer.h"
#include "ucl/ucl.h"

namespace {

struct BinaryLoaderInfo {
    PCSX::BinaryLoader::Region region;
    uint32_t pc;
    uint32_t sp;
    uint32_t gp;
};

bool binaryLoaderLoad(PCSX::LuaFFI::LuaFile* src, PCSX::LuaFFI::LuaFile* dest, BinaryLoaderInfo* info) {
    PCSX::BinaryLoader::Info i;
    info->region = PCSX::BinaryLoader::Region::UNKNOWN;
    info->pc = 0;
    info->sp = 0;
    info->gp = 0;
    bool ret = PCSX::BinaryLoader::load(src->file, dest->file, i);
    if (ret) {
        info->region = i.region.value_or(PCSX::BinaryLoader::Region::UNKNOWN);
        info->pc = i.pc.value_or(0);
        info->sp = i.sp.value_or(0);
        info->gp = i.gp.value_or(0);
    }
    return ret;
}

void ps1PackerPack(PCSX::LuaFFI::LuaFile* src, PCSX::LuaFFI::LuaFile* dest, uint32_t addr, uint32_t pc, uint32_t gp,
                   uint32_t sp, PCSX::PS1Packer::Options options) {
    PCSX::PS1Packer::pack(src->file, dest->file, addr, pc, gp, sp, options);
}

uint32_t uclPack(PCSX::LuaFFI::LuaFile* src, PCSX::LuaFFI::LuaFile* dest) {
    std::vector<uint8_t> dataIn;
    dataIn.resize(src->file->size());
    src->file->read(dataIn.data(), dataIn.size());

    std::vector<uint8_t> dataOut;
    dataOut.resize(dataIn.size() * 1.2 + 2048);
    ucl_uint outSize;
    int r;

    r = ucl_nrv2e_99_compress(dataIn.data(), dataIn.size(), dataOut.data(), &outSize, nullptr, 10, nullptr, nullptr);
    if (r != UCL_E_OK) {
        throw std::runtime_error("Fatal error during data compression.\n");
    }
    dataOut.resize(outSize);
    dest->file->write(dataOut.data(), outSize);

    return outSize;
}

uint32_t writeUclDecomp(PCSX::LuaFFI::LuaFile* dest) {
    dest->file->write(n2e_d::code, sizeof(n2e_d::code));
    return sizeof(n2e_d::code);
}

template <typename T, size_t S>
void registerSymbol(PCSX::Lua L, const char (&name)[S], const T ptr) {
    L.push<S>(name);
    L.push((void*)ptr);
    L.settable();
}

#define REGISTER(L, s) registerSymbol(L, #s, s)

void registerAllSymbols(PCSX::Lua L) {
    L.getfieldtable("_CLIBS", LUA_REGISTRYINDEX);
    L.push("SUPPORTPSX_BINARY");
    L.newtable();
    REGISTER(L, binaryLoaderLoad);
    REGISTER(L, ps1PackerPack);
    REGISTER(L, uclPack);
    REGISTER(L, writeUclDecomp);
    L.settable();
    L.pop();
}

}  // namespace

void PCSX::LuaSupportPSX::open_binaries(Lua L) {
    static int lualoader = 1;
    static const char* binffi = (
#include "supportpsx/binffi.lua"
    );
    registerAllSymbols(L);
    L.load(binffi, "internal:supportpsx/binffi.lua");
}
