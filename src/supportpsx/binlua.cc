/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

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
    std::map<uint32_t, std::string> symbols;
    info->region = PCSX::BinaryLoader::Region::UNKNOWN;
    info->pc = 0;
    info->sp = 0;
    info->gp = 0;
    bool ret = PCSX::BinaryLoader::load(src->file, dest->file, i, symbols);
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
