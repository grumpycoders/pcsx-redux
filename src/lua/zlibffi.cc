/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

#include "lua/zlibffi.h"

#include <zlib.h>

#include "lua/luawrapper.h"

template <typename T, size_t S>
static void registerSymbol(PCSX::Lua L, const char (&name)[S], const T ptr) {
    L.push<S>(name);
    L.push((void*)ptr);
    L.settable();
}

#define REGISTER(L, s) registerSymbol(L, #s, s)

static void registerAllSymbols(PCSX::Lua L) {
    L.push("_CLIBS");
    L.gettable(LUA_REGISTRYINDEX);
    if (L.isnil()) {
        L.pop();
        L.newtable();
        L.push("_CLIBS");
        L.copy(-2);
        L.settable(LUA_REGISTRYINDEX);
    }
    L.push("z");
    L.newtable();
    REGISTER(L, zlibVersion);
    REGISTER(L, deflate);
    REGISTER(L, deflateEnd);
    REGISTER(L, inflate);
    REGISTER(L, inflateEnd);
    REGISTER(L, deflateSetDictionary);
    REGISTER(L, deflateGetDictionary);
    REGISTER(L, deflateCopy);
    REGISTER(L, deflateReset);
    REGISTER(L, deflateParams);
    REGISTER(L, deflateTune);
    REGISTER(L, deflateBound);
    REGISTER(L, deflatePending);
    REGISTER(L, deflatePrime);
    REGISTER(L, deflateSetHeader);
    REGISTER(L, inflateSetDictionary);
    REGISTER(L, inflateGetDictionary);
    REGISTER(L, inflateSync);
    REGISTER(L, inflateCopy);
    REGISTER(L, inflateReset);
    REGISTER(L, inflateReset2);
    REGISTER(L, inflatePrime);
    REGISTER(L, inflateMark);
    REGISTER(L, inflateGetHeader);
    REGISTER(L, inflateBack);
    REGISTER(L, inflateBackEnd);
    REGISTER(L, zlibCompileFlags);
    REGISTER(L, compress);
    REGISTER(L, compress2);
    REGISTER(L, compressBound);
    REGISTER(L, uncompress);
    REGISTER(L, uncompress2);
    REGISTER(L, gzopen);
    REGISTER(L, gzdopen);
    REGISTER(L, gzbuffer);
    REGISTER(L, gzsetparams);
    REGISTER(L, gzread);
    REGISTER(L, gzfread);
    REGISTER(L, gzwrite);
    REGISTER(L, gzfwrite);
    REGISTER(L, gzprintf);
    REGISTER(L, gzvprintf);
    REGISTER(L, gzputs);
    REGISTER(L, gzgets);
    REGISTER(L, gzputc);
    REGISTER(L, gzgetc);
    REGISTER(L, gzungetc);
    REGISTER(L, gzflush);
    REGISTER(L, gzseek);
    REGISTER(L, gzrewind);
    REGISTER(L, gztell);
    REGISTER(L, gzoffset);
    REGISTER(L, gzeof);
    REGISTER(L, gzdirect);
    REGISTER(L, gzclose);
    REGISTER(L, gzclose_r);
    REGISTER(L, gzclose_w);
    REGISTER(L, gzerror);
    REGISTER(L, gzclearerr);
    //    REGISTER(L, gzopen64);
    //    REGISTER(L, gzseek64);
    //    REGISTER(L, gztell64);
    //    REGISTER(L, gzoffset64);
    //    REGISTER(L, adler32_combine64);
    //    REGISTER(L, crc32_combine64);
    REGISTER(L, adler32);
    REGISTER(L, adler32_z);
    REGISTER(L, crc32);
    REGISTER(L, crc32_z);
    REGISTER(L, adler32_combine);
    REGISTER(L, crc32_combine);
    REGISTER(L, deflateInit_);
    REGISTER(L, deflateInit2_);
    REGISTER(L, inflateInit_);
    REGISTER(L, inflateInit2_);
    REGISTER(L, inflateBackInit_);
    REGISTER(L, gzgetc_);
    REGISTER(L, zError);
    REGISTER(L, inflateSyncPoint);
    REGISTER(L, get_crc_table);
    REGISTER(L, inflateUndermine);
    REGISTER(L, inflateValidate);
    REGISTER(L, inflateCodesUsed);
    REGISTER(L, inflateResetKeep);
    REGISTER(L, deflateResetKeep);
    //    REGISTER(L, gzopen_w);
    L.settable();
    L.pop();
}

void PCSX::LuaFFI::open_zlib(Lua L) {
    static int lualoader = 1;
    static const char* zlibFFI = (
#include "third_party/zlibffi/zlibffi.lua"
    );
    registerAllSymbols(L);
    L.load(zlibFFI, "internal:third_party/zlibffi/zlibffi.lua");
}
