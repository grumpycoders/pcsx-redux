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

template <typename T>
static void keepSymbol(PCSX::Lua* L, T ptr) {
    L->push((void*)ptr);
    L->pop();
}

static void keepAllSymbols(PCSX::Lua* L) {
    keepSymbol(L, zlibVersion);
    keepSymbol(L, deflate);
    keepSymbol(L, deflateEnd);
    keepSymbol(L, inflate);
    keepSymbol(L, inflateEnd);
    keepSymbol(L, deflateSetDictionary);
    keepSymbol(L, deflateGetDictionary);
    keepSymbol(L, deflateCopy);
    keepSymbol(L, deflateReset);
    keepSymbol(L, deflateParams);
    keepSymbol(L, deflateTune);
    keepSymbol(L, deflateBound);
    keepSymbol(L, deflatePending);
    keepSymbol(L, deflatePrime);
    keepSymbol(L, deflateSetHeader);
    keepSymbol(L, inflateSetDictionary);
    keepSymbol(L, inflateGetDictionary);
    keepSymbol(L, inflateSync);
    keepSymbol(L, inflateCopy);
    keepSymbol(L, inflateReset);
    keepSymbol(L, inflateReset2);
    keepSymbol(L, inflatePrime);
    keepSymbol(L, inflateMark);
    keepSymbol(L, inflateGetHeader);
    keepSymbol(L, inflateBack);
    keepSymbol(L, inflateBackEnd);
    keepSymbol(L, zlibCompileFlags);
    keepSymbol(L, compress);
    keepSymbol(L, compress2);
    keepSymbol(L, compressBound);
    keepSymbol(L, uncompress);
    keepSymbol(L, uncompress2);
    keepSymbol(L, gzopen);
    keepSymbol(L, gzdopen);
    keepSymbol(L, gzbuffer);
    keepSymbol(L, gzsetparams);
    keepSymbol(L, gzread);
    keepSymbol(L, gzfread);
    keepSymbol(L, gzwrite);
    keepSymbol(L, gzfwrite);
    keepSymbol(L, gzprintf);
    keepSymbol(L, gzvprintf);
    keepSymbol(L, gzputs);
    keepSymbol(L, gzgets);
    keepSymbol(L, gzputc);
    keepSymbol(L, gzgetc);
    keepSymbol(L, gzungetc);
    keepSymbol(L, gzflush);
    keepSymbol(L, gzseek);
    keepSymbol(L, gzrewind);
    keepSymbol(L, gztell);
    keepSymbol(L, gzoffset);
    keepSymbol(L, gzeof);
    keepSymbol(L, gzdirect);
    keepSymbol(L, gzclose);
    keepSymbol(L, gzclose_r);
    keepSymbol(L, gzclose_w);
    keepSymbol(L, gzerror);
    keepSymbol(L, gzclearerr);
    //    keepSymbol(L, gzopen64);
    //    keepSymbol(L, gzseek64);
    //    keepSymbol(L, gztell64);
    //    keepSymbol(L, gzoffset64);
    //    keepSymbol(L, adler32_combine64);
    //    keepSymbol(L, crc32_combine64);
    keepSymbol(L, adler32);
    keepSymbol(L, adler32_z);
    keepSymbol(L, crc32);
    keepSymbol(L, crc32_z);
    keepSymbol(L, adler32_combine);
    keepSymbol(L, crc32_combine);
    keepSymbol(L, deflateInit_);
    keepSymbol(L, deflateInit2_);
    keepSymbol(L, inflateInit_);
    keepSymbol(L, inflateInit2_);
    keepSymbol(L, inflateBackInit_);
    keepSymbol(L, gzgetc_);
    keepSymbol(L, zError);
    keepSymbol(L, inflateSyncPoint);
    keepSymbol(L, get_crc_table);
    keepSymbol(L, inflateUndermine);
    keepSymbol(L, inflateValidate);
    keepSymbol(L, inflateCodesUsed);
    keepSymbol(L, inflateResetKeep);
    keepSymbol(L, deflateResetKeep);
    keepSymbol(L, gzopen_w);
}

void PCSX::LuaFFI::open_zlib(Lua* L) {
    static int lualoader = 1;
    static const char* zlibFFI = (
#include "lua/zlibffi.lua"
    );
    L->load(zlibFFI, "internal:lua/zlibffi.lua");
    keepAllSymbols(L);
}
