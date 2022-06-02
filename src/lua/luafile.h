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

#pragma once

#include <stdio.h>

#include "lua/luawrapper.h"
#include "support/file.h"

namespace PCSX {

namespace LuaFFI {

enum SeekWheel {
    WHEEL_SEEK_SET,
    WHEEL_SEEK_CUR,
    WHEEL_SEEK_END,
};

static constexpr inline int wheelConv(enum SeekWheel w) {
    switch (w) {
        case WHEEL_SEEK_SET:
            return SEEK_SET;
        case WHEEL_SEEK_CUR:
            return SEEK_CUR;
        case WHEEL_SEEK_END:
            return SEEK_END;
    }

    return -1;
}

struct LuaFile {
    LuaFile(IO<File> file) : file(file) {}
    IO<File> file;
};

void open_file(Lua);
}  // namespace LuaFFI

}  // namespace PCSX
