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

#pragma once

#include <optional>

#include "support/file.h"

namespace PCSX {

namespace PS1Packer {

struct Options {
    uint32_t tload = 0;
    bool shell = false;
    bool booty = false;
    bool raw = false;
    bool rom = false;
    bool cpe = false;
};

void pack(IO<File> src, IO<File> dest, uint32_t addr, uint32_t pc, uint32_t gp, uint32_t sp, const Options &);

}  // namespace PS1Packer

}  // namespace PCSX
