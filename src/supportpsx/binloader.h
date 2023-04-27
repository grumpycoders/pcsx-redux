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

#pragma once

#include <stdint.h>

#include <filesystem>
#include <map>
#include <optional>
#include <string>

#include "support/file.h"

namespace PCSX {

namespace BinaryLoader {

enum class Region { UNKNOWN, NTSC, PAL };
struct Info {
    std::optional<Region> region;
    std::optional<uint32_t> pc;
    std::optional<uint32_t> sp;
    std::optional<uint32_t> gp;
};

bool load(IO<File> in, IO<File> dest, Info& info, std::map<uint32_t, std::string>& symbols);

}  // namespace BinaryLoader

}  // namespace PCSX
