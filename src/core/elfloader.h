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
#include <string>

#include "dwarf++.hh"
#include "elf++.hh"

namespace PCSX {

class Elf {
  public:
    bool load(const char* name);
#if defined(__cpp_lib_char8_t)
    bool load(const std::u8string& filename) {
        return load(reinterpret_cast<const char*>(filename.c_str());
    }
#endif
    bool load(const std::string& filename) { return load(filename.c_str()); }

    dwarf::line_table::entry findByAddress(uint32_t pc);

    const std::map<uint32_t, std::string>& getSymbols() { return m_symbols; }

  private:
    elf::elf m_elf;
    dwarf::dwarf m_dwarf;
    std::map<uint32_t, std::string> m_symbols;
};

}  // namespace PCSX
