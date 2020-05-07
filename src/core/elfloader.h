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
#include <tuple>

#include "dwarf++.hh"
#include "elf++.hh"

#include "interval_tree.h"

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

    std::tuple<dwarf::line_table::entry, std::vector<dwarf::die>> findByAddress(uint32_t pc) const;

    const std::map<uint32_t, std::string>& getSymbols() const { return m_symbols; }
    const elf::elf getElf() const { return m_elf; }
    const std::map<dwarf::section_offset, dwarf::die>& getDies() const { return m_dies; }
    const std::vector<dwarf::compilation_unit>& getCUs() const { return m_cus; }
    const dwarf::fde findFDE(uint32_t pc) const;

  private:
    elf::elf m_elf;
    dwarf::dwarf m_dwarf;
    std::map<uint32_t, std::string> m_symbols;
    std::map<dwarf::section_offset, dwarf::die> m_dies;
    std::vector<dwarf::compilation_unit> m_cus;
    interval_tree::IntervalTree<uint32_t, dwarf::fde> m_fdes;

    void mapDies(const dwarf::die&);
};  // namespace PCSX

}  // namespace PCSX
