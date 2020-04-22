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

#include "core/elfloader.h"

#include "core/psxemulator.h"
#include "core/psxmem.h"

bool PCSX::Elf::load(const char *name) {
    m_elf = std::move(elf::elf(elf::create_file_loader(name)));
    if (!m_elf.valid()) return false;
    m_dwarf = std::move(dwarf::dwarf(dwarf::elf::create_loader(m_elf)));
    if (!m_dwarf.valid()) return false;

    auto segs = m_elf.segments();
    for (auto &s : segs) {
        if (s.valid() && (s.get_hdr().type == elf::pt::load)) {
            auto &h = s.get_hdr();
            uint32_t loadAddr = h.vaddr;
            void *dst = PSXM(loadAddr);
            const void *src = s.data();
            size_t size = s.file_size();
            memcpy(dst, src, size);
        }
    }

    auto sections = m_elf.sections();
    for (auto &s : sections) {
        if (s.valid() && s.get_hdr().type == elf::sht::symtab) {
            auto symbols = s.as_symtab();
            for (elf::symtab::iterator it = symbols.begin(); it != symbols.end(); it++) {
                auto sym = *it;
                auto name = sym.get_name();
                if (name.empty()) continue;
                auto data = sym.get_data();
                uint32_t value = data.value;
                if ((data.info != 4) && (value != 0)) m_symbols.insert(std::pair(value, name));
            }
        }
    }

    return true;
}

dwarf::line_table::entry PCSX::Elf::findByAddress(uint32_t pc) const {
    for (auto &cu : m_dwarf.compilation_units()) {
        try {
            if (dwarf::die_pc_range(cu.root()).contains(pc)) {
                auto &lt = cu.get_line_table();
                auto it = lt.find_address(pc);
                if (it != lt.end()) return *it;
            }
        } catch (std::out_of_range &e) {
        }
    }
    return std::move(dwarf::line_table::entry());
}

void PCSX::Elf::mapDies(const dwarf::die &node) const {
    m_dies.insert(std::pair(node.get_section_offset(), node));
    for (auto &child : node) mapDies(child);
}
