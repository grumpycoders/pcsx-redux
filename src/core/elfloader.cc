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
    m_elf = elf::elf(elf::create_file_loader(name));
    if (!m_elf.valid()) return false;
    m_dwarf = dwarf::dwarf(dwarf::elf::create_loader(m_elf));
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
                uint32_t info = data.info;
                uint32_t size = data.size;
                uint32_t value = data.value;
                if ((data.info != 4) && (value != 0)) m_symbols.insert(std::pair(value, name));
            }
        }
    }
    // Compilation units roots are lazily constructions, but they have a fatal flaw:
    // they will grab a reference from within the vector, which will be destroyed.
    // The whole library is pretty fragile with regards to pointer lifespan. So
    // let's keep a permanent copy here, build all the dies, and use it at all times.
    m_cus = m_dwarf.compilation_units();
    for (auto &cu : m_cus) {
        mapDies(cu.root());
    }

    const auto &fdes = m_dwarf.get_fdes();
    std::vector<interval_tree::Interval<uint32_t, dwarf::fde>> intervals;
    for (const auto &fde : fdes) {
        uint32_t begin = fde.initial_location();
        uint32_t end = begin + fde.length() - 1;
        intervals.emplace_back(begin, end, fde);
    }
    m_fdes = std::move(interval_tree::IntervalTree<uint32_t, dwarf::fde>(std::move(intervals)));

    return true;
}

static bool search(const dwarf::die &d, uint32_t pc, std::vector<dwarf::die> &stack) {
    bool found = false;
    for (auto &c : d) {
        if ((found = search(c, pc, stack))) break;
    }
    switch (d.tag) {
        case dwarf::DW_TAG::subprogram:
        case dwarf::DW_TAG::inlined_subroutine:
            try {
                if (found || die_pc_range(d).contains(pc)) {
                    found = true;
                    stack.push_back(d);
                }
            } catch (...) {
            }
            break;
    }
    return found;
};

std::tuple<dwarf::line_table::entry, std::vector<dwarf::die>> PCSX::Elf::findByAddress(uint32_t pc) const {
    dwarf::line_table::entry entry;
    std::vector<dwarf::die> stack;

    for (auto &cu : m_cus) {
        try {
            if (dwarf::die_pc_range(cu.root()).contains(pc)) {
                auto &lt = cu.get_line_table();
                auto it = lt.find_address(pc);
                if (it != lt.end()) entry = *it;
                search(cu.root(), pc, stack);
            }
        } catch (std::out_of_range &e) {
        }
    }
    return std::tie(entry, stack);
}

void PCSX::Elf::mapDies(const dwarf::die &node) {
    m_dies.insert(std::pair(node.get_section_offset(), node));
    for (auto &child : node) mapDies(child);
}

const dwarf::fde PCSX::Elf::findFDE(uint32_t pc) const {
    auto f = m_fdes.findOverlapping(pc, pc);
    if (f.size()) return f[0].value;
    return dwarf::fde();
}
