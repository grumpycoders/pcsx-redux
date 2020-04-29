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

#include "core/stacktrace.h"

#include "core/psxemulator.h"
#include "core/psxmem.h"

static void computeStacktraceRec(std::vector<PCSX::Stacktrace::Element>& ret, PCSX::Memory* mem, uint32_t pc,
                                 uint32_t sp, uint32_t ra = 0) {
    for (const auto& e : mem->getElves()) {
        // let's see if we have line information for this pc
        auto [entry, stack] = e.findByAddress(pc);
        if (!entry.valid()) continue;
        // yes ? let's add what we have to the callstack.
        // first, let's put our line table entry.
        ret.emplace_back(PCSX::Stacktrace::Element{entry.file->path, int(entry.line), pc, sp});
        // then, if we have inlined subroutines, let's grab their call sites to have a better view of
        // where they came from.
        for (auto& s : stack) {
            switch (s.tag) {
                case dwarf::DW_TAG::inlined_subroutine: {
                    // we're supposed to have call_file and call_line
                    if (!s.has(dwarf::DW_AT::call_file) || !s.has(dwarf::DW_AT::call_line)) break;
                    auto lt = dynamic_cast<const dwarf::compilation_unit*>(&s.get_unit())->get_line_table();
                    auto pathIndex = s[dwarf::DW_AT::call_file].as_sconstant();
                    std::filesystem::path path = lt.get_file(pathIndex)->path;
                    // does our CU have a comp_dir ?
                    auto root = s.get_unit().root();
                    if (root.has(dwarf::DW_AT::comp_dir)) path = root[dwarf::DW_AT::comp_dir].as_string() / path;
                    ret.emplace_back(
                        PCSX::Stacktrace::Element{path, int(s[dwarf::DW_AT::call_line].as_sconstant()), pc, sp});
                    break;
                }
            }
        }
        // next up, let's try computing what we need to do a recursive call
        // first, do we have an fde for this pc?
        const auto& fde = e.findFDE(pc);
        if (!fde.valid()) break;
        dwarf::fde::cfa cfa;
        try {
            cfa = fde.evaluate_cfa(pc);
        } catch (...) {
        }
        // do we have anything useful in there?
        if (!cfa.offset_valid || !cfa.ra_offset_valid || cfa.reg != 29) break;
        // we shall try reading our RA from the current stack then!
        uint32_t raAbsoluteOffset = sp + cfa.offset + cfa.ra_offset;
        uint32_t* raPtr = (uint32_t*)PSXM(raAbsoluteOffset);
        if (raPtr) {
            ra = *raPtr;
            // let's try adjusting our stack pointer
            uint32_t* spPtr = nullptr;
            if (cfa.saved_reg_offset_valid) {
                uint32_t spAbsoluteOffset = sp + cfa.offset + cfa.saved_reg_offset;
                spPtr = (uint32_t*)PSXM(spAbsoluteOffset);
            }
            sp = spPtr ? *spPtr : sp + cfa.offset;
        }
        break;
    }
    // do we have a useful return address to go up to ?
    if (ra) {
        // before diving recursively, let's check if we don't already
        // have the same ra/sp combination in our stack; if yes, this
        // will result in an infinite recursion, so let's not.
        for (auto& s : ret) {
            if ((s.pc == ra) && (s.sp == sp)) return;
        }
        computeStacktraceRec(ret, mem, ra, sp);
    }
}

std::vector<PCSX::Stacktrace::Element> PCSX::Stacktrace::computeStacktrace(Memory* mem, psxRegisters* regs) {
    std::vector<PCSX::Stacktrace::Element> ret;
    computeStacktraceRec(ret, mem, regs->pc, regs->GPR.n.sp, regs->GPR.n.ra);
    return std::move(ret);
}
