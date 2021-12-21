/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include "profiler.h"

#include <algorithm>
#include <functional>

#include "recompiler.h"

#if defined(DYNAREC_X86_64)
// Starts a profiling session for this block using the CPU's timestamp counter (TSC)
// Returns whether or not the profiler data overflowed. If it did, the recompiler should uncompile all blocks
// And compile them again, otherwise profiling data will be off
bool DynaRecCPU::startProfiling(uint32_t pc) {
    bool overflowed = false;

    if (!m_profiler.hasSpace()) {  // Flush data if we can't store any more
        dumpProfileData();
        m_profiler.reset();
        overflowed = true;
    }

    ProfilerEntry entry(0, 0, pc);  // Create and queue profiler entry
    m_profiler.add(entry);

    const ProfilerEntry& entryRef = m_profiler.back();
    const uintptr_t iterationOffset = (uintptr_t)&entryRef.timesInvoked - (uintptr_t)&entryRef;

    gen.mov(rcx, (uintptr_t)&entryRef);     // rcx = pointer to entry object
    gen.inc(qword[rcx + iterationOffset]);  // Increment "times invoked" variable

    gen.rdtsc();  // Read current CPU timestamp
    gen.shl(rdx, 32);
    gen.or_(rax, rdx);                                               // rax = 64-bit CPU timestamp
    gen.mov(qword[contextPointer + HOST_REG_CACHE_OFFSET(1)], rax);  // Cache timestamp

    return overflowed;
}

void DynaRecCPU::endProfiling() {
    const ProfilerEntry& entryRef = m_profiler.back();
    const uintptr_t cycleOffset = (uintptr_t)&entryRef.cyclesSpent - (uintptr_t)&entryRef;

    gen.rdtsc();                         // Read current CPU timestamp
    gen.mov(rcx, (uintptr_t)&entryRef);  // rcx = pointer to entry object
    gen.shl(rdx, 32);
    gen.or_(rax, rdx);  // rax = 64-bit CPU timestamp

    // Subtract cached timestamp from current timestamp to get delta
    gen.sub(rax, qword[contextPointer + HOST_REG_CACHE_OFFSET(1)]);
    gen.add(qword[rcx + cycleOffset], rax);  // Add delta to elapsed cycles

    loadAddress(rcx, &m_profiler.totalCycles());
    gen.add(qword[rcx], rax);  // Add delta to total cycles
}

void DynaRecCPU::dumpProfileData() {
    std::string data = "Program Counter        Cycles Spent            Times Invoked\n";

    // Sort blocks based on cycles spent in descending order
    m_profiler.sort();
    const int numberOfBlocks = std::min<int>(500, m_profiler.size());
    const uint64_t totalCycles = m_profiler.totalCycles();

    for (int i = 0; i < numberOfBlocks; i++) {
        const ProfilerEntry& entry = m_profiler[i];
        const double percentage = (double)entry.cyclesSpent / (double)totalCycles * 100.0;
        data += fmt::format("{:08X}               {}({:.2f}%)                      {}\n", entry.pc, entry.cyclesSpent,
                            percentage, entry.timesInvoked);
    }

    std::ofstream out("DynarecProfileData.txt");
    out << data;

    m_profiler.reset();
}
#endif  // DYNAREC_X86_64
