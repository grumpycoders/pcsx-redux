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

#pragma once

#include "core/r3000a.h"
#if defined(DYNAREC_X86_64)
#include <algorithm>
#include <cassert>
#include <fstream>
#include <functional>
#include <vector>

struct ProfilerEntry {
    uint32_t pc;
    uint64_t cyclesSpent = 0; // Total amount of CPU cycles spent in this block
    uint64_t timesInvoked = 0; // Total amount of times this block has been executed 

    ProfilerEntry(uint64_t cyclesSpent, uint64_t timesInvoked, uint32_t pc)
        : cyclesSpent(cyclesSpent), timesInvoked(timesInvoked), pc(pc) {}
    ProfilerEntry() {}

    // Compare objects based on cyclesSpent (used for sorting entries)
    bool operator > (const ProfilerEntry& other) const {
        return (cyclesSpent > other.cyclesSpent);
    }
};

// Wrapper around a fixed-size vector
template <int maxEntryCount>
class RecompilerProfiler {
    static_assert(maxEntryCount > 0, "Can't have a profiler with less than 1 entries");    
    int m_entryCount;
    std::vector<ProfilerEntry> m_entries;
    uint64_t m_totalCycles;

public:
    void init() {
        m_entries.resize(maxEntryCount); // We don't do this in the constructor, because unlike init it gets called in release builds
        m_entryCount = 0;
    }

    void reset() {
        m_entryCount = 0;
    }

    // Returns if there's enough space to fit an extra entry
    bool hasSpace() { return m_entryCount < maxEntryCount; }
    int size() { return m_entryCount; }
    ProfilerEntry& back() { return m_entries[m_entryCount]; }

    // Sort entries in descending order
    void sort() {
        std::partial_sort(m_entries.begin(), m_entries.begin() + m_entryCount, m_entries.end(), std::greater<ProfilerEntry>());
    }

    // Check for possible overflows before calling
    void add(ProfilerEntry& entry) {
        m_entries[m_entryCount].pc = entry.pc;
        m_entries[m_entryCount].cyclesSpent = entry.cyclesSpent;
        m_entries[m_entryCount].timesInvoked = entry.timesInvoked;

        m_entryCount++;
    }

    uint64_t& totalCycles() { return m_totalCycles; }
    ProfilerEntry& operator[] (int i) { return m_entries[i]; }
};
#endif // DYNAREC_X86_64
