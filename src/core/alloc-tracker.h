/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include <map>
#include <string>
#include <vector>

#include "core/debug.h"
#include "mips/common/hardware/allocdesc.h"

namespace PCSX {

/*

Generic allocator tracker.

Where the PSYQo heap viewer walks a known allocator's own free list and is
therefore stateless, this observes an arbitrary allocator by breakpointing its
entry points and recording what it was asked for and what it handed back. It
knows nothing about block headers and never reads guest memory to learn a
block's size, which is what makes it work against an allocator nobody has
documented.

The price is that it only functions under the interpreter with the debugger
enabled: the dynamic recompiler honors no execution breakpoints at all. Callers
must surface that rather than rendering an empty map.

Two things it structurally cannot know, both of which must be displayed as
unknown rather than guessed:
  - the free list, so the gaps between live blocks are unknown space, not free
    space, and no honest fragmentation figure can be derived from them;
  - anything allocated before registration, which is invisible forever.

*/

class AllocTracker {
  public:
    AllocTracker() {}
    ~AllocTracker() { reset(); }

    struct Block {
        uint32_t size = 0;
        uint32_t caller = 0;
        uint64_t serial = 0;
    };

    enum class FindingKind {
        DoubleOrUnknownFree,
        InteriorFree,
        UnknownRealloc,
        Overlap,
        FailedAlloc,
        ZeroSize,
    };

    struct Finding {
        FindingKind kind;
        size_t arena = 0;
        uint32_t pointer = 0;
        // Block base for an interior free, the requested size otherwise.
        uint32_t extra = 0;
        uint32_t caller = 0;
        uint64_t serial = 0;
    };

    struct Arena {
        std::string name;
        uint32_t descriptorAddr = 0;
        uint32_t start = 0;
        uint32_t end = 0;
        // False means the descriptor gave no bounds and no INIT entry has been
        // seen, so any address range shown is derived from observed blocks.
        bool boundsKnown = false;
        std::map<uint32_t, Block> live;
        uint64_t allocCount = 0;
        uint64_t freeCount = 0;
        uint64_t liveBytes = 0;
        uint64_t peakBytes = 0;
        // Snapshot serial for mark/diff leak hunting; blocks with a serial at
        // or above this were allocated since the mark.
        uint64_t mark = 0;
        // Re-entrancy depth. Real allocators implement calloc and realloc in
        // terms of malloc and free, so a single guest call fires several of the
        // registered entry points. Only the outermost is what the program
        // asked for; the rest are internals and recording them double-counts
        // every allocation and invents double frees. Nonzero means we are
        // inside a tracked call for this arena and further entries are noise.
        uint32_t depth = 0;
        std::vector<pcsx_AllocEntry> entries;
        std::vector<const Debug::Breakpoint*> breakpoints;
    };

    // Reads the descriptor payload out of guest memory once and installs the
    // entry breakpoints. payloadAddress points just past the command header;
    // the caller has already bounds-checked entryCount against the struct's
    // declared size. Returns a pcsx_CommandStatus, and fills error with
    // something human-readable on anything other than OK.
    uint32_t registerDescriptor(uint32_t payloadAddress, uint32_t entryCount, std::string* error);

    // Drops every arena, breakpoint and pending return capture. Call on reset
    // and on savestate load: a pending capture restored into a machine that
    // will never reach its return address is a permanent phantom.
    void reset();

    const std::vector<Arena>& arenas() const { return m_arenas; }
    const std::vector<Finding>& findings() const { return m_findings; }
    void clearFindings() { m_findings.clear(); }
    void markArena(size_t index);
    size_t pendingCaptures() const { return m_pendingCaptures; }
    bool active() const { return !m_arenas.empty(); }

    // True when the current core and debugger settings let the entry
    // breakpoints actually fire. False means every number here is stale.
    static bool canObserve();

  private:
    void installBreakpoints(size_t arenaIndex);
    void onEntry(size_t arenaIndex, const pcsx_AllocEntry& entry);
    void onReturn(size_t arenaIndex, const pcsx_AllocEntry& entry, uint32_t requestedSize, uint32_t oldPointer,
                  uint32_t result, uint32_t caller);
    void captureReturn(size_t arenaIndex, const pcsx_AllocEntry& entry, uint32_t requestedSize, uint32_t oldPointer);

    void recordAlloc(size_t arenaIndex, uint32_t pointer, uint32_t size, uint32_t caller);
    void recordFree(size_t arenaIndex, uint32_t pointer, uint32_t caller);
    void addFinding(FindingKind kind, size_t arenaIndex, uint32_t pointer, uint32_t extra, uint32_t caller);

    std::vector<Arena> m_arenas;
    std::vector<Finding> m_findings;
    uint64_t m_serial = 0;
    size_t m_pendingCaptures = 0;
    uint64_t m_captureId = 0;
    // In-flight return captures, so a capture whose return never arrives can
    // still be torn down on reset instead of staying armed forever.
    std::map<uint64_t, const Debug::Breakpoint*> m_pendingBreakpoints;

    // A capture whose return never arrives (longjmp, a tail-called allocator,
    // a descriptor pointing at the wrong address) leaves its one-shot armed
    // forever. Cap the in-flight set so a misconfigured descriptor degrades
    // instead of accumulating breakpoints without bound.
    static constexpr size_t c_maxPendingCaptures = 256;
    static constexpr size_t c_maxFindings = 4096;
};

}  // namespace PCSX
