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

#include "core/alloc-tracker.h"

#include <algorithm>
#include <optional>

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/system.h"
#include "fmt/format.h"

namespace {

std::optional<uint32_t> readGuest32(uint32_t address) {
    auto* ptr = PCSX::g_emulator->m_mem->getPointer<uint32_t>(address);
    if (!ptr) return std::nullopt;
    return *ptr;
}

// O32: indices 0..3 are a0..a3, 4 and up are stack arguments in the caller's
// argument save area at sp + 0x10. Only valid at function entry, before the
// prologue has moved sp.
std::optional<uint32_t> readArg(uint8_t index) {
    if (index == PCSX_ALLOCARG_NONE) return std::nullopt;
    auto& regs = PCSX::g_emulator->m_cpu->m_regs;
    if (index < 4) return regs.GPR.r[4 + index];
    return readGuest32(regs.GPR.n.sp + 0x10 + (index - 4) * 4);
}

std::string readGuestString(uint32_t address, size_t limit = 64) {
    std::string out;
    if (!address) return out;
    for (size_t i = 0; i < limit; i++) {
        auto* c = PCSX::g_emulator->m_mem->getPointer<char>(address + i);
        if (!c || !*c) break;
        out += *c;
    }
    return out;
}

}  // namespace

bool PCSX::AllocTracker::canObserve() {
    const auto& settings = g_emulator->settings;
    if (!settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::Debug>()) return false;
    if (settings.get<Emulator::SettingDynarec>()) return false;
    return true;
}

void PCSX::AllocTracker::reset() {
    // Emulator members are destroyed in reverse declaration order, so
    // m_allocTracker is declared after m_debug and ~AllocTracker runs while the
    // debugger is still alive. Do not move it back up: a destroyed unique_ptr
    // is not guaranteed to read as null, so the check below cannot catch that.
    bool debuggerAlive = g_emulator && g_emulator->m_debug;
    for (auto& arena : m_arenas) {
        if (debuggerAlive) {
            for (auto* bp : arena.breakpoints) {
                g_emulator->m_debug->removeBreakpoint(bp);
            }
        }
        arena.breakpoints.clear();
    }
    // A pending capture's one-shot normally deletes itself by returning false,
    // but one whose return never arrives stays armed. Nothing else removes it,
    // so track them by id and tear them down here explicitly.
    if (debuggerAlive) {
        for (auto& pending : m_pendingBreakpoints) {
            if (pending.second) g_emulator->m_debug->removeBreakpoint(pending.second);
        }
    }
    m_pendingBreakpoints.clear();
    m_arenas.clear();
    m_findings.clear();
    m_serial = 0;
    m_pendingCaptures = 0;
}

uint32_t PCSX::AllocTracker::registerDescriptor(uint32_t payloadAddress, uint32_t entryCount, std::string* error) {
    uint32_t status = PCSX_CMDSTATUS_OK;
    auto fail = [error, &status](uint32_t code, const char* message) {
        if (error) *error = message;
        status = code;
        return status;
    };

    if (entryCount == 0) return fail(PCSX_CMDSTATUS_BAD_ARGUMENT, "descriptor declares no entries");
    if (entryCount > 64) return fail(PCSX_CMDSTATUS_BAD_ARGUMENT, "descriptor declares too many entries");

    auto nameAddr = readGuest32(payloadAddress + 0);
    auto heapStart = readGuest32(payloadAddress + 4);
    auto heapEnd = readGuest32(payloadAddress + 8);
    if (!nameAddr || !heapStart || !heapEnd) {
        return fail(PCSX_CMDSTATUS_UNMAPPED, "descriptor payload is not fully in mapped memory");
    }

    Arena arena;
    arena.descriptorAddr = payloadAddress;
    arena.name = readGuestString(*nameAddr);
    if (arena.name.empty()) arena.name = fmt::format("arena @ {:08x}", payloadAddress);
    arena.start = *heapStart;
    arena.end = *heapEnd;
    arena.boundsKnown = (*heapStart != 0) || (*heapEnd != 0);
    if (arena.boundsKnown && (arena.end <= arena.start)) {
        return fail(PCSX_CMDSTATUS_BAD_ARGUMENT, "descriptor bounds are inverted or empty");
    }

    uint32_t entriesBase = payloadAddress + 16;
    for (uint32_t i = 0; i < entryCount; i++) {
        uint32_t base = entriesBase + i * 8;
        auto address = readGuest32(base + 0);
        auto packed = readGuest32(base + 4);
        if (!address || !packed) {
            return fail(PCSX_CMDSTATUS_UNMAPPED, "descriptor entry table runs outside mapped memory");
        }
        pcsx_AllocEntry entry;
        entry.address = *address;
        entry.kind = (*packed >> 0) & 0xff;
        entry.argSize = (*packed >> 8) & 0xff;
        entry.argPtr = (*packed >> 16) & 0xff;
        entry.argCount = (*packed >> 24) & 0xff;
        if (entry.kind == PCSX_ALLOC_KIND_END) continue;
        if (entry.kind > PCSX_ALLOC_KIND_INIT) {
            return fail(PCSX_CMDSTATUS_BAD_ARGUMENT, "descriptor entry has an unknown kind");
        }
        if (!g_emulator->m_mem->getPointer<uint32_t>(entry.address)) {
            return fail(PCSX_CMDSTATUS_BAD_ARGUMENT, "descriptor entry points outside mapped memory");
        }
        arena.entries.push_back(entry);
    }
    if (arena.entries.empty()) return fail(PCSX_CMDSTATUS_BAD_ARGUMENT, "descriptor has no usable entries");

    m_arenas.push_back(std::move(arena));
    installBreakpoints(m_arenas.size() - 1);
    return PCSX_CMDSTATUS_OK;
}

void PCSX::AllocTracker::installBreakpoints(size_t arenaIndex) {
    auto& arena = m_arenas[arenaIndex];
    for (const auto& entry : arena.entries) {
        auto* bp = g_emulator->m_debug->addBreakpoint(
            entry.address, Debug::BreakpointType::Exec, 4, _("Allocator tracker"), arena.name,
            [this, arenaIndex, entry](Debug::Breakpoint*, uint32_t, unsigned, const char*) {
                onEntry(arenaIndex, entry);
                // Keep the breakpoint, and never pause: this is an observer.
                return true;
            });
        arena.breakpoints.push_back(bp);
    }
}

void PCSX::AllocTracker::onEntry(size_t arenaIndex, const pcsx_AllocEntry& entry) {
    if (arenaIndex >= m_arenas.size()) return;
    auto& arena = m_arenas[arenaIndex];
    // Inside a tracked call already: this is the allocator calling itself.
    if (arena.depth > 0) return;
    auto caller = g_emulator->m_cpu->m_regs.GPR.n.ra;

    switch (entry.kind) {
        case PCSX_ALLOC_KIND_INIT: {
            auto base = readArg(entry.argPtr);
            auto size = readArg(entry.argSize);
            // Re-initialization discards the allocator's previous bookkeeping,
            // so every block we are still holding is fiction from here on.
            arena.live.clear();
            arena.liveBytes = 0;
            arena.mark = 0;
            if (base && size) {
                arena.start = *base;
                arena.end = *base + *size;
                arena.boundsKnown = true;
            }
            break;
        }
        case PCSX_ALLOC_KIND_FREE: {
            auto ptr = readArg(entry.argPtr);
            if (ptr) recordFree(arenaIndex, *ptr, caller);
            break;
        }
        case PCSX_ALLOC_KIND_ALLOC: {
            auto size = readArg(entry.argSize);
            captureReturn(arenaIndex, entry, size.value_or(0), 0);
            break;
        }
        case PCSX_ALLOC_KIND_CALLOC: {
            auto count = readArg(entry.argCount);
            auto size = readArg(entry.argSize);
            uint64_t total = uint64_t(count.value_or(0)) * uint64_t(size.value_or(0));
            captureReturn(arenaIndex, entry, uint32_t(total), 0);
            break;
        }
        case PCSX_ALLOC_KIND_REALLOC: {
            auto ptr = readArg(entry.argPtr);
            auto size = readArg(entry.argSize);
            captureReturn(arenaIndex, entry, size.value_or(0), ptr.value_or(0));
            break;
        }
        default:
            break;
    }
}

void PCSX::AllocTracker::captureReturn(size_t arenaIndex, const pcsx_AllocEntry& entry, uint32_t requestedSize,
                                       uint32_t oldPointer) {
    auto& regs = g_emulator->m_cpu->m_regs.GPR.n;
    uint32_t ra = regs.ra;
    uint32_t sp = regs.sp;
    if (!ra) return;
    if (m_pendingCaptures >= c_maxPendingCaptures) return;
    m_pendingCaptures++;
    // Held until the matching return, so everything the allocator does
    // internally in between is ignored.
    m_arenas[arenaIndex].depth++;
    uint64_t id = ++m_captureId;
    m_pendingBreakpoints[id] = nullptr;

    auto* bp = g_emulator->m_debug->addBreakpoint(
        ra, Debug::BreakpointType::Exec, 4, _("Allocator tracker return"),
        [this, arenaIndex, entry, requestedSize, oldPointer, sp, ra, id](Debug::Breakpoint*, uint32_t, unsigned,
                                                                         const char*) {
            // The epilogue restores sp, so at the return site sp matches what
            // it was at entry. A mismatch means this is a different frame that
            // happens to return to the same address: keep waiting.
            if (g_emulator->m_cpu->m_regs.GPR.n.sp != sp) return true;
            m_pendingCaptures--;
            if (arenaIndex < m_arenas.size() && m_arenas[arenaIndex].depth > 0) m_arenas[arenaIndex].depth--;
            // Forget the id before returning false, or reset() will try to
            // remove a breakpoint the debugger is about to delete.
            m_pendingBreakpoints.erase(id);
            onReturn(arenaIndex, entry, requestedSize, oldPointer, g_emulator->m_cpu->m_regs.GPR.n.v0, ra);
            // One-shot: the invoker returning false deletes the breakpoint.
            return false;
        });
    auto it = m_pendingBreakpoints.find(id);
    // The invoker can fire before this assignment only if the guest ran in
    // between, which it cannot: addBreakpoint does not execute anything.
    if (it != m_pendingBreakpoints.end()) it->second = bp;
}

void PCSX::AllocTracker::onReturn(size_t arenaIndex, const pcsx_AllocEntry& entry, uint32_t requestedSize,
                                  uint32_t oldPointer, uint32_t result, uint32_t caller) {
    if (arenaIndex >= m_arenas.size()) return;

    if (entry.kind == PCSX_ALLOC_KIND_REALLOC && oldPointer != 0) {
        // A successful realloc consumes the old block whether or not it moved,
        // and a failed one leaves it alone - which is why a non-null result is
        // normally what retires the old pointer.
        //
        // realloc(p, 0) breaks that rule: it is a free, and it returns null.
        // Telling the two null-returning cases apart needs the requested size,
        // because nothing else distinguishes "freed it" from "could not do it".
        // Getting this wrong strands the block as live forever, and the
        // re-entrancy suppression is what makes it matter: the inner free that
        // such an implementation performs is correctly ignored as an internal,
        // so this is the only place the free can be recorded at all.
        if (result != 0 || requestedSize == 0) recordFree(arenaIndex, oldPointer, caller);
    }

    if (result == 0) {
        if (requestedSize != 0) addFinding(FindingKind::FailedAlloc, arenaIndex, 0, requestedSize, caller);
        return;
    }
    if (requestedSize == 0) addFinding(FindingKind::ZeroSize, arenaIndex, result, 0, caller);
    recordAlloc(arenaIndex, result, requestedSize, caller);
}

void PCSX::AllocTracker::recordAlloc(size_t arenaIndex, uint32_t pointer, uint32_t size, uint32_t caller) {
    auto& arena = m_arenas[arenaIndex];

    // An allocator handing out a block that overlaps one it already handed out
    // and has not been told to release is an allocator bug, and it is visible
    // from the (pointer, size) pairs alone without knowing any block layout.
    if (size != 0) {
        auto it = arena.live.upper_bound(pointer);
        if (it != arena.live.begin()) {
            auto prev = std::prev(it);
            if (prev->second.size != 0 && (uint64_t(prev->first) + prev->second.size) > pointer) {
                addFinding(FindingKind::Overlap, arenaIndex, pointer, prev->first, caller);
            }
        }
        if (it != arena.live.end() && (uint64_t(pointer) + size) > it->first) {
            addFinding(FindingKind::Overlap, arenaIndex, pointer, it->first, caller);
        }
    }

    Block block;
    block.size = size;
    block.caller = caller;
    block.serial = ++m_serial;
    auto existing = arena.live.find(pointer);
    if (existing != arena.live.end()) {
        // Same address handed out twice with no intervening free. Retire the
        // old accounting rather than counting the address twice; the overlap
        // check above has already recorded it as a finding where it is one.
        arena.liveBytes -= std::min<uint64_t>(arena.liveBytes, existing->second.size);
    }
    arena.live[pointer] = block;
    arena.liveBytes += size;
    arena.allocCount++;
    if (arena.liveBytes > arena.peakBytes) arena.peakBytes = arena.liveBytes;

    if (!arena.boundsKnown) {
        if (arena.start == 0 || pointer < arena.start) arena.start = pointer;
        if ((uint64_t(pointer) + size) > arena.end) arena.end = pointer + size;
    }
}

void PCSX::AllocTracker::recordFree(size_t arenaIndex, uint32_t pointer, uint32_t caller) {
    auto& arena = m_arenas[arenaIndex];
    if (pointer == 0) return;  // free(NULL) is defined and boring.

    auto it = arena.live.find(pointer);
    if (it != arena.live.end()) {
        arena.liveBytes -= std::min<uint64_t>(arena.liveBytes, it->second.size);
        arena.live.erase(it);
        arena.freeCount++;
        return;
    }

    // Not a block we know. Distinguish an interior pointer, which is a very
    // specific and very diagnosable bug, from a plain unknown pointer, which is
    // a double free, a foreign heap, or an allocation from before we attached.
    auto after = arena.live.upper_bound(pointer);
    if (after != arena.live.begin()) {
        auto prev = std::prev(after);
        if (prev->second.size != 0 && (uint64_t(prev->first) + prev->second.size) > pointer) {
            addFinding(FindingKind::InteriorFree, arenaIndex, pointer, prev->first, caller);
            arena.freeCount++;
            return;
        }
    }
    addFinding(FindingKind::DoubleOrUnknownFree, arenaIndex, pointer, 0, caller);
    arena.freeCount++;
}

void PCSX::AllocTracker::addFinding(FindingKind kind, size_t arenaIndex, uint32_t pointer, uint32_t extra,
                                    uint32_t caller) {
    if (m_findings.size() >= c_maxFindings) return;
    Finding finding;
    finding.kind = kind;
    finding.arena = arenaIndex;
    finding.pointer = pointer;
    finding.extra = extra;
    finding.caller = caller;
    finding.serial = m_serial;
    m_findings.push_back(finding);
}

void PCSX::AllocTracker::markArena(size_t index) {
    if (index >= m_arenas.size()) return;
    m_arenas[index].mark = m_serial;
}
