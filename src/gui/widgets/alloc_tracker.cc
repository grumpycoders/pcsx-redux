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

#include "gui/widgets/alloc_tracker.h"

#include "core/alloc-tracker.h"
#include "core/psxemulator.h"
#include "core/system.h"
#include "fmt/format.h"
#include "imgui.h"

namespace {

// Red for allocated, grey for unknown. Deliberately NOT the heap viewer's green:
// green means free there, and this widget cannot know that.
constexpr ImU32 c_allocatedColor = IM_COL32(180, 60, 60, 255);
constexpr ImU32 c_unknownColor = IM_COL32(90, 90, 95, 255);
constexpr ImU32 c_sinceMarkColor = IM_COL32(200, 140, 50, 255);

const char* findingName(PCSX::AllocTracker::FindingKind kind) {
    switch (kind) {
        case PCSX::AllocTracker::FindingKind::DoubleOrUnknownFree:
            return "Double or unknown free";
        case PCSX::AllocTracker::FindingKind::InteriorFree:
            return "Interior free";
        case PCSX::AllocTracker::FindingKind::UnknownRealloc:
            return "Unknown realloc";
        case PCSX::AllocTracker::FindingKind::Overlap:
            return "Overlapping allocation";
        case PCSX::AllocTracker::FindingKind::FailedAlloc:
            return "Allocation failed";
        case PCSX::AllocTracker::FindingKind::ZeroSize:
            return "Zero-size allocation";
    }
    return "Unknown";
}

const char* findingDetail(PCSX::AllocTracker::FindingKind kind) {
    switch (kind) {
        case PCSX::AllocTracker::FindingKind::InteriorFree:
            return "freed a pointer inside a live block rather than its base";
        case PCSX::AllocTracker::FindingKind::DoubleOrUnknownFree:
            return "freed a pointer this arena never handed out, or handed out and already reclaimed";
        case PCSX::AllocTracker::FindingKind::Overlap:
            return "the allocator handed out a block overlapping one it has not reclaimed";
        case PCSX::AllocTracker::FindingKind::UnknownRealloc:
            return "reallocated a pointer this arena never handed out";
        case PCSX::AllocTracker::FindingKind::FailedAlloc:
            return "the allocator returned null";
        case PCSX::AllocTracker::FindingKind::ZeroSize:
            return "allocation of zero bytes";
    }
    return "";
}

void colorKey(const char* id, ImU32 packed, const char* label) {
    ImVec4 color = ImGui::ColorConvertU32ToFloat4(packed);
    ImGui::ColorButton(id, color, ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoPicker, ImVec2(12, 12));
    ImGui::SameLine();
    ImGui::TextUnformatted(label);
}

}  // namespace

void PCSX::Widgets::AllocTrackerViewer::draw(const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    auto* tracker = g_emulator->m_allocTracker.get();

    // This has to be first and it has to be loud. Without the interpreter and
    // the debugger, no execution breakpoint ever fires, so the map below is not
    // merely empty: it is frozen at whatever it held when observation stopped,
    // which reads exactly like a program that has stopped allocating.
    if (!AllocTracker::canObserve()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.4f, 0.4f, 1.0f));
        ImGui::TextUnformatted("Not observing.");
        ImGui::PopStyleColor();
        ImGui::TextWrapped(
            "This tracker works by placing execution breakpoints on the allocator's entry points, and those only "
            "exist in the interpreter with the debugger enabled. The dynamic recompiler honors no execution "
            "breakpoints at all. Anything shown below is stale.");
        ImGui::Separator();
    }

    const auto& arenas = tracker->arenas();
    if (arenas.empty()) {
        ImGui::TextUnformatted("No allocator registered.");
        ImGui::TextWrapped(
            "The running program has not described its allocator to the emulator. A guest registers one by filling in "
            "a pcsx_AllocDescriptor (common/hardware/allocdesc.h) with the addresses of its malloc, free and realloc "
            "entry points and issuing PCSX_CMD_REGISTER_ALLOCATOR. Several arenas may be registered independently.");
        ImGui::End();
        return;
    }

    if (m_selectedArena >= arenas.size()) m_selectedArena = 0;

    if (arenas.size() > 1) {
        if (ImGui::BeginCombo("Arena", arenas[m_selectedArena].name.c_str())) {
            for (size_t i = 0; i < arenas.size(); i++) {
                bool selected = (i == m_selectedArena);
                if (ImGui::Selectable(arenas[i].name.c_str(), selected)) m_selectedArena = i;
                if (selected) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }
    } else {
        ImGui::Text("Arena: %s", arenas[0].name.c_str());
    }

    const auto& arena = arenas[m_selectedArena];

    // The declared bounds are a snapshot the guest took at registration, and an
    // allocator whose break moves will outgrow them. Blocks landing outside are
    // therefore normal rather than corrupt - but clamping them into the declared
    // span renders them at zero width, so the map goes blank while the summary
    // still reports live bytes. Draw over the union instead, and say why.
    uint32_t displayStart = arena.start;
    uint32_t displayEnd = arena.end;
    bool outsideDeclared = false;
    for (const auto& [address, block] : arena.live) {
        if (displayStart == 0 || address < displayStart) displayStart = address;
        if (uint64_t(address) + block.size > displayEnd) displayEnd = address + block.size;
        if (arena.boundsKnown && (address < arena.start || uint64_t(address) + block.size > arena.end)) {
            outsideDeclared = true;
        }
    }

    if (arena.boundsKnown) {
        ImGui::Text("Declared range: %08x - %08x (%u bytes)", arena.start, arena.end, arena.end - arena.start);
    } else {
        ImGui::Text("Range: %08x - %08x (derived from observed blocks; the allocator's real bounds are unknown)",
                    displayStart, displayEnd);
    }
    if (outsideDeclared) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.8f, 0.0f, 1.0f));
        ImGui::TextWrapped(
            "Live blocks lie outside the declared range; showing %08x - %08x instead. The descriptor's bounds were a "
            "snapshot taken when it was registered, and this allocator's heap has grown since.",
            displayStart, displayEnd);
        ImGui::PopStyleColor();
    }
    ImGui::Text("Live: %zu block%s, %llu bytes    Peak: %llu bytes", arena.live.size(),
                arena.live.size() == 1 ? "" : "s", (unsigned long long)arena.liveBytes,
                (unsigned long long)arena.peakBytes);
    ImGui::Text("Calls: %llu allocations, %llu frees", (unsigned long long)arena.allocCount,
                (unsigned long long)arena.freeCount);
    if (tracker->pendingCaptures() != 0) {
        ImGui::Text("In-flight return captures: %zu", tracker->pendingCaptures());
    }

    ImGui::Separator();

    // Leak hunting: mark the current live set, run a scene, then look at what
    // is newer than the mark. A leak is only meaningful against a baseline.
    if (ImGui::Button("Mark")) {
        g_emulator->m_allocTracker->markArena(m_selectedArena);
    }
    ImGui::SameLine();
    ImGui::TextUnformatted("the current live set as a baseline");
    ImGui::SameLine();
    ImGui::Checkbox("Only show blocks since mark", &m_onlySinceMark);

    size_t sinceMark = 0;
    uint64_t sinceMarkBytes = 0;
    for (const auto& [address, block] : arena.live) {
        if (block.serial > arena.mark) {
            sinceMark++;
            sinceMarkBytes += block.size;
        }
    }
    if (arena.mark != 0) {
        ImGui::Text("Since mark: %zu blocks, %llu bytes still live", sinceMark, (unsigned long long)sinceMarkBytes);
    }

    ImGui::Separator();

    uint64_t span = (displayEnd > displayStart) ? (displayEnd - displayStart) : 0;
    if (span > 0) {
        ImVec2 avail = ImGui::GetContentRegionAvail();
        float barWidth = avail.x;
        float barHeight = 20.0f;
        ImVec2 barPos = ImGui::GetCursorScreenPos();
        ImDrawList* drawList = ImGui::GetWindowDrawList();

        // The whole span starts unknown and allocated blocks are painted over
        // it. That ordering is the honest one: absence of a block is absence of
        // information, not evidence of free space.
        drawList->AddRectFilled(barPos, ImVec2(barPos.x + barWidth, barPos.y + barHeight), c_unknownColor);

        for (const auto& [address, block] : arena.live) {
            if (block.size == 0) continue;
            float x0 = barWidth * (float)(address - displayStart) / (float)span;
            float x1 = barWidth * (float)(address + block.size - displayStart) / (float)span;
            if (x0 < 0) x0 = 0;
            if (x1 > barWidth) x1 = barWidth;
            // A one-pixel block is invisible; give every live block at least a
            // sliver, or a heap full of small allocations renders as empty.
            if (x1 - x0 < 1.0f) x1 = x0 + 1.0f;
            ImU32 color = (arena.mark != 0 && block.serial > arena.mark) ? c_sinceMarkColor : c_allocatedColor;
            drawList->AddRectFilled(ImVec2(barPos.x + x0, barPos.y), ImVec2(barPos.x + x1, barPos.y + barHeight),
                                    color);
        }
        drawList->AddRect(barPos, ImVec2(barPos.x + barWidth, barPos.y + barHeight), IM_COL32(200, 200, 200, 255));
        ImGui::Dummy(ImVec2(barWidth, barHeight));

        if (ImGui::IsItemHovered()) {
            float mouseX = ImGui::GetMousePos().x - barPos.x;
            uint32_t hoverAddr = displayStart + (uint32_t)((double)span * mouseX / barWidth);
            bool found = false;
            for (const auto& [address, block] : arena.live) {
                if (hoverAddr >= address && hoverAddr < address + block.size) {
                    ImGui::BeginTooltip();
                    ImGui::Text("Allocated at %08x, %u bytes", address, block.size);
                    ImGui::Text("Requested from %08x", block.caller);
                    ImGui::TextUnformatted("Click to jump");
                    ImGui::EndTooltip();
                    if (ImGui::IsMouseClicked(0)) {
                        g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToMemory{address | 0x80000000, block.size});
                    }
                    found = true;
                    break;
                }
            }
            if (!found) {
                ImGui::BeginTooltip();
                ImGui::Text("%08x: unknown", hoverAddr);
                ImGui::TextUnformatted("No block was observed here. That is not the same as free space.");
                ImGui::EndTooltip();
            }
        }

        colorKey("##allocated", c_allocatedColor, "Allocated");
        ImGui::SameLine();
        colorKey("##sincemark", c_sinceMarkColor, "Allocated since mark");
        ImGui::SameLine();
        colorKey("##unknown", c_unknownColor, "Unknown (not free)");
    }

    ImGui::Separator();

    const auto& findings = tracker->findings();
    size_t arenaFindings = 0;
    for (const auto& finding : findings) {
        if (finding.arena == m_selectedArena) arenaFindings++;
    }

    if (ImGui::BeginTabBar("AllocTrackerTabs")) {
        if (ImGui::BeginTabItem("Blocks")) {
            if (ImGui::BeginTable("AllocBlocks", 4,
                                  ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                                      ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp,
                                  ImVec2(0, 0))) {
                ImGui::TableSetupColumn("Address");
                ImGui::TableSetupColumn("Size");
                ImGui::TableSetupColumn("Requested from");
                ImGui::TableSetupColumn("Order");
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();

                for (const auto& [address, block] : arena.live) {
                    bool isNew = (arena.mark != 0 && block.serial > arena.mark);
                    if (m_onlySinceMark && !isNew) continue;
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    auto label = fmt::format("{:08x}##block{}", address, address);
                    if (ImGui::Selectable(label.c_str(), false,
                                          ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                        g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToMemory{address | 0x80000000, block.size});
                    }
                    ImGui::TableNextColumn();
                    ImGui::Text("%u", block.size);
                    ImGui::TableNextColumn();
                    // The caller is the return address captured at entry, so it
                    // points just after the call site rather than at it.
                    ImGui::Text("%08x", block.caller);
                    ImGui::TableNextColumn();
                    if (isNew) {
                        ImGui::TextColored(ImVec4(0.8f, 0.55f, 0.2f, 1.0f), "%llu (since mark)",
                                           (unsigned long long)block.serial);
                    } else {
                        ImGui::Text("%llu", (unsigned long long)block.serial);
                    }
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }

        auto findingsLabel = fmt::format("Findings ({})###Findings", arenaFindings);
        if (ImGui::BeginTabItem(findingsLabel.c_str())) {
            if (ImGui::Button("Clear")) g_emulator->m_allocTracker->clearFindings();
            ImGui::SameLine();
            ImGui::TextWrapped(
                "Findings are derived from the calls alone. Overflow, use-after-free and uninitialized reads need "
                "memory inspection and belong to the MSAN viewer instead.");
            if (arenaFindings == 0) {
                ImGui::TextUnformatted("Nothing found.");
            } else if (ImGui::BeginTable("AllocFindings", 4,
                                         ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                                             ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp,
                                         ImVec2(0, 0))) {
                ImGui::TableSetupColumn("What");
                ImGui::TableSetupColumn("Pointer");
                ImGui::TableSetupColumn("Block");
                ImGui::TableSetupColumn("From");
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();
                for (size_t i = 0; i < findings.size(); i++) {
                    const auto& finding = findings[i];
                    if (finding.arena != m_selectedArena) continue;
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.0f, 1.0f), "%s", findingName(finding.kind));
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetTooltip("%s", findingDetail(finding.kind));
                    }
                    ImGui::TableNextColumn();
                    auto label = fmt::format("{:08x}##finding{}", finding.pointer, i);
                    if (ImGui::Selectable(label.c_str(), false)) {
                        g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToMemory{finding.pointer | 0x80000000, 4});
                    }
                    ImGui::TableNextColumn();
                    if (finding.kind == AllocTracker::FindingKind::InteriorFree ||
                        finding.kind == AllocTracker::FindingKind::Overlap) {
                        ImGui::Text("%08x", finding.extra);
                    } else if (finding.extra != 0) {
                        ImGui::Text("%u bytes", finding.extra);
                    } else {
                        ImGui::TextUnformatted("-");
                    }
                    ImGui::TableNextColumn();
                    ImGui::Text("%08x", finding.caller);
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::End();
}
