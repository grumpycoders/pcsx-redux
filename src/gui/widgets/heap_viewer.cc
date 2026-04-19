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

#include "gui/widgets/heap_viewer.h"
#include <optional>

#include "core/psxmem.h"
#include "core/system.h"
#include "fmt/format.h"
#include "imgui.h"

// The MIPS-side metadata struct layout (5 pointers, 4 bytes each):
//   uint32_t head;              // offset 0: pointer to first free block
//   uint32_t bottom;            // offset 4: start of heap
//   uint32_t top;               // offset 8: end of heap
//   uint32_t maximum_heap_end;  // offset 12: high-water mark
//   uint32_t marker_next;       // offset 16: end-of-list sentinel's next (NULL)
//
// Each free block (empty_block) in guest memory:
//   uint32_t next;  // offset 0: pointer to next free block
//   uint32_t size;  // offset 4: size in bytes including header

static std::optional<uint32_t> readGuest32(PCSX::Memory* memory, uint32_t addr) {
    auto* ptr = memory->getPointer<uint32_t>(addr);
    if (!ptr) return std::nullopt;
    return *ptr;
}

PCSX::Widgets::HeapViewer::WalkResult PCSX::Widgets::HeapViewer::walkHeap(Memory* memory) {
    WalkResult result;

    uint32_t metaAddr = memory->m_psyqoHeapMetadata;
    if (metaAddr == 0) return result;

    auto headPtr = readGuest32(memory, metaAddr + 0);
    auto bottomPtr = readGuest32(memory, metaAddr + 4);
    auto topPtr = readGuest32(memory, metaAddr + 8);
    auto markerPtr = metaAddr + 16;

    if (!headPtr || !bottomPtr || !topPtr) {
        result.error = "Heap metadata contains invalid pointers - likely corrupted metadata.";
        return result;
    }

    if (bottomPtr == 0 || topPtr == 0 || bottomPtr >= topPtr) return result;

    // Sanity check: heap shouldn't be larger than 8MB (max PS1 RAM).
    if (*topPtr - *bottomPtr > 8 * 1024 * 1024) {
        result.error = "Heap range exceeds 8MB - likely corrupted metadata.";
        return result;
    }

    // Validate that all metadata pointers resolve to readable memory.
    if (!memory->getPointer(*bottomPtr) || !memory->getPointer(*topPtr - 1)) {
        result.error = "Heap range points to unmapped memory.";
        return result;
    }

    // Collect all free blocks by walking the free list.
    // Guard against cycles, out-of-range pointers, and absurd sizes.
    struct FreeBlock {
        uint32_t address;
        uint32_t size;
    };
    std::vector<FreeBlock> freeBlocks;

    uint32_t curr = *headPtr;
    uint32_t prevAddr = 0;
    constexpr int maxFreeBlocks = 100000;

    while (curr != markerPtr && (int)freeBlocks.size() < maxFreeBlocks) {
        // A null next-pointer is not a valid terminator; it means the link was smashed.
        if (curr == 0) {
            result.error = "Free list contains a null pointer (expected marker) - heap corruption.";
            break;
        }

        // Free block must be within heap range.
        if (curr < bottomPtr || curr >= topPtr) {
            result.error = fmt::format("Free list entry at {:08x} is outside heap range [{:08x}, {:08x}).", curr,
                                       *bottomPtr, *topPtr);
            break;
        }

        // Free list must be sorted by address (ascending). Detects cycles too.
        if (prevAddr != 0 && curr <= prevAddr) {
            result.error =
                fmt::format("Free list not ascending at {:08x} (prev {:08x}) - cycle or corruption.", curr, prevAddr);
            break;
        }

        if (!memory->getPointer(curr)) {
            result.error = fmt::format("Free list entry at {:08x} points to unmapped memory.", curr);
            break;
        }

        auto next = readGuest32(memory, curr + 0);
        auto size = readGuest32(memory, curr + 4);

        // Size must be at least 8 (sizeof empty_block) and aligned to 8.
        if (!size || *size < 8 || (*size & 7) != 0) {
            result.error = fmt::format("Free block at {:08x} has invalid size {} (must be >= 8 and 8-aligned).", curr, size ? *size : 0);
            break;
        }

        // Block must not extend past top (overflow-safe form).
        if (*size > (*topPtr - curr)) {
            result.error =
                fmt::format("Free block at {:08x} (size {}) extends past heap top {:08x}.", curr, *size, *topPtr);
            break;
        }

        freeBlocks.push_back({curr, *size});
        prevAddr = curr;
        curr = *next;
    }

    if (freeBlocks.size() >= maxFreeBlocks && result.error.empty()) {
        result.error = "Free list exceeded 100000 entries - likely corrupted.";
    }

    // Walk from bottom to top, emitting allocated and free blocks.
    // Even if the free list walk hit an error, use whatever we collected.
    uint32_t pos = *bottomPtr;
    size_t freeIdx = 0;
    constexpr int maxBlocks = 200000;

    while (pos < *topPtr && (int)result.blocks.size() < maxBlocks) {
        if (freeIdx < freeBlocks.size() && freeBlocks[freeIdx].address == pos) {
            result.blocks.push_back({pos, freeBlocks[freeIdx].size, true});
            pos += freeBlocks[freeIdx].size;
            freeIdx++;
        } else {
            // Allocated block. Read size from header (offset 4, same layout as empty_block).
            auto size = readGuest32(memory, pos + 4);

            if (!size || *size < 8 || (*size & 7) != 0 || *size > (*topPtr - pos)) {
                // Corrupted allocated block. Emit remainder as unknown.
                if (result.error.empty()) {
                    result.error = fmt::format(
                        "Allocated block at {:08x} has invalid size {} (remaining space: {}).", pos, size ? *size : 0, *topPtr - pos);
                }
                result.blocks.push_back({pos, *topPtr - pos, false});
                break;
            }

            // Skip past any free blocks that fall within this allocated block's range.
            // (Shouldn't happen in a healthy heap, but be defensive.)
            while (freeIdx < freeBlocks.size() && freeBlocks[freeIdx].address < pos + *size) {
                if (result.error.empty()) {
                    result.error = fmt::format("Free block at {:08x} overlaps allocated block at {:08x}.",
                                               freeBlocks[freeIdx].address, pos);
                }
                freeIdx++;
            }

            result.blocks.push_back({pos, *size, false});
            pos += *size;
        }
    }

    if (result.blocks.size() >= maxBlocks && result.error.empty()) {
        result.error = "Block count exceeded 200000 - likely corrupted.";
    }

    return result;
}

void PCSX::Widgets::HeapViewer::draw(Memory* memory, const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    uint32_t metaAddr = memory->m_psyqoHeapMetadata;
    if (metaAddr == 0) {
        ImGui::TextUnformatted("No PSYQo heap registered.");
        ImGui::TextWrapped("The running program has not registered its heap metadata with the emulator. "
                           "This requires a PSYQo build with heap registration support.");
        ImGui::End();
        return;
    }

    auto headPtr = readGuest32(memory, metaAddr + 0);
    auto bottomPtr = readGuest32(memory, metaAddr + 4);
    auto topPtr = readGuest32(memory, metaAddr + 8);
    auto maxEnd = readGuest32(memory, metaAddr + 12);
    uint32_t markerPtr = metaAddr + 16;

    if (!headPtr || !bottomPtr || !topPtr) {
        ImGui::Text("Heap metadata at %08x contains invalid pointers - likely corrupted metadata.", metaAddr);
        ImGui::End();
        return;
    }

    ImGui::Text("Heap range: %08x - %08x (%u bytes)", bottomPtr ? *bottomPtr : 0, topPtr ? *topPtr : 0, bottomPtr && topPtr ? *topPtr - *bottomPtr : 0);
    ImGui::Text("High-water mark: %08x", maxEnd ? *maxEnd : 0);
    ImGui::Text("Free list head: %08x  Marker: %08x", headPtr ? *headPtr : 0, markerPtr);
    ImGui::Separator();

    auto result = walkHeap(memory);

    // Show corruption warning prominently if detected.
    if (!result.error.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.8f, 0.0f, 1.0f));
        ImGui::TextWrapped("Heap corruption detected: %s", result.error.c_str());
        ImGui::PopStyleColor();
        ImGui::Separator();
    }

    auto& blocks = result.blocks;
    if (blocks.empty()) {
        ImGui::TextUnformatted("Heap not yet initialized.");
        ImGui::End();
        return;
    }

    // Summary stats.
    uint32_t totalFree = 0;
    uint32_t totalAlloc = 0;
    uint32_t freeCount = 0;
    uint32_t allocCount = 0;
    uint32_t largestFree = 0;
    for (auto& b : blocks) {
        if (b.free) {
            totalFree += b.size;
            freeCount++;
            if (b.size > largestFree) largestFree = b.size;
        } else {
            totalAlloc += b.size;
            allocCount++;
        }
    }

    uint32_t totalAccountedFor = totalFree + totalAlloc;
    uint32_t heapSize = topPtr && bottomPtr ? *topPtr - *bottomPtr : 0;

    ImGui::Text("Allocated: %u bytes (%u blocks)  Free: %u bytes (%u blocks)", totalAlloc, allocCount, totalFree,
                freeCount);
    ImGui::Text("Largest free block: %u bytes  Fragmentation: %u fragments", largestFree, freeCount);

    // Flag if accounting doesn't add up.
    if (heapSize > 0 && totalAccountedFor != heapSize) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.8f, 0.0f, 1.0f));
        ImGui::Text("Accounting mismatch: blocks sum to %u bytes, heap is %u bytes (%d unaccounted)",
                     totalAccountedFor, heapSize, (int)heapSize - (int)totalAccountedFor);
        ImGui::PopStyleColor();
    }

    ImGui::Separator();

    // Visual heap map.
    if (heapSize > 0) {
        ImVec2 avail = ImGui::GetContentRegionAvail();
        float barWidth = avail.x;
        float barHeight = 20.0f;

        ImVec2 barPos = ImGui::GetCursorScreenPos();
        ImDrawList* drawList = ImGui::GetWindowDrawList();

        for (auto& b : blocks) {
            float x0 = barWidth * (float)(b.address - (bottomPtr ? *bottomPtr : 0)) / (float)heapSize;
            float x1 = barWidth * (float)(b.address + b.size - (bottomPtr ? *bottomPtr : 0)) / (float)heapSize;
            // Clamp to bar bounds.
            if (x0 < 0) x0 = 0;
            if (x1 > barWidth) x1 = barWidth;
            ImU32 color = b.free ? IM_COL32(60, 120, 60, 255) : IM_COL32(180, 60, 60, 255);
            drawList->AddRectFilled(ImVec2(barPos.x + x0, barPos.y),
                                    ImVec2(barPos.x + x1, barPos.y + barHeight), color);
        }

        drawList->AddRect(ImVec2(barPos.x, barPos.y), ImVec2(barPos.x + barWidth, barPos.y + barHeight),
                          IM_COL32(200, 200, 200, 255));
        ImGui::Dummy(ImVec2(barWidth, barHeight));

        // Tooltip on hover, jump to memory on click.
        if (ImGui::IsItemHovered()) {
            float mouseX = ImGui::GetMousePos().x - barPos.x;
            uint32_t hoverAddr = bottomPtr ? *bottomPtr + (uint32_t)((float)heapSize * mouseX / barWidth) : 0;
            for (auto& b : blocks) {
                if (hoverAddr >= b.address && hoverAddr < b.address + b.size) {
                    ImGui::BeginTooltip();
                    ImGui::Text("%s at %08x, %u bytes", b.free ? "Free" : "Allocated", b.address, b.size);
                    if (!b.free && b.size > 8) {
                        ImGui::Text("User payload: %u bytes (click to jump)", b.size - 8);
                    } else {
                        ImGui::TextUnformatted("Click to jump");
                    }
                    ImGui::EndTooltip();
                    if (ImGui::IsMouseClicked(0)) {
                        // For allocated blocks, jump to user data (past the 8-byte header).
                        // For free blocks, jump to the block start.
                        uint32_t jumpAddr = b.free ? b.address : b.address + 8;
                        uint32_t jumpSize = b.free ? b.size : (b.size > 8 ? b.size - 8 : b.size);
                        g_system->m_eventBus->signal(
                            Events::GUI::JumpToMemory{jumpAddr | 0x80000000, jumpSize});
                    }
                    break;
                }
            }
        }

        // Legend.
        ImGui::ColorButton("##alloc", ImVec4(180.0f / 255, 60.0f / 255, 60.0f / 255, 1.0f),
                           ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoPicker, ImVec2(12, 12));
        ImGui::SameLine();
        ImGui::Text("Allocated");
        ImGui::SameLine();
        ImGui::ColorButton("##free", ImVec4(60.0f / 255, 120.0f / 255, 60.0f / 255, 1.0f),
                           ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoPicker, ImVec2(12, 12));
        ImGui::SameLine();
        ImGui::Text("Free");
    }

    ImGui::Separator();

    // Block table.
    if (ImGui::BeginTable("HeapBlocks", 4,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                              ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp,
                          ImVec2(0, 0))) {
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Size");
        ImGui::TableSetupColumn("User size");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (size_t i = 0; i < blocks.size(); i++) {
            auto& b = blocks[i];
            ImGui::TableNextRow();
            ImGui::TableNextColumn();

            // Make the entire row clickable via a Selectable spanning all columns.
            char label[32];
            snprintf(label, sizeof(label), "%08x##block%zu", b.address, i);
            if (ImGui::Selectable(label, false,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                uint32_t jumpAddr = b.free ? b.address : b.address + 8;
                uint32_t jumpSize = b.free ? b.size : (b.size > 8 ? b.size - 8 : b.size);
                g_system->m_eventBus->signal(Events::GUI::JumpToMemory{jumpAddr | 0x80000000, jumpSize});
            }
            ImGui::TableNextColumn();
            ImGui::Text("%u", b.size);
            ImGui::TableNextColumn();
            if (!b.free) {
                ImGui::Text("%u", b.size > 8 ? b.size - 8 : 0);
            } else {
                ImGui::TextUnformatted("-");
            }
            ImGui::TableNextColumn();
            if (b.free) {
                ImGui::TextColored(ImVec4(0.3f, 0.8f, 0.3f, 1.0f), "Free");
            } else {
                ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "Allocated");
            }
        }

        ImGui::EndTable();
    }

    ImGui::End();
}
