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

#include "gui/widgets/msan_viewer.h"

#include <algorithm>
#include <cstdio>

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "gui/gui.h"
#include "imgui.h"

void PCSX::Widgets::MsanViewer::draw(GUI* gui, Memory* memory, const char* title) {
    ImGui::SetNextWindowPos(ImVec2(400, 100), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(700, 600), ImGuiCond_FirstUseEver);

    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    if (!memory->msanInitialized()) {
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "MSAN is not initialized.");
        ImGui::TextWrapped(
            "MSAN is activated by PSX software writing to hardware register 0x1f802089. "
            "Run a program built with PSYQo's MSAN-enabled allocator to use this viewer.");
        ImGui::End();
        return;
    }

    if (ImGui::BeginTabBar("MsanTabs")) {
        if (ImGui::BeginTabItem("Status")) {
            drawStatusPanel(gui, memory);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Allocations")) {
            drawAllocationTable(gui, memory);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Memory Map")) {
            drawBitmapVisualization(gui, memory);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Chain Registry")) {
            drawChainRegistry(gui, memory);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::End();

    drawHexEditor(gui, memory);
}

void PCSX::Widgets::MsanViewer::drawStatusPanel(GUI* gui, Memory* memory) {
    uint32_t totalAllocated = 0;
    uint32_t totalInitialized = 0;
    uint32_t allocCount = memory->m_msanAllocs.size();

    for (auto& [offset, size] : memory->m_msanAllocs) {
        totalAllocated += size;
        for (uint32_t i = 0; i < size; i++) {
            if (memory->m_msanInitializedBitmap[(offset + i) / 8] & (1 << ((offset + i) % 8))) {
                totalInitialized++;
            }
        }
    }

    ImGui::SeparatorText("Memory Usage");
    gui->useMonoFont();

    float watermarkMB = memory->m_msanPtr / (1024.0f * 1024.0f);
    float totalMB = Memory::c_msanSize / (1024.0f * 1024.0f);
    float usagePercent = (float)memory->m_msanPtr / Memory::c_msanSize;

    ImGui::Text("Watermark:     0x%08x (%.2f MB / %.0f MB)", memory->m_msanPtr, watermarkMB, totalMB);
    ImGui::ProgressBar(usagePercent, ImVec2(-1, 0), "");
    ImGui::Text("Allocations:   %u", allocCount);
    ImGui::Text("Allocated:     %u bytes (%.2f KB)", totalAllocated, totalAllocated / 1024.0f);
    ImGui::Text("Initialized:   %u / %u bytes (%.1f%%)", totalInitialized, totalAllocated,
                totalAllocated > 0 ? 100.0f * totalInitialized / totalAllocated : 0.0f);
    ImGui::Text("Chain entries: %zu", memory->m_msanChainRegistry.size());

    ImGui::PopFont();
}

float PCSX::Widgets::MsanViewer::computeInitializedPercent(Memory* memory, uint32_t offset, uint32_t size) {
    if (size == 0) return 0.0f;
    uint32_t initialized = 0;
    for (uint32_t i = 0; i < size; i++) {
        if (memory->m_msanInitializedBitmap[(offset + i) / 8] & (1 << ((offset + i) % 8))) {
            initialized++;
        }
    }
    return 100.0f * initialized / size;
}

void PCSX::Widgets::MsanViewer::drawAllocationTable(GUI* gui, Memory* memory) {
    // Rebuild sorted allocation list
    m_sortedAllocs.clear();
    m_sortedAllocs.reserve(memory->m_msanAllocs.size());
    for (auto& [offset, size] : memory->m_msanAllocs) {
        m_sortedAllocs.push_back({offset, size, computeInitializedPercent(memory, offset, size)});
    }

    switch (m_sortColumn) {
        case SortColumn::Address:
            std::sort(m_sortedAllocs.begin(), m_sortedAllocs.end(), [this](const AllocEntry& a, const AllocEntry& b) {
                return m_sortAscending ? a.offset < b.offset : a.offset > b.offset;
            });
            break;
        case SortColumn::Size:
            std::sort(m_sortedAllocs.begin(), m_sortedAllocs.end(), [this](const AllocEntry& a, const AllocEntry& b) {
                return m_sortAscending ? a.size < b.size : a.size > b.size;
            });
            break;
        case SortColumn::Initialized:
            std::sort(m_sortedAllocs.begin(), m_sortedAllocs.end(), [this](const AllocEntry& a, const AllocEntry& b) {
                return m_sortAscending ? a.initializedPercent < b.initializedPercent
                                       : a.initializedPercent > b.initializedPercent;
            });
            break;
    }

    ImGui::Text("%zu live allocations", m_sortedAllocs.size());
    ImGui::SameLine();
    if (ImGui::Button("Open Hex Editor")) {
        m_showHexEditor = true;
    }

    if (ImGui::BeginTable("AllocTable", 5,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Sortable |
                              ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
                          ImVec2(0, -1))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_DefaultSort, 0.0f, (int)SortColumn::Address);
        ImGui::TableSetupColumn("Size", 0, 0.0f, (int)SortColumn::Size);
        ImGui::TableSetupColumn("Initialized", 0, 0.0f, (int)SortColumn::Initialized);
        ImGui::TableSetupColumn("Status Bar", ImGuiTableColumnFlags_NoSort);
        ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_NoSort);
        ImGui::TableHeadersRow();

        // Handle sorting
        if (ImGuiTableSortSpecs* sortSpecs = ImGui::TableGetSortSpecs()) {
            if (sortSpecs->SpecsDirty && sortSpecs->SpecsCount > 0) {
                m_sortColumn = (SortColumn)sortSpecs->Specs[0].ColumnUserID;
                m_sortAscending = sortSpecs->Specs[0].SortDirection == ImGuiSortDirection_Ascending;
                sortSpecs->SpecsDirty = false;
            }
        }

        gui->useMonoFont();
        ImGuiListClipper clipper;
        clipper.Begin(m_sortedAllocs.size());
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                auto& alloc = m_sortedAllocs[i];
                ImGui::TableNextRow();

                ImGui::TableNextColumn();
                ImGui::Text("0x%08x", alloc.offset + c_msanStart);

                ImGui::TableNextColumn();
                ImGui::Text("%u", alloc.size);

                ImGui::TableNextColumn();
                if (alloc.initializedPercent >= 100.0f) {
                    ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "100%%");
                } else if (alloc.initializedPercent == 0.0f) {
                    ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "0%%");
                } else {
                    ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "%.1f%%", alloc.initializedPercent);
                }

                ImGui::TableNextColumn();
                ImGui::PushID(i);
                ImVec4 barColor = alloc.initializedPercent >= 100.0f ? ImVec4(0.0f, 0.8f, 0.0f, 1.0f)
                                  : alloc.initializedPercent > 0.0f  ? ImVec4(0.8f, 0.8f, 0.0f, 1.0f)
                                                                     : ImVec4(0.8f, 0.2f, 0.2f, 1.0f);
                ImGui::PushStyleColor(ImGuiCol_PlotHistogram, barColor);
                ImGui::ProgressBar(alloc.initializedPercent / 100.0f, ImVec2(-1, ImGui::GetTextLineHeight()));
                ImGui::PopStyleColor();
                ImGui::PopID();

                ImGui::TableNextColumn();
                ImGui::PushID(i + 100000);
                if (ImGui::SmallButton("View")) {
                    m_showHexEditor = true;
                    m_hexEditor.GotoAddrAndHighlight(alloc.offset, alloc.offset + alloc.size);
                }
                ImGui::PopID();
            }
        }
        ImGui::PopFont();

        ImGui::EndTable();
    }
}

void PCSX::Widgets::MsanViewer::drawBitmapVisualization(GUI* gui, Memory* memory) {
    ImGui::SliderInt("Bytes per pixel", (int*)&m_bitmapBytesPerPixel, 1, 1024, "%d", ImGuiSliderFlags_Logarithmic);

    // Only visualize up to the watermark, not the full 1.5GB
    uint32_t visibleBytes = memory->m_msanPtr;
    if (visibleBytes == 0) {
        ImGui::Text("No allocations yet.");
        return;
    }

    float availWidth = ImGui::GetContentRegionAvail().x;
    int columns = std::max(1, (int)(availWidth / 2.0f));  // 2px per cell
    int rows = (visibleBytes / m_bitmapBytesPerPixel + columns - 1) / columns;
    rows = std::min(rows, 2048);  // cap to avoid insane draw lists

    ImVec2 canvasPos = ImGui::GetCursorScreenPos();
    ImVec2 canvasSize(columns * 2.0f, rows * 2.0f);

    ImGui::InvisibleButton("bitmap_canvas", canvasSize);
    ImDrawList* drawList = ImGui::GetWindowDrawList();

    // Color legend
    {
        ImDrawList* legendDraw = ImGui::GetWindowDrawList();
        float sz = ImGui::GetTextLineHeight();
        auto legendItem = [&](ImU32 col, const char* label) {
            ImVec2 p = ImGui::GetCursorScreenPos();
            legendDraw->AddRectFilled(p, ImVec2(p.x + sz, p.y + sz), col);
            ImGui::Dummy(ImVec2(sz, sz));
            ImGui::SameLine();
            ImGui::Text("%s", label);
            ImGui::SameLine();
        };
        legendItem(IM_COL32(50, 50, 50, 255), "Unusable");
        legendItem(IM_COL32(255, 150, 0, 255), "Uninitialized");
        legendItem(IM_COL32(0, 200, 0, 255), "OK");
        ImGui::NewLine();
    }

    for (int row = 0; row < rows; row++) {
        for (int col = 0; col < columns; col++) {
            uint32_t byteOffset = ((uint32_t)row * columns + col) * m_bitmapBytesPerPixel;
            if (byteOffset >= visibleBytes) break;

            // Sample the status of this pixel's byte range
            // Check the first byte as representative
            uint32_t bitmapIndex = byteOffset / 8;
            uint8_t bitmask = 1 << (byteOffset % 8);

            ImU32 color;
            if (memory->m_msanUsableBitmap[bitmapIndex] & bitmask) {
                if (memory->m_msanInitializedBitmap[bitmapIndex] & bitmask) {
                    color = IM_COL32(0, 200, 0, 255);  // OK - green
                } else {
                    color = IM_COL32(255, 150, 0, 255);  // Uninitialized - orange
                }
            } else {
                color = IM_COL32(50, 50, 50, 255);  // Unusable - dark
            }

            ImVec2 p0(canvasPos.x + col * 2.0f, canvasPos.y + row * 2.0f);
            ImVec2 p1(p0.x + 2.0f, p0.y + 2.0f);
            drawList->AddRectFilled(p0, p1, color);
        }
    }

    // Tooltip on hover
    if (ImGui::IsItemHovered()) {
        ImVec2 mousePos = ImGui::GetMousePos();
        int col = (int)((mousePos.x - canvasPos.x) / 2.0f);
        int row = (int)((mousePos.y - canvasPos.y) / 2.0f);
        if (col >= 0 && col < columns && row >= 0 && row < rows) {
            uint32_t byteOffset = ((uint32_t)row * columns + col) * m_bitmapBytesPerPixel;
            if (byteOffset < visibleBytes) {
                uint32_t addr = byteOffset + c_msanStart;
                uint32_t bitmapIndex = byteOffset / 8;
                uint8_t bitmask = 1 << (byteOffset % 8);
                bool usable = memory->m_msanUsableBitmap[bitmapIndex] & bitmask;
                bool initialized = memory->m_msanInitializedBitmap[bitmapIndex] & bitmask;

                ImGui::BeginTooltip();
                gui->useMonoFont();
                ImGui::Text("Address: 0x%08x", addr);
                ImGui::Text("Offset:  0x%08x", byteOffset);
                if (usable) {
                    ImGui::Text("Status:  %s", initialized ? "OK" : "UNINITIALIZED");
                } else {
                    ImGui::Text("Status:  UNUSABLE");
                }
                // Find if this belongs to an allocation
                for (auto& [allocOffset, allocSize] : memory->m_msanAllocs) {
                    if (byteOffset >= allocOffset && byteOffset < allocOffset + allocSize) {
                        ImGui::Text("Alloc:   0x%08x (%u bytes)", allocOffset + c_msanStart, allocSize);
                        break;
                    }
                }
                ImGui::PopFont();
                ImGui::EndTooltip();
            }
        }
    }
}

void PCSX::Widgets::MsanViewer::drawChainRegistry(GUI* gui, Memory* memory) {
    ImGui::Text("%zu chain entries", memory->m_msanChainRegistry.size());

    if (memory->m_msanChainRegistry.empty()) {
        ImGui::TextWrapped(
            "No GPU DMA chain entries registered. Chain entries are created when PSX software "
            "sets up ordering tables with MSAN-allocated memory.");
        return;
    }

    if (ImGui::BeginTable("ChainTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                          ImVec2(0, -1))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Header Address");
        ImGui::TableSetupColumn("Chain Pointer");
        ImGui::TableHeadersRow();

        gui->useMonoFont();
        for (auto& [headerAddr, chainPtr] : memory->m_msanChainRegistry) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("0x%08x", headerAddr);
            ImGui::TableNextColumn();
            ImGui::Text("0x%08x", chainPtr);
        }
        ImGui::PopFont();

        ImGui::EndTable();
    }
}

void PCSX::Widgets::MsanViewer::drawHexEditor(GUI* gui, Memory* memory) {
    if (!m_showHexEditor) return;
    if (!memory->msanInitialized()) {
        m_showHexEditor = false;
        return;
    }

    m_hexEditor.OptShowDataPreview = true;
    m_hexEditor.OptUpperCaseHex = false;
    m_hexEditor.PushMonoFont = [gui]() { gui->useMonoFont(); };

    // Color bytes based on MSAN status.
    // HighlightFn is a raw function pointer so we use a static to pass context.
    static Memory* s_highlightMemory = nullptr;
    s_highlightMemory = memory;
    m_hexEditor.HighlightFn = [](size_t off) -> bool {
        if (!s_highlightMemory || off >= Memory::c_msanSize) return false;
        uint32_t bitmapIndex = (uint32_t)off / 8;
        uint8_t bitmask = 1 << ((uint32_t)off % 8);
        // Highlight anything that isn't fully OK (usable + initialized)
        bool usable = s_highlightMemory->m_msanUsableBitmap[bitmapIndex] & bitmask;
        bool initialized = s_highlightMemory->m_msanInitializedBitmap[bitmapIndex] & bitmask;
        return !usable || !initialized;
    };
    m_hexEditor.ReadFn = [memory](size_t off) -> ImU8 { return ((uint8_t*)memory->m_msanRAM)[off]; };
    // Orange highlight for problematic bytes
    m_hexEditor.HighlightColor = IM_COL32(255, 150, 0, 80);

    ImGui::SetNextWindowPos(ImVec2(500, 200), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(484, 480), ImGuiCond_FirstUseEver);
    m_hexEditor.DrawWindow("MSAN Memory Editor", memory->m_msanPtr);
}
