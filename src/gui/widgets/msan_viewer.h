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

#include <cstdint>
#include <string>
#include <vector>

#include "imgui.h"
#include "imgui_memory_editor/imgui_memory_editor.h"

namespace PCSX {

class GUI;
class Memory;

namespace Widgets {

class MsanViewer {
  public:
    MsanViewer(bool& show) : m_show(show), m_hexEditor(m_showHexEditor, c_msanStart, m_hexEditorAddr) {}
    void draw(GUI* gui, Memory* memory, const char* title);

    bool& m_show;

  private:
    static constexpr uint32_t c_msanStart = 0x20000000;

    // Hex editor for MSAN memory
    bool m_showHexEditor = false;
    size_t m_hexEditorAddr = 0;
    MemoryEditor m_hexEditor;

    // Bitmap visualization
    uint32_t m_bitmapBytesPerPixel = 64;

    // Cached sorted allocation list for the table
    struct AllocEntry {
        uint32_t offset;
        uint32_t size;
        float initializedPercent;
    };
    std::vector<AllocEntry> m_sortedAllocs;
    enum class SortColumn { Address, Size, Initialized };
    SortColumn m_sortColumn = SortColumn::Address;
    bool m_sortAscending = true;

    void drawStatusPanel(GUI* gui, Memory* memory);
    void drawAllocationTable(GUI* gui, Memory* memory);
    void drawBitmapVisualization(GUI* gui, Memory* memory);
    void drawChainRegistry(GUI* gui, Memory* memory);
    void drawHexEditor(GUI* gui, Memory* memory);

    float computeInitializedPercent(Memory* memory, uint32_t offset, uint32_t size);
};

}  // namespace Widgets

}  // namespace PCSX
