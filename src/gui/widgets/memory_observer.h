/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include <vector>

#include "imgui.h"
#include "imgui_memory_editor/imgui_memory_editor.h"

namespace PCSX {

namespace Widgets {

class MemoryObserver {
public:
    void draw(const char* title);
    bool m_show = false;

    MemoryObserver();

    enum class ScanType {
        ExactValue,
        BiggerThan,
        SmallerThan,
        Changed,
        Unchanged,
        Increased,
        Decreased,
        UnknownInitialValue
    };

    struct AddressValuePair {
        uint32_t address = 0;
        uint8_t scanned_value = 0;
    };

private:
    ScanType m_scantype = ScanType::ExactValue;
    std::vector<AddressValuePair> m_address_value_pairs;
    bool m_hex = false;
    int m_value = 0;
    bool m_showMemoryEditor = false;

    MemoryEditor m_memoryEditor;
};

}

}
