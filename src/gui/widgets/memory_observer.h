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

#include <stdint.h>

#include <vector>

#include "imgui.h"

namespace PCSX {

namespace Widgets {

class MemoryObserver {
public:
    void draw(const char* title);
    bool m_show = false;

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

    enum class ScanAlignment : uint8_t {
        OneByte = 1,
        TwoBytes = 2,
        FourBytes = 4
    };

    struct AddressValuePair {
        uint32_t address = 0;
        int scannedValue = 0;
    };

private:
    static int getMemValue(uint32_t absoluteAddress, const uint8_t* memData, uint32_t memSize, uint32_t memBase, uint8_t stride);

    ScanType m_scanType = ScanType::ExactValue;
    ScanAlignment m_scanAlignment = ScanAlignment::OneByte;
    std::vector<AddressValuePair> m_AddressValuePairs;
    bool m_hex = false;
    int m_value = 0;
};

}

}
