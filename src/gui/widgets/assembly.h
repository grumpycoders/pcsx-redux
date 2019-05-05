/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include "gui/widgets/filedialog.h"

struct psxRegisters;
struct MemoryEditor;

namespace PCSX {

class Memory;

namespace Widgets {

class Assembly {
  public:
    Assembly(MemoryEditor* mainMemoryEditor, MemoryEditor* hwMemoryEditor)
        : m_mainMemoryEditor(mainMemoryEditor), m_hwMemoryEditor(hwMemoryEditor) {
        memset(m_jumpAddressString, 0, sizeof(m_jumpAddressString));
    }
    void draw(psxRegisters* registers, Memory* memory, const char* title);

    bool m_show = false;

  private:
    bool m_followPC = false;
    bool m_pseudoFilling = true;
    bool m_pseudo = true;
    bool m_delaySlotNotch = true;
    char m_jumpAddressString[20];
    std::map<uint32_t, std::string> m_symbols;
    FileDialog m_symbolsFileDialog = {"Load Symbols"};
    MemoryEditor* m_mainMemoryEditor;
    MemoryEditor* m_hwMemoryEditor;
};

}  // namespace Widgets
}  // namespace PCSX
