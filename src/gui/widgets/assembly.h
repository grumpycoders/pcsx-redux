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

#include "core/disr3000a.h"
#include "gui/widgets/filedialog.h"

struct MemoryEditor;

namespace PCSX {

struct psxRegisters;

class Memory;

namespace Widgets {

class Assembly : private Disasm {
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
    bool m_displayArrowForJumps = false;
    int m_numColumns = 4;
    char m_jumpAddressString[20];
    std::map<uint32_t, std::string> m_symbols;
    FileDialog m_symbolsFileDialog = {[]() { return _("Load Symbols"); }};
    MemoryEditor* m_mainMemoryEditor = nullptr;
    MemoryEditor* m_hwMemoryEditor = nullptr;
    std::vector<std::pair<uint32_t, uint32_t>> m_arrows;

    // Disasm section
    void sameLine();
    void comma();
    uint8_t* ptr(uint32_t addr);
    void jumpToMemory(uint32_t addr, int size);
    uint8_t mem8(uint32_t addr);
    uint16_t mem16(uint32_t addr);
    uint32_t mem32(uint32_t addr);
    virtual void Invalid() final;
    virtual void OpCode(const char* str) final;
    virtual void GPR(uint8_t reg) final;
    virtual void CP0(uint8_t reg) final;
    virtual void CP2C(uint8_t reg) final;
    virtual void CP2D(uint8_t reg) final;
    virtual void HI() final;
    virtual void LO() final;
    virtual void Imm(uint16_t value) final;
    virtual void Imm32(uint32_t value) final;
    virtual void Target(uint32_t value) final;
    virtual void Sa(uint8_t value) final;
    virtual void OfB(int16_t offset, uint8_t reg, int size) final;
    virtual void BranchDest(uint32_t value) final;
    virtual void Offset(uint32_t addr, int size) final;
    bool m_gotArg = false;
    bool m_notch = false;
    psxRegisters* m_registers;
    uint32_t m_currentAddr = 0;
    bool m_jumpToPC = false;
    uint32_t m_jumpToPCValue = 0;
    Memory* m_memory;
    uint32_t m_ramBase = 0x80000000;
};

}  // namespace Widgets
}  // namespace PCSX
