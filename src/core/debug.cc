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

#include <iomanip>
#include <sstream>

#include "core/debug.h"
#include "core/disr3000a.h"
#include "core/gpu.h"
#include "core/psxemulator.h"
#include "core/r3000a.h"

enum {
    MAP_EXEC = 1,
    MAP_R8 = 2,
    MAP_R16 = 4,
    MAP_R32 = 8,
    MAP_W8 = 16,
    MAP_W16 = 32,
    MAP_W32 = 64,
    MAP_EXEC_JAL = 128,
};

void PCSX::Debug::MarkMap(uint32_t address, int mask) {
    uint32_t base = (address >> 20) & 0xffc;
    uint32_t real = address & 0x1fffff;
    if (((base == 0x000) || (base == 0x800) || (base == 0xa00)) && (real < sizeof(m_mainMemoryMap))) {
        m_mainMemoryMap[real] |= mask;
    } else if ((base == 0x1f0) && (real < sizeof(m_parpMemoryMap))) {
        m_parpMemoryMap[real] |= mask;
    } else if ((base == 0x1f8) && (real < sizeof(m_scratchPadMap))) {
        m_scratchPadMap[real] |= mask;
    } else if ((base == 0xbfc) && (real < sizeof(m_biosMemoryMap))) {
        m_biosMemoryMap[real] |= mask;
    }
}

bool PCSX::Debug::IsMapMarked(uint32_t address, int mask) {
    uint32_t base = (address >> 20) & 0xffc;
    uint32_t real = address & 0x1fffff;
    if (((base == 0x000) || (base == 0x800) || (base == 0xa00)) && (real < sizeof(m_mainMemoryMap))) {
        return m_mainMemoryMap[real] & mask;
    } else if ((base == 0x1f0) && (real < sizeof(m_parpMemoryMap))) {
        return m_parpMemoryMap[real] & mask;
    } else if ((base == 0x1f8) && (real < sizeof(m_scratchPadMap))) {
        return m_scratchPadMap[real] & mask;
    } else if ((base == 0xbfc) && (real < sizeof(m_biosMemoryMap))) {
        return m_biosMemoryMap[real] & mask;
    }
    return false;
}

void PCSX::Debug::ProcessDebug() {
    const uint32_t& pc = PCSX::g_emulator.m_psxCpu->m_psxRegs.pc;
    DebugCheckBP(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc, BE);
    if (m_mapping_e) {
        MarkMap(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc, MAP_EXEC);
        // JAL
        if ((PCSX::g_emulator.m_psxCpu->m_psxRegs.code >> 26) == 3) {
            MarkMap(_JumpTarget_, MAP_EXEC_JAL);
        }
        // JALR
        if (((PCSX::g_emulator.m_psxCpu->m_psxRegs.code >> 26) == 0) &&
            ((PCSX::g_emulator.m_psxCpu->m_psxRegs.code & 0x3F) == 9)) {
            MarkMap(_Rd_, MAP_EXEC_JAL);
        }
    }
}

void PCSX::Debug::triggerBP(bpiterator bp) {
    if (bp->m_temporary) {
        m_lastBP = m_breakpoints.end();
        m_breakpoints.erase(bp);
    } else {
        m_lastBP = bp;
    }
    PCSX::g_system->pause();
}

void PCSX::Debug::DebugCheckBP(uint32_t address, BreakpointType type) {
    if (m_mapping_r8 && type == BR1) MarkMap(address, MAP_R8);
    if (m_mapping_r16 && type == BR2) MarkMap(address, MAP_R16);
    if (m_mapping_r32 && type == BR4) MarkMap(address, MAP_R32);
    if (m_mapping_w8 && type == BW1) MarkMap(address, MAP_W8);
    if (m_mapping_w16 && type == BW2) MarkMap(address, MAP_W16);
    if (m_mapping_w32 && type == BW4) MarkMap(address, MAP_W32);

    for (auto it = m_breakpoints.begin(); it != m_breakpoints.end(); it++) {
        if ((it->m_type == type) && (it->m_address == address)) {
            triggerBP(it);
            return;
        }
    }

    auto none = m_breakpoints.end();

    if (m_breakmp_e && type == BE && !IsMapMarked(address, MAP_EXEC)) {
        triggerBP(none);
        return;
    } else if (m_breakmp_r8 && type == BR1 && !IsMapMarked(address, MAP_R8)) {
        triggerBP(none);
        return;
    } else if (m_breakmp_r16 && type == BR2 && !IsMapMarked(address, MAP_R16)) {
        triggerBP(none);
        return;
    } else if (m_breakmp_r32 && type == BR4 && !IsMapMarked(address, MAP_R32)) {
        triggerBP(none);
        return;
    } else if (m_breakmp_w8 && type == BW1 && !IsMapMarked(address, MAP_W8)) {
        triggerBP(none);
        return;
    } else if (m_breakmp_w16 && type == BW2 && !IsMapMarked(address, MAP_W16)) {
        triggerBP(none);
        return;
    } else if (m_breakmp_w32 && type == BW4 && !IsMapMarked(address, MAP_W32)) {
        triggerBP(none);
        return;
    }
}

std::string PCSX::Debug::GenerateFlowIDC() {
    std::stringstream ss;
    ss << "#include <idc.idc>\r\n\r\n";
    ss << "static main(void) {\r\n";
    for (uint32_t i = 0; i < 0x00200000; i++) {
        if (IsMapMarked(i, MAP_EXEC_JAL)) {
            ss << "\tMakeFunction(0X8" << std::hex << std::setw(7) << std::setfill('0') << i << ", BADADDR);\r\n ";
        }
    }
    ss << "}\r\n";
    return ss.str();
}

std::string PCSX::Debug::GenerateMarkIDC() {
    std::stringstream ss;
    ss << "#include <idc.idc>\r\n\r\n";
    ss << "static main(void) {\r\n";
    for (uint32_t i = 0; i < 0x00200000; i++) {
        if (IsMapMarked(i, MAP_EXEC)) {
            ss << "\tMakeCode(0X8" << std::hex << std::setw(7) << std::setfill('0') << i << ");\r\n";
        }
    }
    ss << "}\r\n";
    return ss.str();
}
