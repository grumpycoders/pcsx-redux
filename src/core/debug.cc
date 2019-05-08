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

void PCSX::Debug::markMap(uint32_t address, int mask) {
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

bool PCSX::Debug::isMapMarked(uint32_t address, int mask) {
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

void PCSX::Debug::processBefore() {
    const uint32_t& pc = PCSX::g_emulator.m_psxCpu->m_psxRegs.pc;
    const bool isJAL = (PCSX::g_emulator.m_psxCpu->m_psxRegs.code >> 26) == 3;
    const bool isJALR = ((PCSX::g_emulator.m_psxCpu->m_psxRegs.code >> 26) == 0) &&
                        ((PCSX::g_emulator.m_psxCpu->m_psxRegs.code & 0x3F) == 9);
    const bool isJRRA = ((PCSX::g_emulator.m_psxCpu->m_psxRegs.code >> 26) == 0) &&
                        ((PCSX::g_emulator.m_psxCpu->m_psxRegs.code & 0x3f) == 8) && _Rs_ == 31;

    if (m_stepping) {
        if (isJAL || isJALR) m_steppingJumps++;
        if (isJRRA) m_steppingJumps--;

        auto none = m_breakpoints.end();
        switch (m_stepType) {
            case STEP_IN:
                triggerBP(none);
                break;
            case STEP_OVER:
                if (m_steppingJumps == 0) triggerBP(none);
                break;
            case STEP_OUT:
                if (m_steppingJumps == -1) triggerBP(none);
                break;
        }
    }

    if (m_mapping_e) {
        markMap(pc, MAP_EXEC);
        if (isJAL) markMap(_JumpTarget_, MAP_EXEC_JAL);
        if (isJALR) markMap(_Rd_, MAP_EXEC_JAL);
    }
}

void PCSX::Debug::processAfter() {
    const uint32_t& pc = PCSX::g_emulator.m_psxCpu->m_psxRegs.pc;
    checkBP(pc, BE);
}

void PCSX::Debug::startStepping() {
    if (PCSX::g_system->running()) return;
    m_stepping = true;
    m_steppingJumps = 0;
    g_system->resume();
}

void PCSX::Debug::triggerBP(bpiterator bp) {
    m_stepping = false;
    if (bp != m_breakpoints.end() && bp->second.m_temporary) {
        m_lastBP = m_breakpoints.end();
        m_breakpoints.erase(bp);
    } else {
        m_lastBP = bp;
    }
    PCSX::g_system->pause();
}

void PCSX::Debug::checkBP(uint32_t address, BreakpointType type) {
    for (auto it = m_breakpoints.begin(); it != m_breakpoints.end(); it++) {
        if ((it->second.m_type == type) && (it->first == address)) {
            triggerBP(it);
            break;
        }
    }

    auto none = m_breakpoints.end();

    if (m_breakmp_e && type == BE && !isMapMarked(address, MAP_EXEC)) {
        triggerBP(none);
    } else if (m_breakmp_r8 && type == BR1 && !isMapMarked(address, MAP_R8)) {
        triggerBP(none);
    } else if (m_breakmp_r16 && type == BR2 && !isMapMarked(address, MAP_R16)) {
        triggerBP(none);
    } else if (m_breakmp_r32 && type == BR4 && !isMapMarked(address, MAP_R32)) {
        triggerBP(none);
    } else if (m_breakmp_w8 && type == BW1 && !isMapMarked(address, MAP_W8)) {
        triggerBP(none);
    } else if (m_breakmp_w16 && type == BW2 && !isMapMarked(address, MAP_W16)) {
        triggerBP(none);
    } else if (m_breakmp_w32 && type == BW4 && !isMapMarked(address, MAP_W32)) {
        triggerBP(none);
    }

    if (m_mapping_r8 && type == BR1) markMap(address, MAP_R8);
    if (m_mapping_r16 && type == BR2) markMap(address, MAP_R16);
    if (m_mapping_r32 && type == BR4) markMap(address, MAP_R32);
    if (m_mapping_w8 && type == BW1) markMap(address, MAP_W8);
    if (m_mapping_w16 && type == BW2) markMap(address, MAP_W16);
    if (m_mapping_w32 && type == BW4) markMap(address, MAP_W32);
}

std::string PCSX::Debug::generateFlowIDC() {
    std::stringstream ss;
    ss << "#include <idc.idc>\r\n\r\n";
    ss << "static main(void) {\r\n";
    for (uint32_t i = 0; i < 0x00200000; i++) {
        if (isMapMarked(i, MAP_EXEC_JAL)) {
            ss << "\tMakeFunction(0X8" << std::hex << std::setw(7) << std::setfill('0') << i << ", BADADDR);\r\n ";
        }
    }
    ss << "}\r\n";
    return ss.str();
}

std::string PCSX::Debug::generateMarkIDC() {
    std::stringstream ss;
    ss << "#include <idc.idc>\r\n\r\n";
    ss << "static main(void) {\r\n";
    for (uint32_t i = 0; i < 0x00200000; i++) {
        if (isMapMarked(i, MAP_EXEC)) {
            ss << "\tMakeCode(0X8" << std::hex << std::setw(7) << std::setfill('0') << i << ");\r\n";
        }
    }
    ss << "}\r\n";
    return ss.str();
}
