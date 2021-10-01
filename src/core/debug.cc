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

#include "core/debug.h"

#include <iomanip>
#include <sstream>

#include "core/callstacks.h"
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

void PCSX::Debug::process(uint32_t oldPC, uint32_t newPC, uint32_t code) {
    const uint32_t basic = code >> 26;
    const bool isAnyLoadOrStore = (basic >= 0x20) && (basic < 0x30);

    checkBP(newPC, BreakpointType::Exec, 4);
    if (m_breakmp_e && !isMapMarked(newPC, MAP_EXEC)) {
        triggerBP(nullptr, _("Execution map"));
    }
    if (m_mapping_e) {
        const bool isJAL = basic == 3;
        const bool isJALR = (basic == 0) && ((code & 0x3F) == 9);
        const uint32_t target = (code & 0x03ffffff) * 4 + (oldPC & 0xf0000000);
        const uint32_t rd = (code >> 11) & 0x1f;
        markMap(oldPC, MAP_EXEC);
        if (isJAL) markMap(target, MAP_EXEC_JAL);
        if (isJALR) markMap(g_emulator->m_psxCpu->m_psxRegs.GPR.r[rd], MAP_EXEC_JAL);
    }

    if (isAnyLoadOrStore) {
        const bool isLB = basic == 0x20;
        const bool isLH = basic == 0x21;
        const bool isLWL = basic == 0x22;
        const bool isLW = basic == 0x23;
        const bool isLBU = basic == 0x24;
        const bool isLHU = basic == 0x25;
        const bool isLWR = basic == 0x26;
        const bool isSB = basic == 0x28;
        const bool isSH = basic == 0x29;
        const bool isSWL = basic == 0x2a;
        const bool isSW = basic == 0x2b;
        const bool isSWR = basic == 0x2e;
        uint32_t offset = g_emulator->m_psxCpu->m_psxRegs.GPR.r[(code >> 21) & 0x1f] + int16_t(code);
        if (isLWL || isLWR || isSWR || isSWL) offset &= ~3;
        if (isLB || isLBU) {
            checkBP(offset, BreakpointType::Read, 1);
            if (m_breakmp_r8 && !isMapMarked(offset, MAP_R8)) {
                triggerBP(nullptr, _("Read 8 map"));
            }
            if (m_mapping_r8) markMap(offset, MAP_R8);
        }
        if (isLH || isLHU) {
            checkBP(offset, BreakpointType::Read, 2);
            if (m_breakmp_r16 && !isMapMarked(offset, MAP_R16)) {
                triggerBP(nullptr, _("Read 16 map"));
            }
            if (m_mapping_r16) markMap(offset, MAP_R16);
        }
        if (isLW || isLWR || isLWL) {
            checkBP(offset, BreakpointType::Read, 4);
            if (m_breakmp_r32 && !isMapMarked(offset, MAP_R32)) {
                triggerBP(nullptr, _("Read 32 map"));
            }
            if (m_mapping_r32) markMap(offset, MAP_R32);
        }
        if (isSB) {
            checkBP(offset, BreakpointType::Write, 1);
            if (m_breakmp_w8 && !isMapMarked(offset, MAP_W8)) {
                triggerBP(nullptr, _("Write 8 map"));
            }
            if (m_mapping_w8) markMap(offset, MAP_W8);
        }
        if (isSH) {
            checkBP(offset, BreakpointType::Write, 2);
            if (m_breakmp_w16 && !isMapMarked(offset, MAP_W16)) {
                triggerBP(nullptr, _("Write 16 map"));
            }
            if (m_mapping_w16) markMap(offset, MAP_W16);
        }
        if (isSW || isSWR || isSWL) {
            checkBP(offset, BreakpointType::Write, 4);
            if (m_breakmp_w32 && !isMapMarked(offset, MAP_W32)) {
                triggerBP(nullptr, _("Write 32 map"));
            }
            if (m_mapping_w32) markMap(offset, MAP_W32);
        }
    }

    if (m_step == STEP_NONE) return;
    if (!m_wasInISR && g_emulator->m_psxCpu->m_inISR) return;

    switch (m_step) {
        case STEP_IN: {
            triggerBP(nullptr, _("Step in"));
        } break;
        case STEP_OVER: {
        } break;
        case STEP_OUT: {
            if (!m_stepperHasBreakpoint) triggerBP(nullptr, _("Step out (no callstack)"));
        }
    }
}

void PCSX::Debug::startStepping() {
    if (PCSX::g_system->running()) return;
    m_wasInISR = g_emulator->m_psxCpu->m_inISR;
    g_system->resume();
}

bool PCSX::Debug::triggerBP(Breakpoint* bp, std::string_view reason) {
    uint32_t pc = g_emulator->m_psxCpu->m_psxRegs.pc;
    bool keepBP = true;
    std::string name;
    m_lastBP = nullptr;
    if (bp) {
        name = bp->name();
        keepBP = bp->trigger();
        if (keepBP) m_lastBP = bp;
    } else {
        g_system->pause();
    }
    if (g_system->running()) return keepBP;
    m_step = STEP_NONE;
    g_system->printf(_("Breakpoint triggered: PC=0x%08x - Cause: %s\n"), pc, name.empty() ? reason : name);
    return keepBP;
}

void PCSX::Debug::checkBP(uint32_t address, BreakpointType type, unsigned width) {
    auto none = m_breakpoints.end();
    address &= ~0xe0000000;

    BreakpointUserListType todelete;
    for (auto it = m_breakpoints.find(address, address + width - 1); it != m_breakpoints.end(); it++) {
        if (it->type() != type) continue;
        if (!triggerBP(&*it)) todelete.push_back(&*it);
    }
    todelete.destroyAll();
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

std::string PCSX::Debug::Breakpoint::name() const {
    return fmt::format("{:08x}::{}::{} ({})", address() | base(), s_breakpoint_type_names[unsigned(m_type)](), width(),
                       m_source);
}

void PCSX::Debug::stepOut() {
    m_step = STEP_OUT;
    startStepping();
    if (!g_emulator->m_callStacks->hasCurrent()) return;
    auto& callstack = g_emulator->m_callStacks->getCurrent();
    if ((callstack.calls.size() == 0) && (callstack.ra == 0)) return;

    auto call = callstack.calls.end();
    call--;
    uint32_t fp = call->fp;
    uint32_t ra = call->ra;

    if (ra == 0) return;
    if (fp == 0) return;

    addBreakpoint(ra, BreakpointType::Exec, 4, _("Step Out"), [fp, this](const Breakpoint* bp) {
        if (g_emulator->m_psxCpu->m_psxRegs.GPR.n.sp != fp) return true;
        g_system->pause();
        m_stepperHasBreakpoint = false;
        return false;
    });
    m_stepperHasBreakpoint = true;
}
