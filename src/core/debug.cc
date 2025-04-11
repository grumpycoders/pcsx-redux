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
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "supportpsx/memory.h"

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

PCSX::Debug::Debug() : m_listener(g_system->m_eventBus) {
    m_listener.listen<PCSX::Events::ExecutionFlow::Reset>([this](auto&) {
        m_checkKernel = false;
        clearMaps();
    });
}

uint32_t PCSX::Debug::normalizeAddress(uint32_t address) {
    PSXAddress addr(address);
    const bool ramExpansion = PCSX::g_emulator->settings.get<PCSX::Emulator::Setting8MB>();
    if (!ramExpansion && (addr.type == PSXAddress::Type::RAM)) {
        addr.physical &= ~0x00600000;
    }
    return addr.toVirtual().value_or(0xffffffff);
}

bool PCSX::Debug::isInKernel(uint32_t address, bool biosIsKernel) {
    PSXAddress addr(address);
    if (addr.type == PSXAddress::Type::MSAN) return false;
    const bool ramExpansion = PCSX::g_emulator->settings.get<PCSX::Emulator::Setting8MB>();
    if (addr.type == PSXAddress::Type::ROM) return biosIsKernel;
    if (addr.type != PSXAddress::Type::RAM) return false;
    if (!ramExpansion) addr.physical &= ~0x00600000;
    return addr.physical < 0x10000;
}

void PCSX::Debug::markMap(uint32_t address, int mask) {
    PSXAddress addr(normalizeAddress(address));

    switch (addr.type) {
        case PSXAddress::Type::RAM:
            if (addr.physical < sizeof(m_mainMemoryMap)) {
                m_mainMemoryMap[addr.physical] |= mask;
            }
            break;
        case PSXAddress::Type::ScratchPad:
            if (addr.physical < sizeof(m_scratchPadMap)) {
                m_scratchPadMap[addr.physical] |= mask;
            }
            break;
        case PSXAddress::Type::ROM:
            if (addr.physical < sizeof(m_biosMemoryMap)) {
                m_biosMemoryMap[addr.physical] |= mask;
            }
            break;
    }
}

bool PCSX::Debug::isMapMarked(uint32_t address, int mask) {
    PSXAddress addr(normalizeAddress(address));

    switch (addr.type) {
        case PSXAddress::Type::RAM:
            if (addr.physical < sizeof(m_mainMemoryMap)) {
                return m_mainMemoryMap[addr.physical] & mask;
            }
            break;
        case PSXAddress::Type::ScratchPad:
            if (addr.physical < sizeof(m_scratchPadMap)) {
                return m_scratchPadMap[addr.physical] & mask;
            }
            break;
        case PSXAddress::Type::ROM:
            if (addr.physical < sizeof(m_biosMemoryMap)) {
                return m_biosMemoryMap[addr.physical] & mask;
            }
            break;
    }
    return false;
}

void PCSX::Debug::process(uint32_t oldPC, uint32_t newPC, uint32_t oldCode, uint32_t newCode, bool linked) {
    const auto& regs = g_emulator->m_cpu->m_regs;
    const uint32_t basic = newCode >> 26;
    const bool isAnyLoadOrStore = (basic >= 0x20) && (basic < 0x3b);
    const bool isJAL = basic == 3;
    const bool isJR = (basic == 0) && ((newCode & 0x3f) == 8);
    const bool isJALR = (basic == 0) && ((newCode & 0x3f) == 9);
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
    const bool isLWC2 = basic == 0x32;
    const bool isSWC2 = basic == 0x3a;
    const bool isLoad = isLB || isLBU || isLH || isLHU || isLW || isLWL || isLWR || isLWC2;
    const bool isStore = isSB || isSH || isSW || isSWL || isSWR || isSWC2;
    const bool wasInKernel = isInKernel(oldPC);
    const bool isInKernelNow = isInKernel(newPC);
    const uint32_t target = (newCode & 0x03ffffff) * 4 + (newPC & 0xf0000000);
    const bool isTargetInKernel = isInKernel(target);
    const uint32_t rd = (newCode >> 11) & 0x1f;
    uint32_t offset = regs.GPR.r[(newCode >> 21) & 0x1f] + int16_t(newCode);
    const bool offsetIsInKernel = isInKernel(offset, false);
    const bool isJRToRA = isJR && (rd == 31);
    const uint32_t oldPCBase = normalizeAddress(oldPC) & ~0xe0000000;
    const uint32_t newPCBase = normalizeAddress(newPC) & ~0xe0000000;
    const uint32_t targetBase = normalizeAddress(target) & ~0xe0000000;

    checkBP(newPC, BreakpointType::Exec, 4);
    if (m_breakmp_e && !isMapMarked(newPC, MAP_EXEC)) {
        triggerBP(nullptr, newPC, 4, _("Execution map"));
    }
    if (m_mapping_e) {
        markMap(newPC, MAP_EXEC);
        if (isJAL) markMap(target, MAP_EXEC_JAL);
        if (isJALR) markMap(regs.GPR.r[rd], MAP_EXEC_JAL);
    }

    // Are we jumping from a non-kernel address to a kernel address which:
    // - is not a jr to $ra (aka a return from a callback)
    // - is not a jump to 0xa0 / 0xb0 / 0xc0 (aka the syscall gates)
    // - is not going to the break or exception handler
    if ((isJR || isJALR) && !wasInKernel && isTargetInKernel && !isJRToRA && (targetBase != 0x40) &&
        (targetBase != 0x80) && (targetBase != 0xa0) && (targetBase != 0xb0) && (targetBase != 0xc0)) {
        if (m_checkKernel) {
            g_system->printf(_("Kernel checker: Jump from 0x%08x to 0x%08x\n"), oldPC, targetBase);
            g_system->pause();
        }
    }

    if (isAnyLoadOrStore) {
        if (isLWL || isLWR || isSWR || isSWL) offset &= ~3;
        if (isLB || isLBU) {
            checkBP(offset, BreakpointType::Read, 1);
            if (m_breakmp_r8 && !isMapMarked(offset, MAP_R8)) {
                triggerBP(nullptr, offset, 1, _("Read 8 map"));
            }
            if (m_mapping_r8) markMap(offset, MAP_R8);
        }
        if (isLH || isLHU) {
            checkBP(offset, BreakpointType::Read, 2);
            if (m_breakmp_r16 && !isMapMarked(offset, MAP_R16)) {
                triggerBP(nullptr, offset, 2, _("Read 16 map"));
            }
            if (m_mapping_r16) markMap(offset, MAP_R16);
        }
        if (isLW || isLWR || isLWL || isLWC2) {
            checkBP(offset, BreakpointType::Read, 4);
            if (m_breakmp_r32 && !isMapMarked(offset, MAP_R32)) {
                triggerBP(nullptr, offset, 4, _("Read 32 map"));
            }
            if (m_mapping_r32) markMap(offset, MAP_R32);
        }
        if (isSB) {
            checkBP(offset, BreakpointType::Write, 1);
            if (m_breakmp_w8 && !isMapMarked(offset, MAP_W8)) {
                triggerBP(nullptr, offset, 1, _("Write 8 map"));
            }
            if (m_mapping_w8) markMap(offset, MAP_W8);
        }
        if (isSH) {
            checkBP(offset, BreakpointType::Write, 2);
            if (m_breakmp_w16 && !isMapMarked(offset, MAP_W16)) {
                triggerBP(nullptr, offset, 2, _("Write 16 map"));
            }
            if (m_mapping_w16) markMap(offset, MAP_W16);
        }
        if (isSW || isSWR || isSWL || isSWC2) {
            checkBP(offset, BreakpointType::Write, 4);
            if (m_breakmp_w32 && !isMapMarked(offset, MAP_W32)) {
                triggerBP(nullptr, offset, 4, _("Write 32 map"));
            }
            if (m_mapping_w32) markMap(offset, MAP_W32);
        }
        // Are we accessing a kernel address from a non-kernel address, while not in IRQ?
        if (!g_emulator->m_cpu->m_inISR && offsetIsInKernel && !wasInKernel) {
            if (m_checkKernel) {
                if (isLoad) {
                    g_system->printf(_("Kernel checker: Reading %08x from %08x\n"), offset, oldPC);
                    g_system->pause();
                } else {
                    g_system->printf(_("Kernel checker: Writing to %08x from %08x\n"), offset, oldPC);
                    g_system->pause();
                }
                g_system->pause();
            }
        }
    }

    if (m_step == STEP_NONE) return;
    bool skipStepOverAndOut = false;
    if (!m_wasInISR && g_emulator->m_cpu->m_inISR) {
        uint32_t cause = (regs.CP0.n.Cause >> 2) & 0x1f;
        if (cause == 0) return;
        skipStepOverAndOut = true;
    }

    switch (m_step) {
        case STEP_IN: {
            triggerBP(nullptr, newPC, 4, _("Step in"));
        } break;
        case STEP_OVER: {
            if (!m_stepperHasBreakpoint && !skipStepOverAndOut) {
                if (linked) {
                    uint32_t sp = regs.GPR.n.sp;
                    m_stepperHasBreakpoint = true;
                    addBreakpoint(
                        oldPC + 4, BreakpointType::Exec, 4, _("Step Over"),
                        [sp, this](const Breakpoint* bp, uint32_t address, unsigned width, const char* cause) {
                            if (sp != g_emulator->m_cpu->m_regs.GPR.n.sp) return true;
                            g_system->pause();
                            m_stepperHasBreakpoint = false;
                            return false;
                        });
                } else {
                    triggerBP(nullptr, newPC, 4, _("Step over"));
                }
            }
        } break;
        case STEP_OUT: {
            if (!m_stepperHasBreakpoint && !skipStepOverAndOut) {
                triggerBP(nullptr, newPC, 4, _("Step out (no callstack)"));
            }
            break;
        }
    }
}

void PCSX::Debug::startStepping() {
    if (PCSX::g_system->running()) return;
    m_wasInISR = g_emulator->m_cpu->m_inISR;
    g_system->resume();
}

bool PCSX::Debug::triggerBP(Breakpoint* bp, uint32_t address, unsigned width, const char* cause) {
    uint32_t pc = g_emulator->m_cpu->m_regs.pc;
    bool keepBP = true;
    std::string name;
    m_lastBP = nullptr;
    if (bp) {
        name = bp->name();
        keepBP = bp->trigger(address, width, cause);
        if (keepBP) m_lastBP = bp;
    } else {
        g_system->pause();
    }
    if (g_system->running()) return keepBP;
    m_step = STEP_NONE;
    g_system->printf(_("Breakpoint triggered: PC=0x%08x - Cause: %s %s\n"), pc, name, cause);
    g_system->m_eventBus->signal(Events::GUI::JumpToPC{pc});
    return keepBP;
}

void PCSX::Debug::checkBP(uint32_t address, BreakpointType type, uint32_t width, const char* cause) {
    auto& cpu = g_emulator->m_cpu;
    auto& regs = cpu->m_regs;

    if (m_scheduledCop0.has_value()) {
        regs.pc = std::get<uint32_t>(m_scheduledCop0.value());
        cpu->exception(R3000Acpu::Exception::Break, std::get<bool>(m_scheduledCop0.value()), true);
        m_scheduledCop0.reset();
    } else if ((regs.CP0.n.DCIC & 0xc0800000) == 0xc0800000) {
        if (type == BreakpointType::Exec && ((regs.CP0.n.DCIC & 0x01000000) == 0x01000000)) {
            if (((regs.CP0.n.BPC ^ address) & regs.CP0.n.BPCM) == 0) {
                m_scheduledCop0.emplace(regs.pc, cpu->m_inDelaySlot);
            }
        } else if ((type == BreakpointType::Read) && ((regs.CP0.n.DCIC & 0x06000000) == 0x06000000)) {
            if (((regs.CP0.n.BDA ^ address) & regs.CP0.n.BDAM) == 0) {
                m_scheduledCop0.emplace(regs.pc, cpu->m_inDelaySlot);
            }
        } else if ((type == BreakpointType::Write) && ((regs.CP0.n.DCIC & 0x0a000000) == 0x0a000000)) {
            if (((regs.CP0.n.BDA ^ address) & regs.CP0.n.BDAM) == 0) {
                m_scheduledCop0.emplace(regs.pc, cpu->m_inDelaySlot);
            }
        }
    }

    auto end = m_breakpoints.end();
    uint32_t normalizedAddress = normalizeAddress(address & ~0xe0000000);

    BreakpointTemporaryListType torun;
    for (auto it = m_breakpoints.find(normalizedAddress, normalizedAddress + width - 1); it != end; it++) {
        if (it->type() != type) continue;
        auto bp = &*it;
        torun.push_back(bp);
    }

    while (!torun.empty()) {
        auto it = torun.begin();
        auto bp = &*it;
        torun.erase(it);
        if (!triggerBP(bp, address, width, cause)) delete bp;
    }
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

    uint32_t fp = 0;
    uint32_t ra = 0;

    if (callstack.ra != 0) {
        fp = callstack.fp;
        ra = callstack.ra;
    } else {
        auto call = callstack.calls.end();
        call--;
        fp = call->fp;
        ra = call->ra;
    }

    if (ra == 0) return;
    if (fp == 0) return;

    addBreakpoint(ra, BreakpointType::Exec, 4, _("Step Out"),
                  [fp, this](const Breakpoint* bp, uint32_t address, unsigned width, const char* cause) {
                      if (g_emulator->m_cpu->m_regs.GPR.n.sp != fp) return true;
                      g_system->pause();
                      m_stepperHasBreakpoint = false;
                      return false;
                  });
    m_stepperHasBreakpoint = true;
}

void PCSX::Debug::updatedPC(uint32_t pc) {
    IO<File> memFile = g_emulator->m_mem->getMemoryAsFile();
    uint32_t code = memFile->readAt<uint32_t>(pc);
    process(pc, pc, code, code, false);
}
