/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                *
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

// GTE COP2 data transfer operations: MFC2, MTC2, CFC2, CTC2, LWC2, SWC2.

#include "core/gte.h"
#include "core/gte-internal.h"
#include "core/psxmem.h"

using namespace PCSX::GTEImpl;

uint32_t PCSX::GTE::MFC2(uint32_t code) {
    return MFC2(static_cast<int>(_Rd_));
}

uint32_t PCSX::GTE::MFC2(int reg) {
    auto* d = dataRegs();
    switch (reg) {
        case 1: case 3: case 5:
        case 8: case 9: case 10: case 11:
            d[reg].d = static_cast<int32_t>(d[reg].sw.l);
            break;
        case 7: case 16: case 17: case 18: case 19:
            d[reg].d = static_cast<uint32_t>(d[reg].w.l);
            break;
        case 15:
            d[reg].d = sxy2();
            break;
        case 28: case 29:
            d[reg].d = lim(ir1() >> 7, 0x1f, 0, 0) |
                       (lim(ir2() >> 7, 0x1f, 0, 0) << 5) |
                       (lim(ir3() >> 7, 0x1f, 0, 0) << 10);
            break;
    }
    return d[reg].d;
}

uint32_t PCSX::GTE::CFC2(uint32_t code) {
    return ctrlRegs()[_Rd_].d;
}

void PCSX::GTE::MTC2(uint32_t value, int reg) {
    auto* d = dataRegs();
    switch (reg) {
        case 15:
            sxy0() = sxy1();
            sxy1() = sxy2();
            sxy2() = value;
            break;
        case 28:
            ir1() = (value & 0x1f) << 7;
            ir2() = (value & 0x3e0) << 2;
            ir3() = (value & 0x7c00) >> 3;
            break;
        case 30:
            d[31].d = countLeadingBits(value);
            break;
        case 31:
            return;
    }
    d[reg].d = value;
}

void PCSX::GTE::MTC2(uint32_t code) {
    MTC2(g_emulator->m_cpu->m_regs.GPR.r[_Rt_], _Rd_);
}

void PCSX::GTE::CTC2(uint32_t value, int reg) {
    switch (reg) {
        case 4: case 12: case 20:
        case 26: case 27: case 29: case 30:
            value = static_cast<int32_t>(static_cast<int16_t>(value));
            break;
        case 31:
            value = value & 0x7ffff000;
            if (value & Flag::ERROR_BITS) value |= Flag::GTE_ERROR;
            break;
    }
    ctrlRegs()[reg].d = value;
}

void PCSX::GTE::CTC2(uint32_t code) {
    CTC2(g_emulator->m_cpu->m_regs.GPR.r[_Rt_], _Rd_);
}

void PCSX::GTE::LWC2(uint32_t code) {
    uint32_t addr = g_emulator->m_cpu->m_regs.GPR.r[_Rs_] + _Imm_;
    if (addr & 3) {
        g_emulator->m_cpu->m_regs.pc -= 4;
        g_system->log(LogClass::CPU, _("Unaligned address 0x%08x in LWC2 from 0x%08x\n"), addr,
                      g_emulator->m_cpu->m_regs.pc);
        g_emulator->m_cpu->m_regs.CP0.n.BadVAddr = addr;
        g_emulator->m_cpu->exception(R3000Acpu::Exception::LoadAddressError, g_emulator->m_cpu->m_inDelaySlot);
        return;
    }
    MTC2(g_emulator->m_mem->read32(addr), _Rt_);
}

void PCSX::GTE::SWC2(uint32_t code) {
    uint32_t addr = g_emulator->m_cpu->m_regs.GPR.r[_Rs_] + _Imm_;
    if (addr & 3) {
        g_emulator->m_cpu->m_regs.pc -= 4;
        g_system->log(LogClass::CPU, _("Unaligned address 0x%08x in SWC2 from 0x%08x\n"), addr,
                      g_emulator->m_cpu->m_regs.pc);
        g_emulator->m_cpu->m_regs.CP0.n.BadVAddr = addr;
        g_emulator->m_cpu->exception(R3000Acpu::Exception::StoreAddressError, g_emulator->m_cpu->m_inDelaySlot);
        return;
    }
    g_emulator->m_mem->write32(addr, MFC2(static_cast<int>(_Rt_)));
}
