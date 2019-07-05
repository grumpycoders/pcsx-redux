/***************************************************************************
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
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

/*
 * Internal PSX HLE functions.
 */

#include "core/psxhle.h"
#include "core/r3000a.h"

static void hleDummy() {
    PCSX::g_emulator.m_psxCpu->m_psxRegs.pc = PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.ra;

    PCSX::g_emulator.m_psxCpu->psxBranchTest();
}

static void hleA0() {
    uint32_t call = PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.t1 & 0xff;

    PCSX::g_emulator.m_psxBios->callA0(call);

    PCSX::g_emulator.m_psxCpu->psxBranchTest();
}

static void hleB0() {
    uint32_t call = PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.t1 & 0xff;

    PCSX::g_emulator.m_psxBios->callB0(call);

    PCSX::g_emulator.m_psxCpu->psxBranchTest();
}

static void hleC0() {
    uint32_t call = PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.t1 & 0xff;

    PCSX::g_emulator.m_psxBios->callC0(call);

    PCSX::g_emulator.m_psxCpu->psxBranchTest();
}

static void hleBootstrap() {  // 0xbfc00000
    PCSX::g_system->biosPrintf("hleBootstrap\n");
    if (!CheckCdrom()) {
        PCSX::g_system->biosPrintf("hleBootstrap: No CDRom\n");
        PCSX::g_system->stop();
        PCSX::g_emulator.EmuReset();
        return;
    }
    if (!LoadCdrom()) {
        PCSX::g_system->biosPrintf("hleBootstrap: failed to load cdrom's binary\n");
        PCSX::g_system->stop();
        PCSX::g_emulator.EmuReset();
        return;
    }
    PCSX::g_system->biosPrintf("CdromLabel: \"%s\": PC = %8.8x (SP = %8.8x)\n", PCSX::g_emulator.m_cdromLabel,
                               (unsigned int)PCSX::g_emulator.m_psxCpu->m_psxRegs.pc,
                               (unsigned int)PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.sp);
}

typedef struct {
    uint32_t _pc0;
    uint32_t gp0;
    uint32_t t_addr;
    uint32_t t_size;
    uint32_t d_addr;
    uint32_t d_size;
    uint32_t b_addr;
    uint32_t b_size;
    uint32_t S_addr;
    uint32_t s_size;
    uint32_t _sp, _fp, _gp, ret, base;
} EXEC;

static void hleExecRet() {
    EXEC *header = (EXEC *)PSXM(PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.s0);

    PCSX::g_system->biosPrintf("ExecRet %x: %x\n", PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.s0, header->ret);

    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.ra = header->ret;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.sp = header->_sp;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.s8 = header->_fp;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.gp = header->_gp;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.s0 = header->base;

    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.v0 = 1;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.pc = PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.ra;
}

static void hleException() {
    PCSX::g_emulator.m_psxBios->psxBiosException();
}

const HLE_t psxHLEt[8] = {hleDummy, hleA0, hleB0, hleC0, hleBootstrap, hleExecRet, hleException, hleDummy};
