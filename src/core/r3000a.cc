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
 * R3000A CPU functions.
 */

#include "core/cdrom.h"
#include "core/debug.h"
#include "core/gpu.h"
#include "core/gte.h"
#include "core/mdec.h"
#include "core/pgxp_mem.h"
#include "core/r3000a.h"

int PCSX::R3000Acpu::psxInit() {
    PCSX::g_system->SysPrintf(_("Running PCSXR Version %s (%s).\n"), PACKAGE_VERSION, __DATE__);

    if (PCSX::g_emulator.config().Cpu == PCSX::Emulator::CPU_DYNAREC) {
        PCSX::g_emulator.m_psxCpu = PCSX::Cpus::DynaRec();
    }

    if (!PCSX::g_emulator.m_psxCpu) {
        PCSX::g_emulator.m_psxCpu = PCSX::Cpus::Interpreted();
    }

    if (psxMemInit() == -1) return -1;
    PGXP_Init();
    PauseDebugger();

    return PCSX::g_emulator.m_psxCpu->Init();
}

void PCSX::R3000Acpu::psxReset() {
    Reset();

    psxMemReset();

    memset(&m_psxRegs, 0, sizeof(m_psxRegs));

    m_psxRegs.pc = 0xbfc00000;  // Start in bootstrap

    m_psxRegs.CP0.r[12] = 0x10900000;  // COP0 enabled | BEV = 1 | TS = 1
    m_psxRegs.CP0.r[15] = 0x00000002;  // PRevID = Revision ID, same as R3000A

    psxHwReset();
    psxBiosInit();

    if (!PCSX::g_emulator.config().HLE) psxExecuteBios();

    EMU_LOG("*BIOS END*\n");
}

void PCSX::R3000Acpu::psxShutdown() {
    psxMemShutdown();
    psxBiosShutdown();

    Shutdown();
}

void PCSX::R3000Acpu::psxException(uint32_t code, uint32_t bd) {
    // Set the Cause
    m_psxRegs.CP0.n.Cause = code;

    // Set the EPC & PC
    if (bd) {
        PSXCPU_LOG("bd set!!!\n");
        PCSX::g_system->SysPrintf("bd set!!!\n");
        m_psxRegs.CP0.n.Cause |= 0x80000000;
        m_psxRegs.CP0.n.EPC = (m_psxRegs.pc - 4);
    } else
        m_psxRegs.CP0.n.EPC = (m_psxRegs.pc);

    if (m_psxRegs.CP0.n.Status & 0x400000)
        m_psxRegs.pc = 0xbfc00180;
    else
        m_psxRegs.pc = 0x80000080;

    // Set the Status
    m_psxRegs.CP0.n.Status = (m_psxRegs.CP0.n.Status & ~0x3f) | ((m_psxRegs.CP0.n.Status & 0xf) << 2);

    if (PCSX::g_emulator.config().HLE) psxBiosException();
}

void PCSX::R3000Acpu::psxBranchTest() {
    // GameShark Sampler: Give VSync pin some delay before exception eats it
    if (psxHu32(0x1070) & psxHu32(0x1074)) {
        if ((m_psxRegs.CP0.n.Status & 0x401) == 0x401) {
            uint32_t opcode;

            // Crash Bandicoot 2: Don't run exceptions when GTE in pipeline
            opcode = SWAP32(*Read_ICache(m_psxRegs.pc, true));
            if (((opcode >> 24) & 0xfe) != 0x4a) {
                PSXCPU_LOG("Interrupt: %x %x\n", psxHu32(0x1070), psxHu32(0x1074));
                psxException(0x400, 0);
            }
        }
    }

#if 0
	if( SPU_async )
	{
		static int init;
		int elapsed;

		if( init == 0 ) {
			// 10 apu cycles
			// - Final Fantasy Tactics (distorted - dropped sound effects)
			m_psxRegs.intCycle[PSXINT_SPUASYNC].cycle = PCSX::g_emulator.m_psxClockSpeed / 44100 * 10;

			init = 1;
		}

		elapsed = m_psxRegs.cycle - m_psxRegs.intCycle[PSXINT_SPUASYNC].sCycle;
		if (elapsed >= m_psxRegs.intCycle[PSXINT_SPUASYNC].cycle) {
			SPU_async( elapsed );

			m_psxRegs.intCycle[PSXINT_SPUASYNC].sCycle = m_psxRegs.cycle;
		}
	}
#endif

    if ((m_psxRegs.cycle - g_psxNextsCounter) >= g_psxNextCounter) psxRcntUpdate();

    if (m_psxRegs.interrupt) {
        if ((m_psxRegs.interrupt & (1 << PSXINT_SIO)) && !PCSX::g_emulator.config().SioIrq) {  // sio
            if ((m_psxRegs.cycle - m_psxRegs.intCycle[PSXINT_SIO].sCycle) >= m_psxRegs.intCycle[PSXINT_SIO].cycle) {
                m_psxRegs.interrupt &= ~(1 << PSXINT_SIO);
                sioInterrupt();
            }
        }
        if (m_psxRegs.interrupt & (1 << PSXINT_CDR)) {  // cdr
            if ((m_psxRegs.cycle - m_psxRegs.intCycle[PSXINT_CDR].sCycle) >= m_psxRegs.intCycle[PSXINT_CDR].cycle) {
                m_psxRegs.interrupt &= ~(1 << PSXINT_CDR);
                cdrInterrupt();
            }
        }
        if (m_psxRegs.interrupt & (1 << PSXINT_CDREAD)) {  // cdr read
            if ((m_psxRegs.cycle - m_psxRegs.intCycle[PSXINT_CDREAD].sCycle) >=
                m_psxRegs.intCycle[PSXINT_CDREAD].cycle) {
                m_psxRegs.interrupt &= ~(1 << PSXINT_CDREAD);
                cdrReadInterrupt();
            }
        }
        if (m_psxRegs.interrupt & (1 << PSXINT_GPUDMA)) {  // gpu dma
            if ((m_psxRegs.cycle - m_psxRegs.intCycle[PSXINT_GPUDMA].sCycle) >=
                m_psxRegs.intCycle[PSXINT_GPUDMA].cycle) {
                m_psxRegs.interrupt &= ~(1 << PSXINT_GPUDMA);
                gpuInterrupt();
            }
        }
        if (m_psxRegs.interrupt & (1 << PSXINT_MDECOUTDMA)) {  // mdec out dma
            if ((m_psxRegs.cycle - m_psxRegs.intCycle[PSXINT_MDECOUTDMA].sCycle) >=
                m_psxRegs.intCycle[PSXINT_MDECOUTDMA].cycle) {
                m_psxRegs.interrupt &= ~(1 << PSXINT_MDECOUTDMA);
                mdec1Interrupt();
            }
        }
        if (m_psxRegs.interrupt & (1 << PSXINT_SPUDMA)) {  // spu dma
            if ((m_psxRegs.cycle - m_psxRegs.intCycle[PSXINT_SPUDMA].sCycle) >=
                m_psxRegs.intCycle[PSXINT_SPUDMA].cycle) {
                m_psxRegs.interrupt &= ~(1 << PSXINT_SPUDMA);
                spuInterrupt();
            }
        }
        if (m_psxRegs.interrupt & (1 << PSXINT_MDECINDMA)) {  // mdec in
            if ((m_psxRegs.cycle - m_psxRegs.intCycle[PSXINT_MDECINDMA].sCycle) >=
                m_psxRegs.intCycle[PSXINT_MDECINDMA].cycle) {
                m_psxRegs.interrupt &= ~(1 << PSXINT_MDECINDMA);
                mdec0Interrupt();
            }
        }

        if (m_psxRegs.interrupt & (1 << PSXINT_GPUOTCDMA)) {  // gpu otc
            if ((m_psxRegs.cycle - m_psxRegs.intCycle[PSXINT_GPUOTCDMA].sCycle) >=
                m_psxRegs.intCycle[PSXINT_GPUOTCDMA].cycle) {
                m_psxRegs.interrupt &= ~(1 << PSXINT_GPUOTCDMA);
                gpuotcInterrupt();
            }
        }

        if (m_psxRegs.interrupt & (1 << PSXINT_CDRDMA)) {  // cdrom
            if ((m_psxRegs.cycle - m_psxRegs.intCycle[PSXINT_CDRDMA].sCycle) >=
                m_psxRegs.intCycle[PSXINT_CDRDMA].cycle) {
                m_psxRegs.interrupt &= ~(1 << PSXINT_CDRDMA);
                cdrDmaInterrupt();
            }
        }

        if (m_psxRegs.interrupt & (1 << PSXINT_CDRPLAY)) {  // cdr play timing
            if ((m_psxRegs.cycle - m_psxRegs.intCycle[PSXINT_CDRPLAY].sCycle) >=
                m_psxRegs.intCycle[PSXINT_CDRPLAY].cycle) {
                m_psxRegs.interrupt &= ~(1 << PSXINT_CDRPLAY);
                cdrPlayInterrupt();
            }
        }

        if (m_psxRegs.interrupt & (1 << PSXINT_CDRDBUF)) {  // cdr decoded buffer
            if ((m_psxRegs.cycle - m_psxRegs.intCycle[PSXINT_CDRDBUF].sCycle) >=
                m_psxRegs.intCycle[PSXINT_CDRDBUF].cycle) {
                m_psxRegs.interrupt &= ~(1 << PSXINT_CDRDBUF);
                cdrDecodedBufferInterrupt();
            }
        }

        if (m_psxRegs.interrupt & (1 << PSXINT_CDRLID)) {  // cdr lid states
            if ((m_psxRegs.cycle - m_psxRegs.intCycle[PSXINT_CDRLID].sCycle) >=
                m_psxRegs.intCycle[PSXINT_CDRLID].cycle) {
                m_psxRegs.interrupt &= ~(1 << PSXINT_CDRLID);
                cdrLidSeekInterrupt();
            }
        }
    }
}

void PCSX::R3000Acpu::psxJumpTest() {
    if (!PCSX::g_emulator.config().HLE && PCSX::g_emulator.config().verbose) {
        uint32_t call = m_psxRegs.GPR.n.t1 & 0xff;
        switch (m_psxRegs.pc & 0x1fffff) {
            case 0xa0:
                if (biosA0[call])
                    biosA0[call]();
                else if (call != 0x28 && call != 0xe) {
                    PSXBIOS_LOG("Bios call a0: %s (%x) %x,%x,%x,%x\n", g_biosA0n[call], call, m_psxRegs.GPR.n.a0,
                                m_psxRegs.GPR.n.a1, m_psxRegs.GPR.n.a2, m_psxRegs.GPR.n.a3);
                }
                break;
            case 0xb0:
                if (biosB0[call])
                    biosB0[call]();
                else if (call != 0x17 && call != 0xb) {
                    PSXBIOS_LOG("Bios call b0: %s (%x) %x,%x,%x,%x\n", g_biosB0n[call], call, m_psxRegs.GPR.n.a0,
                                m_psxRegs.GPR.n.a1, m_psxRegs.GPR.n.a2, m_psxRegs.GPR.n.a3);
                }
                break;
            case 0xc0:
                if (biosC0[call])
                    biosC0[call]();
                else {
                    PSXBIOS_LOG("Bios call c0: %s (%x) %x,%x,%x,%x\n", g_biosC0n[call], call, m_psxRegs.GPR.n.a0,
                                m_psxRegs.GPR.n.a1, m_psxRegs.GPR.n.a2, m_psxRegs.GPR.n.a3);
                }

                break;
        }
    }
}

void PCSX::R3000Acpu::psxExecuteBios() {
    while (m_psxRegs.pc != 0x80030000) ExecuteBlock();
}

void PCSX::R3000Acpu::psxSetPGXPMode(uint32_t pgxpMode) {
    SetPGXPMode(pgxpMode);
    // PCSX::g_emulator.m_psxCpu->Reset();
}

static PCSX::InterpretedCPU s_cpuInt;
PCSX::R3000Acpu* PCSX::Cpus::Interpreted() { return &s_cpuInt; }

static PCSX::X86DynaRecCPU s_cpuX86DynRec;
PCSX::R3000Acpu* PCSX::Cpus::DynaRec() {
    if (s_cpuX86DynRec.Implemented()) return &s_cpuX86DynRec;
    return NULL;
}
