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
#include "core/gpu.h"
#include "core/gte.h"
#include "core/mdec.h"
#include "core/pgxp_mem.h"
#include "core/r3000a.h"

R3000Acpu *g_psxCpu = NULL;
psxRegisters g_psxRegs;

int psxInit() {
    SysPrintf(_("Running PCSXR Version %s (%s).\n"), PACKAGE_VERSION, __DATE__);

#ifdef PSXREC
    if (g_config.Cpu == CPU_INTERPRETER) {
        g_psxCpu = &g_psxInt;
    } else
        g_psxCpu = &g_psxRec;
#else
    g_psxCpu = &g_psxInt;
#endif

    g_log = 0;

    if (psxMemInit() == -1) return -1;
    PGXP_Init();
    PauseDebugger();

    return g_psxCpu->Init();
}

void psxReset() {
    g_psxCpu->Reset();

    psxMemReset();

    memset(&g_psxRegs, 0, sizeof(g_psxRegs));

    g_psxRegs.pc = 0xbfc00000;  // Start in bootstrap

    g_psxRegs.CP0.r[12] = 0x10900000;  // COP0 enabled | BEV = 1 | TS = 1
    g_psxRegs.CP0.r[15] = 0x00000002;  // PRevID = Revision ID, same as R3000A

    psxHwReset();
    psxBiosInit();

    if (!g_config.HLE) psxExecuteBios();

#ifdef EMU_LOG
    EMU_LOG("*BIOS END*\n");
#endif
    g_log = 0;
}

void psxShutdown() {
    psxMemShutdown();
    psxBiosShutdown();

    g_psxCpu->Shutdown();
}

void psxException(u32 code, u32 bd) {
    // Set the Cause
    g_psxRegs.CP0.n.Cause = code;

    // Set the EPC & PC
    if (bd) {
#ifdef PSXCPU_LOG
        PSXCPU_LOG("bd set!!!\n");
#endif
        SysPrintf("bd set!!!\n");
        g_psxRegs.CP0.n.Cause |= 0x80000000;
        g_psxRegs.CP0.n.EPC = (g_psxRegs.pc - 4);
    } else
        g_psxRegs.CP0.n.EPC = (g_psxRegs.pc);

    if (g_psxRegs.CP0.n.Status & 0x400000)
        g_psxRegs.pc = 0xbfc00180;
    else
        g_psxRegs.pc = 0x80000080;

    // Set the Status
    g_psxRegs.CP0.n.Status = (g_psxRegs.CP0.n.Status & ~0x3f) | ((g_psxRegs.CP0.n.Status & 0xf) << 2);

    if (g_config.HLE) psxBiosException();
}

void psxBranchTest() {
    // GameShark Sampler: Give VSync pin some delay before exception eats it
    if (psxHu32(0x1070) & psxHu32(0x1074)) {
        if ((g_psxRegs.CP0.n.Status & 0x401) == 0x401) {
            u32 opcode;

            // Crash Bandicoot 2: Don't run exceptions when GTE in pipeline
            opcode = SWAP32(*Read_ICache(g_psxRegs.pc, TRUE));
            if (((opcode >> 24) & 0xfe) != 0x4a) {
#ifdef PSXCPU_LOG
                PSXCPU_LOG("Interrupt: %x %x\n", psxHu32(0x1070), psxHu32(0x1074));
#endif
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
			g_psxRegs.intCycle[PSXINT_SPUASYNC].cycle = PSXCLK / 44100 * 10;

			init = 1;
		}

		elapsed = g_psxRegs.cycle - g_psxRegs.intCycle[PSXINT_SPUASYNC].sCycle;
		if (elapsed >= g_psxRegs.intCycle[PSXINT_SPUASYNC].cycle) {
			SPU_async( elapsed );

			g_psxRegs.intCycle[PSXINT_SPUASYNC].sCycle = g_psxRegs.cycle;
		}
	}
#endif

    if ((g_psxRegs.cycle - g_psxNextsCounter) >= g_psxNextCounter) psxRcntUpdate();

    if (g_psxRegs.interrupt) {
        if ((g_psxRegs.interrupt & (1 << PSXINT_SIO)) && !g_config.SioIrq) {  // sio
            if ((g_psxRegs.cycle - g_psxRegs.intCycle[PSXINT_SIO].sCycle) >= g_psxRegs.intCycle[PSXINT_SIO].cycle) {
                g_psxRegs.interrupt &= ~(1 << PSXINT_SIO);
                sioInterrupt();
            }
        }
        if (g_psxRegs.interrupt & (1 << PSXINT_CDR)) {  // cdr
            if ((g_psxRegs.cycle - g_psxRegs.intCycle[PSXINT_CDR].sCycle) >= g_psxRegs.intCycle[PSXINT_CDR].cycle) {
                g_psxRegs.interrupt &= ~(1 << PSXINT_CDR);
                cdrInterrupt();
            }
        }
        if (g_psxRegs.interrupt & (1 << PSXINT_CDREAD)) {  // cdr read
            if ((g_psxRegs.cycle - g_psxRegs.intCycle[PSXINT_CDREAD].sCycle) >= g_psxRegs.intCycle[PSXINT_CDREAD].cycle) {
                g_psxRegs.interrupt &= ~(1 << PSXINT_CDREAD);
                cdrReadInterrupt();
            }
        }
        if (g_psxRegs.interrupt & (1 << PSXINT_GPUDMA)) {  // gpu dma
            if ((g_psxRegs.cycle - g_psxRegs.intCycle[PSXINT_GPUDMA].sCycle) >= g_psxRegs.intCycle[PSXINT_GPUDMA].cycle) {
                g_psxRegs.interrupt &= ~(1 << PSXINT_GPUDMA);
                gpuInterrupt();
            }
        }
        if (g_psxRegs.interrupt & (1 << PSXINT_MDECOUTDMA)) {  // mdec out dma
            if ((g_psxRegs.cycle - g_psxRegs.intCycle[PSXINT_MDECOUTDMA].sCycle) >=
                g_psxRegs.intCycle[PSXINT_MDECOUTDMA].cycle) {
                g_psxRegs.interrupt &= ~(1 << PSXINT_MDECOUTDMA);
                mdec1Interrupt();
            }
        }
        if (g_psxRegs.interrupt & (1 << PSXINT_SPUDMA)) {  // spu dma
            if ((g_psxRegs.cycle - g_psxRegs.intCycle[PSXINT_SPUDMA].sCycle) >= g_psxRegs.intCycle[PSXINT_SPUDMA].cycle) {
                g_psxRegs.interrupt &= ~(1 << PSXINT_SPUDMA);
                spuInterrupt();
            }
        }
        if (g_psxRegs.interrupt & (1 << PSXINT_MDECINDMA)) {  // mdec in
            if ((g_psxRegs.cycle - g_psxRegs.intCycle[PSXINT_MDECINDMA].sCycle) >=
                g_psxRegs.intCycle[PSXINT_MDECINDMA].cycle) {
                g_psxRegs.interrupt &= ~(1 << PSXINT_MDECINDMA);
                mdec0Interrupt();
            }
        }

        if (g_psxRegs.interrupt & (1 << PSXINT_GPUOTCDMA)) {  // gpu otc
            if ((g_psxRegs.cycle - g_psxRegs.intCycle[PSXINT_GPUOTCDMA].sCycle) >=
                g_psxRegs.intCycle[PSXINT_GPUOTCDMA].cycle) {
                g_psxRegs.interrupt &= ~(1 << PSXINT_GPUOTCDMA);
                gpuotcInterrupt();
            }
        }

        if (g_psxRegs.interrupt & (1 << PSXINT_CDRDMA)) {  // cdrom
            if ((g_psxRegs.cycle - g_psxRegs.intCycle[PSXINT_CDRDMA].sCycle) >= g_psxRegs.intCycle[PSXINT_CDRDMA].cycle) {
                g_psxRegs.interrupt &= ~(1 << PSXINT_CDRDMA);
                cdrDmaInterrupt();
            }
        }

        if (g_psxRegs.interrupt & (1 << PSXINT_CDRPLAY)) {  // cdr play timing
            if ((g_psxRegs.cycle - g_psxRegs.intCycle[PSXINT_CDRPLAY].sCycle) >= g_psxRegs.intCycle[PSXINT_CDRPLAY].cycle) {
                g_psxRegs.interrupt &= ~(1 << PSXINT_CDRPLAY);
                cdrPlayInterrupt();
            }
        }

        if (g_psxRegs.interrupt & (1 << PSXINT_CDRDBUF)) {  // cdr decoded buffer
            if ((g_psxRegs.cycle - g_psxRegs.intCycle[PSXINT_CDRDBUF].sCycle) >= g_psxRegs.intCycle[PSXINT_CDRDBUF].cycle) {
                g_psxRegs.interrupt &= ~(1 << PSXINT_CDRDBUF);
                cdrDecodedBufferInterrupt();
            }
        }

        if (g_psxRegs.interrupt & (1 << PSXINT_CDRLID)) {  // cdr lid states
            if ((g_psxRegs.cycle - g_psxRegs.intCycle[PSXINT_CDRLID].sCycle) >= g_psxRegs.intCycle[PSXINT_CDRLID].cycle) {
                g_psxRegs.interrupt &= ~(1 << PSXINT_CDRLID);
                cdrLidSeekInterrupt();
            }
        }
    }
}

void psxJumpTest() {
    if (!g_config.HLE && g_config.PsxOut) {
        u32 call = g_psxRegs.GPR.n.t1 & 0xff;
        switch (g_psxRegs.pc & 0x1fffff) {
            case 0xa0:
                if (biosA0[call])
                    biosA0[call]();
                else if (call != 0x28 && call != 0xe) {
#ifdef PSXBIOS_LOG
                    PSXBIOS_LOG("Bios call a0: %s (%x) %x,%x,%x,%x\n", g_biosA0n[call], call, g_psxRegs.GPR.n.a0,
                                g_psxRegs.GPR.n.a1, g_psxRegs.GPR.n.a2, g_psxRegs.GPR.n.a3);
#endif
                }
                break;
            case 0xb0:
                if (biosB0[call])
                    biosB0[call]();
                else if (call != 0x17 && call != 0xb) {
#ifdef PSXBIOS_LOG
                    PSXBIOS_LOG("Bios call b0: %s (%x) %x,%x,%x,%x\n", g_biosB0n[call], call, g_psxRegs.GPR.n.a0,
                                g_psxRegs.GPR.n.a1, g_psxRegs.GPR.n.a2, g_psxRegs.GPR.n.a3);
#endif
                }
                break;
            case 0xc0:
                if (biosC0[call])
                    biosC0[call]();
                else {
#ifdef PSXBIOS_LOG
                    PSXBIOS_LOG("Bios call c0: %s (%x) %x,%x,%x,%x\n", g_biosC0n[call], call, g_psxRegs.GPR.n.a0,
                                g_psxRegs.GPR.n.a1, g_psxRegs.GPR.n.a2, g_psxRegs.GPR.n.a3);
#endif
                }

                break;
        }
    }
}

void psxExecuteBios() {
    while (g_psxRegs.pc != 0x80030000) g_psxCpu->ExecuteBlock();
}

void psxSetPGXPMode(u32 pgxpMode) {
    g_psxCpu->SetPGXPMode(pgxpMode);
    // g_psxCpu->Reset();
}
