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

#ifndef __PSXDMA_H__
#define __PSXDMA_H__

#include "core/psxcommon.h"
#include "core/psxhw.h"
#include "core/psxmem.h"
#include "core/r3000a.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GPUDMA_INT(eCycle)                                      \
    {                                                           \
        g_psxRegs.interrupt |= (1 << PSXINT_GPUDMA);              \
        g_psxRegs.intCycle[PSXINT_GPUDMA].cycle = eCycle;         \
        g_psxRegs.intCycle[PSXINT_GPUDMA].sCycle = g_psxRegs.cycle; \
    }

#define SPUDMA_INT(eCycle)                                      \
    {                                                           \
        g_psxRegs.interrupt |= (1 << PSXINT_SPUDMA);              \
        g_psxRegs.intCycle[PSXINT_SPUDMA].cycle = eCycle;         \
        g_psxRegs.intCycle[PSXINT_SPUDMA].sCycle = g_psxRegs.cycle; \
    }

#define MDECOUTDMA_INT(eCycle)                                      \
    {                                                               \
        g_psxRegs.interrupt |= (1 << PSXINT_MDECOUTDMA);              \
        g_psxRegs.intCycle[PSXINT_MDECOUTDMA].cycle = eCycle;         \
        g_psxRegs.intCycle[PSXINT_MDECOUTDMA].sCycle = g_psxRegs.cycle; \
    }

#define MDECINDMA_INT(eCycle)                                      \
    {                                                              \
        g_psxRegs.interrupt |= (1 << PSXINT_MDECINDMA);              \
        g_psxRegs.intCycle[PSXINT_MDECINDMA].cycle = eCycle;         \
        g_psxRegs.intCycle[PSXINT_MDECINDMA].sCycle = g_psxRegs.cycle; \
    }

#define GPUOTCDMA_INT(eCycle)                                      \
    {                                                              \
        g_psxRegs.interrupt |= (1 << PSXINT_GPUOTCDMA);              \
        g_psxRegs.intCycle[PSXINT_GPUOTCDMA].cycle = eCycle;         \
        g_psxRegs.intCycle[PSXINT_GPUOTCDMA].sCycle = g_psxRegs.cycle; \
    }

#define CDRDMA_INT(eCycle)                                      \
    {                                                           \
        g_psxRegs.interrupt |= (1 << PSXINT_CDRDMA);              \
        g_psxRegs.intCycle[PSXINT_CDRDMA].cycle = eCycle;         \
        g_psxRegs.intCycle[PSXINT_CDRDMA].sCycle = g_psxRegs.cycle; \
    }

/*
DMA5 = N/A (PIO)
*/

void psxDma3(u32 madr, u32 bcr, u32 chcr);
void psxDma4(u32 madr, u32 bcr, u32 chcr);
void psxDma6(u32 madr, u32 bcr, u32 chcr);
void spuInterrupt();
void mdec0Interrupt();
void gpuotcInterrupt();
void cdrDmaInterrupt();

#ifdef __cplusplus
}
#endif
#endif
