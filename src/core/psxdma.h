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

#include "core/psxemulator.h"
#include "core/psxhw.h"
#include "core/psxmem.h"
#include "core/r3000a.h"

static inline void scheduleGPUDMAIRQ(uint32_t eCycle) {
    PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt |= (1 << PCSX::PSXINT_GPUDMA);
    PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_GPUDMA].cycle = eCycle;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_GPUDMA].sCycle =
        PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle;
}

static inline void scheduleSPUDMAIRQ(uint32_t eCycle) {
    PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt |= (1 << PCSX::PSXINT_SPUDMA);
    PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_SPUDMA].cycle = eCycle;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_SPUDMA].sCycle =
        PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle;
}

static inline void scheduleMDECOUTDMAIRQ(uint32_t eCycle) {
    PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt |= (1 << PCSX::PSXINT_MDECOUTDMA);
    PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_MDECOUTDMA].cycle = eCycle;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_MDECOUTDMA].sCycle =
        PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle;
}

static inline void scheduleMDECINDMAIRQ(uint32_t eCycle) {
    PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt |= (1 << PCSX::PSXINT_MDECINDMA);
    PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_MDECINDMA].cycle = eCycle;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_MDECINDMA].sCycle =
        PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle;
}

static inline void scheduleGPUOTCDMAIRQ(uint32_t eCycle) {
    PCSX::g_emulator.m_psxCpu->m_psxRegs.interrupt |= (1 << PCSX::PSXINT_GPUOTCDMA);
    PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_GPUOTCDMA].cycle = eCycle;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle[PCSX::PSXINT_GPUOTCDMA].sCycle =
        PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle;
}

/*
DMA5 = N/A (PIO)
*/

// void dma(uint32_t madr, uint32_t bcr, uint32_t chcr);
void psxDma4(uint32_t madr, uint32_t bcr, uint32_t chcr);
void psxDma6(uint32_t madr, uint32_t bcr, uint32_t chcr);
void spuInterrupt();
void gpuotcInterrupt();
// void dmaInterrupt();

#endif
