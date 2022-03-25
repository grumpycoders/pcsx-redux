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
    PCSX::g_emulator->m_cpu->scheduleInterrupt(PCSX::PSXINT_GPUDMA, eCycle);
}

static inline void scheduleSPUDMAIRQ(uint32_t eCycle) {
    PCSX::g_emulator->m_cpu->scheduleInterrupt(PCSX::PSXINT_SPUDMA, eCycle);
}

static inline void scheduleMDECOUTDMAIRQ(uint32_t eCycle) {
    PCSX::g_emulator->m_cpu->scheduleInterrupt(PCSX::PSXINT_MDECOUTDMA, eCycle);
}

static inline void scheduleMDECINDMAIRQ(uint32_t eCycle) {
    PCSX::g_emulator->m_cpu->scheduleInterrupt(PCSX::PSXINT_MDECINDMA, eCycle);
}

static inline void scheduleGPUOTCDMAIRQ(uint32_t eCycle) {
    PCSX::g_emulator->m_cpu->scheduleInterrupt(PCSX::PSXINT_GPUOTCDMA, eCycle);
}

/*
DMA5 = N/A (PIO)
*/

// void dma(uint32_t madr, uint32_t bcr, uint32_t chcr);
void dma4(uint32_t madr, uint32_t bcr, uint32_t chcr);
void dma6(uint32_t madr, uint32_t bcr, uint32_t chcr);
void spuInterrupt();
void gpuotcInterrupt();
// void dmaInterrupt();

#endif
