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
 * Handles PSX DMA functions.
 */

#include "core/psxdma.h"

#include "core/debug.h"
#include "spu/interface.h"

// Dma0/1 in Mdec.c
// Dma3   in CdRom.c

void spuInterrupt() {
    HW_DMA4_CHCR &= SWAP_LE32(~0x01000000);
    DMA_INTERRUPT(4);
}

void psxDma4(uint32_t madr, uint32_t bcr, uint32_t chcr) {  // SPU
    uint16_t *ptr;
    uint32_t size;

    switch (chcr) {
        case 0x01000201:  // cpu to spu transfer
            PSXDMA_LOG("*** DMA4 SPU - mem2spu *** %x addr = %x size = %x\n", chcr, madr, bcr);
            ptr = (uint16_t *)PSXM(madr);
            if (ptr == nullptr) {
                PSXDMA_LOG("*** DMA4 SPU - mem2spu *** NULL Pointer!!!\n");
                break;
            }
            size = (bcr >> 16) * (bcr & 0xffff) * 2;
            PCSX::g_emulator->m_spu->writeDMAMem(ptr, size);
            if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                    .get<PCSX::Emulator::DebugSettings::Debug>()) {
                PCSX::g_emulator->m_debug->checkDMAread(4, madr, size * 2);
            }

            // Jungle Book - max 0.333x DMA length
            // Harry Potter and the Philosopher's Stone - max 0.5x DMA length
            // uint32_t dmalen=64 + ((bcr >> 18) * (bcr & 0xffff)); // less linear to DMA length which should work with
            // both games above?
            scheduleSPUDMAIRQ((bcr >> 16) * (bcr & 0xffff) / 2);
            return;

        case 0x01000200:  // spu to cpu transfer
            PSXDMA_LOG("*** DMA4 SPU - spu2mem *** %x addr = %x size = %x\n", chcr, madr, bcr);
            ptr = (uint16_t *)PSXM(madr);
            if (ptr == nullptr) {
                PSXDMA_LOG("*** DMA4 SPU - spu2mem *** NULL Pointer!!!\n");
                break;
            }
            size = (bcr >> 16) * (bcr & 0xffff) * 2;
            PCSX::g_emulator->m_spu->readDMAMem(ptr, size);
            if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                    .get<PCSX::Emulator::DebugSettings::Debug>()) {
                PCSX::g_emulator->m_debug->checkDMAwrite(4, madr, size * 2);
            }
            PCSX::g_emulator->m_psxCpu->Clear(madr, size * 2);

#if 1
            scheduleSPUDMAIRQ((bcr >> 16) * (bcr & 0xffff) / 2);
#else
            // Experimental burst dma transfer (0.333x max)
            scheduleSPUDMAIRQ((bcr >> 16) * (bcr & 0xffff) / 3);
#endif
            return;

        default:
            PSXDMA_LOG("*** DMA4 SPU - unknown *** %x addr = %x size = %x\n", chcr, madr, bcr);
            break;
    }

    HW_DMA4_CHCR &= SWAP_LE32(~0x01000000);
    DMA_INTERRUPT(4);
}

void psxDma6(uint32_t madr, uint32_t bcr, uint32_t chcr) {
    uint32_t size;
    uint32_t *mem = (uint32_t *)PSXM(madr);

    PSXDMA_LOG("*** DMA6 OT *** %x addr = %x size = %x\n", chcr, madr, bcr);

    if (chcr == 0x11000002) {
        if (mem == nullptr) {
            PSXDMA_LOG("*** DMA6 OT *** NULL Pointer!!!\n");
            HW_DMA6_CHCR &= SWAP_LE32(~0x01000000);
            DMA_INTERRUPT(6);
            return;
        }

        // already 32-bit size
        size = bcr;

        while (bcr--) {
            *mem-- = SWAP_LE32((madr - 4) & 0xffffff);
            madr -= 4;
        }
        mem++;
        *mem = 0xffffff;
        if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                .get<PCSX::Emulator::DebugSettings::Debug>()) {
            PCSX::g_emulator->m_debug->checkDMAwrite(6, madr, size * 4);
        }

#if 1
        scheduleGPUOTCDMAIRQ(size);
#else
        // Experimental burst dma transfer (0.333x max)
        scheduleGPUOTCDMAIRQ(size / 3);
#endif
        return;
    } else {
        // Unknown option
        PSXDMA_LOG("*** DMA6 OT - unknown *** %x addr = %x size = %x\n", chcr, madr, bcr);
    }

    HW_DMA6_CHCR &= SWAP_LE32(~0x01000000);
    DMA_INTERRUPT(6);
}

void gpuotcInterrupt() {
    HW_DMA6_CHCR &= SWAP_LE32(~0x01000000);
    DMA_INTERRUPT(6);
}
