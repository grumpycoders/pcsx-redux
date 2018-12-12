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

#include "psxdma.h"

// Dma0/1 in Mdec.c
// Dma3   in CdRom.c

void spuInterrupt() {
    HW_DMA4_CHCR &= SWAP32(~0x01000000);
    DMA_INTERRUPT(4);
}

void psxDma4(u32 madr, u32 bcr, u32 chcr) {  // SPU
    u16 *ptr;
    u32 size;

    switch (chcr) {
        case 0x01000201:  // cpu to spu transfer
#ifdef PSXDMA_LOG
            PSXDMA_LOG("*** DMA4 SPU - mem2spu *** %x addr = %x size = %x\n", chcr, madr, bcr);
#endif
            ptr = (u16 *)PSXM(madr);
            if (ptr == NULL) {
#ifdef PSXDMA_LOG
                PSXDMA_LOG("*** DMA4 SPU - mem2spu *** NULL Pointer!!!\n");
#endif
                break;
            }
            SPU_writeDMAMem(ptr, (bcr >> 16) * (bcr & 0xffff) * 2);

            // Jungle Book - max 0.333x DMA length
            // Harry Potter and the Philosopher's Stone - max 0.5x DMA length
            // u32 dmalen=64 + ((bcr >> 18) * (bcr & 0xffff)); // less linear to DMA length which should work with both
            // games above?
            SPUDMA_INT((bcr >> 16) * (bcr & 0xffff) / 2);
            return;

        case 0x01000200:  // spu to cpu transfer
#ifdef PSXDMA_LOG
            PSXDMA_LOG("*** DMA4 SPU - spu2mem *** %x addr = %x size = %x\n", chcr, madr, bcr);
#endif
            ptr = (u16 *)PSXM(madr);
            if (ptr == NULL) {
#ifdef PSXDMA_LOG
                PSXDMA_LOG("*** DMA4 SPU - spu2mem *** NULL Pointer!!!\n");
#endif
                break;
            }
            size = (bcr >> 16) * (bcr & 0xffff) * 2;
            SPU_readDMAMem(ptr, size);
#ifdef PSXREC
            psxCpu->Clear(madr, size);
#endif

#if 1
            SPUDMA_INT((bcr >> 16) * (bcr & 0xffff) / 2);
#else
            // Experimental burst dma transfer (0.333x max)
            SPUDMA_INT((bcr >> 16) * (bcr & 0xffff) / 3);
#endif
            return;

#ifdef PSXDMA_LOG
        default:
            PSXDMA_LOG("*** DMA4 SPU - unknown *** %x addr = %x size = %x\n", chcr, madr, bcr);
            break;
#endif
    }

    HW_DMA4_CHCR &= SWAP32(~0x01000000);
    DMA_INTERRUPT(4);
}

void psxDma6(u32 madr, u32 bcr, u32 chcr) {
    u32 size;
    u32 *mem = (u32 *)PSXM(madr);

#ifdef PSXDMA_LOG
    PSXDMA_LOG("*** DMA6 OT *** %x addr = %x size = %x\n", chcr, madr, bcr);
#endif

    if (chcr == 0x11000002) {
        if (mem == NULL) {
#ifdef PSXDMA_LOG
            PSXDMA_LOG("*** DMA6 OT *** NULL Pointer!!!\n");
#endif
            HW_DMA6_CHCR &= SWAP32(~0x01000000);
            DMA_INTERRUPT(6);
            return;
        }

        // already 32-bit size
        size = bcr;

        while (bcr--) {
            *mem-- = SWAP32((madr - 4) & 0xffffff);
            madr -= 4;
        }
        mem++;
        *mem = 0xffffff;

#if 1
        GPUOTCDMA_INT(size);
#else
        // Experimental burst dma transfer (0.333x max)
        GPUOTCDMA_INT(size / 3);
#endif
        return;
    }
#ifdef PSXDMA_LOG
    else {
        // Unknown option
        PSXDMA_LOG("*** DMA6 OT - unknown *** %x addr = %x size = %x\n", chcr, madr, bcr);
    }
#endif

    HW_DMA6_CHCR &= SWAP32(~0x01000000);
    DMA_INTERRUPT(6);
}

void gpuotcInterrupt() {
    HW_DMA6_CHCR &= SWAP32(~0x01000000);
    DMA_INTERRUPT(6);
}
