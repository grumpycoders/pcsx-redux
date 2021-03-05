/*  Copyright (c) 2010, shalma.
 *  Portions Copyright (c) 2002, Pete Bernert.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "core/gpu.h"

#include "core/pgxp_mem.h"
#include "core/psxdma.h"
#include "core/psxhw.h"

#define GPUSTATUS_ODDLINES 0x80000000
#define GPUSTATUS_DMABITS 0x60000000           // Two bits
#define GPUSTATUS_READYFORCOMMANDS 0x10000000  // DMA block ready
#define GPUSTATUS_READYFORVRAM 0x08000000
#define GPUSTATUS_IDLE 0x04000000  // CMD ready
#define GPUSTATUS_MODE 0x02000000  // Data request mode

#define GPUSTATUS_DISPLAYDISABLED 0x00800000
#define GPUSTATUS_INTERLACED 0x00400000
#define GPUSTATUS_RGB24 0x00200000
#define GPUSTATUS_PAL 0x00100000
#define GPUSTATUS_DOUBLEHEIGHT 0x00080000
#define GPUSTATUS_WIDTHBITS 0x00070000  // Three bits
#define GPUSTATUS_MASKENABLED 0x00001000
#define GPUSTATUS_MASKDRAWN 0x00000800
#define GPUSTATUS_DRAWINGALLOWED 0x00000400
#define GPUSTATUS_DITHER 0x00000200

inline bool PCSX::GPU::CheckForEndlessLoop(uint32_t laddr) {
    if (laddr == s_lUsedAddr[1]) return true;
    if (laddr == s_lUsedAddr[2]) return true;

    if (laddr < s_lUsedAddr[0])
        s_lUsedAddr[1] = laddr;
    else
        s_lUsedAddr[2] = laddr;

    s_lUsedAddr[0] = laddr;

    return false;
}

uint32_t PCSX::GPU::gpuDmaChainSize(uint32_t addr) {
    uint32_t size;
    uint32_t DMACommandCounter = 0;

    s_lUsedAddr[0] = s_lUsedAddr[1] = s_lUsedAddr[2] = 0xffffff;

    // initial linked list s_ptr (word)
    size = 1;

    do {
        addr &= 0x1ffffc;

        if (DMACommandCounter++ > 2000000) break;
        if (CheckForEndlessLoop(addr)) break;

        // # 32-bit blocks to transfer
        size += psxMu8(addr + 3);

        // next 32-bit pointer
        addr = psxMu32(addr & ~0x3) & 0xffffff;
        size += 1;
    } while (!(addr & 0x800000));  // contrary to some documentation, the end-of-linked-list marker is not actually
                                   // 0xFF'FFFF any pointer with bit 23 set will do.
    return size;
}

int PCSX::GPU::gpuReadStatus() {
    int hard;

    // GPU plugin
    hard = readStatus();

    // Gameshark Lite - wants to see VRAM busy
    // - Must enable GPU 'Fake Busy States' hack
    if ((hard & GPUSTATUS_IDLE) == 0) hard &= ~GPUSTATUS_READYFORVRAM;

    return hard;
}

void PCSX::GPU::dma(uint32_t madr, uint32_t bcr, uint32_t chcr) {  // GPU
    uint32_t *ptr;
    uint32_t size, bs;

    switch (chcr) {
        case 0x01000200:  // vram2mem
            PSXDMA_LOG("*** DMA2 GPU - vram2mem *** %lx addr = %lx size = %lx\n", chcr, madr, bcr);
            ptr = (uint32_t *)PSXM(madr);
            if (ptr == nullptr) {
                PSXDMA_LOG("*** DMA2 GPU - vram2mem *** NULL Pointer!!!\n");
                break;
            }
            // BA blocks * BS words (word = 32-bits)
            size = (bcr >> 16) * (bcr & 0xffff);
            readDataMem(ptr, size);
            PCSX::g_emulator->m_psxCpu->Clear(madr, size);
#if 1
            // already 32-bit word size ((size * 4) / 4)
            scheduleGPUDMAIRQ(size);
#else
            // Experimental burst dma transfer (0.333x max)
            scheduleGPUDMAIRQ(size / 3);
#endif
            return;

        case 0x01000201:  // mem2vram
            bs = (bcr & 0xffff);
            size = (bcr >> 16) * bs;  // BA blocks * BS words (word = 32-bits)
            PSXDMA_LOG("*** DMA 2 - GPU mem2vram *** %lx addr = %lxh, BCR %lxh => size %d = BA(%d) * BS(%xh)\n", chcr,
                       madr, bcr, size, size / bs, size / (bcr >> 16));
            ptr = (uint32_t *)PSXM(madr);
            if (ptr == nullptr) {
                PSXDMA_LOG("*** DMA2 GPU - mem2vram *** NULL Pointer!!!\n");
                break;
            }
            pgxpMemory(PGXP_ConvertAddress(madr), PGXP_GetMem());
            writeDataMem(ptr, size);

#if 0
            // already 32-bit word size ((size * 4) / 4)
            scheduleGPUDMAIRQ(size);
#else
            // X-Files video interlace. Experimental delay depending of BS.
            scheduleGPUDMAIRQ((7 * size) / bs);
#endif
            return;

        case 0x00000401:  // Vampire Hunter D: title screen linked list update (see psxhw.c)
        case 0x01000401:  // dma chain
            PSXDMA_LOG("*** DMA 2 - GPU dma chain *** %8.8lx addr = %lx size = %lx\n", chcr, madr, bcr);

            size = gpuDmaChainSize(madr);
            dmaChain((uint32_t *)PCSX::g_emulator->m_psxMem->g_psxM, madr & 0x1fffff);

            // Tekken 3 = use 1.0 only (not 1.5x)

            // Einhander = parse linked list in pieces (todo)
            // Final Fantasy 4 = internal vram time (todo)
            // Rebel Assault 2 = parse linked list in pieces (todo)
            // Vampire Hunter D = allow edits to linked list (todo)
            scheduleGPUDMAIRQ(size);
            return;

        default:
            PSXDMA_LOG("*** DMA 2 - GPU unknown *** %lx addr = %lx size = %lx\n", chcr, madr, bcr);
            break;
    }

    HW_DMA2_CHCR &= SWAP_LE32(~0x01000000);
    DMA_INTERRUPT(2);
}

void PCSX::GPU::gpuInterrupt() {
    HW_DMA2_CHCR &= SWAP_LE32(~0x01000000);
    DMA_INTERRUPT(2);
}
