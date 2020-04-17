/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

#include "common/compiler/stdint.h"
#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "openbios/fileio/fileio.h"
#include "openbios/gpu/gpu.h"

static void GPU_timeout(char * function) {
    psxprintf("%s timeout: gp1=%08x\n", function, GPU_STATUS);
    GPU_abort();
}

void GPU_dw(unsigned x, unsigned y, unsigned w, unsigned h, const void * src) {
    uint32_t * ptr = (uint32_t *) src;
    int waitCounter = 0x100000;
    while ((GPU_STATUS & 0x04000000) == 0) if (waitCounter-- == 0) GPU_timeout("GPU_dw");
    GPU_DATA = 0xa0000000;
    GPU_DATA = (y << 0x10) | (x & 0xffff);
    GPU_DATA = (h << 0x10) | (w & 0xffff);
    int amount = (w * h) / 2;
    while (amount--) GPU_DATA = *ptr++;
}

void GPU_mem2vram(unsigned x, unsigned y, unsigned w, unsigned h, const void * src) {

    GPU_sync();
    GPU_DATA = 0xa0000000;
    GPU_DATA = (y << 0x10) | (x & 0xffff);
    GPU_DATA = (h << 0x10) | (w & 0xffff);
    GPU_STATUS = 0x4000002;
    DPCR |= 0x800;
    DMA_CTRL[DMA_GPU].MADR = (uintptr_t) src;
    DMA_CTRL[DMA_GPU].BCR = ((((w * h) / 2) >> 4) << 16) | 0x10;
    DMA_CTRL[DMA_GPU].CHCR = 0x1000201;
}

void GPU_send(uint32_t cmd) {
    GPU_STATUS = cmd;
}

int GPU_cw(uint32_t cmd) {
    int ret = GPU_sync();
    GPU_DATA = cmd;
    return ret;
}

void GPU_cwb(uint32_t * cmds, int count) {
    GPU_sync();
    while (count--) GPU_DATA = *cmds++;
}

void GPU_sendPackets(uint32_t * start) {
    psxprintf("0x01(%08x)\n", start);
    GPU_sync();
    GPU_STATUS = 0x04000002;
    DICR = 0;
    DPCR |= 0x800;
    DMA_CTRL[DMA_GPU].MADR = (uintptr_t) start;
    DMA_CTRL[DMA_GPU].BCR = 0;
    psxprintf("0x02\n");
    DMA_CTRL[DMA_GPU].CHCR = 0x01000401;
    psxprintf("0x03\n");
}

void GPU_abort() {
    DMA_CTRL[DMA_GPU].CHCR = 0x401;
    GPU_STATUS = 0x04000000;
    GPU_STATUS = 0x02000000;
    GPU_STATUS = 0x01000000;
}

uint32_t GPU_getStatus() {
    return GPU_STATUS;
}

int GPU_sync() {
    int waitCounter = 0x10000000;

    if ((GPU_STATUS & 0x60000000) == 0) {
        while ((GPU_STATUS & 0x10000000) == 0) {
            if (waitCounter-- == 0) {
                GPU_timeout("GPU_sync(FG)");
                return -1;
            }
        }
    } else {
        while ((DMA_CTRL[DMA_GPU].CHCR & 0x1000000) != 0) {
            if (waitCounter-- == 0) {
                GPU_timeout("GPU_sync(BG)");
                return -1;
            }
        }
        while ((GPU_STATUS & 0x4000000) == 0);
        GPU_STATUS = 0x4000000;
    }
    return 0;
}
