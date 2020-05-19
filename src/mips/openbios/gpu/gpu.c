/*

MIT License

Copyright (c) 2020 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

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
