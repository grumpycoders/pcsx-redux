/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

#include "common/hardware/gpu.h"

#include <stdint.h>

#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/irq.h"
#include "common/syscalls/syscalls.h"

static const uint8_t polydata1[] = {
    0xff, 0x80, 0x33, 0x38, 0x01, 0x00, 0xff, 0xff, 0xff, 0x80, 0x33, 0x00, 0x30, 0x00, 0x03, 0x00,
    0xff, 0x80, 0x33, 0x00, 0x05, 0x00, 0x29, 0x00, 0xff, 0x80, 0x33, 0x00, 0x30, 0x00, 0x2e, 0x00,
};
static const uint8_t polydata2[] = {
    0x80, 0xff, 0x33, 0x38, 0x3b, 0x00, 0x0a, 0x00, 0x80, 0xff, 0x33, 0x00, 0x71, 0x00, 0x02, 0x00,
    0x80, 0xff, 0x33, 0x00, 0x44, 0x00, 0x31, 0x00, 0x80, 0xff, 0x33, 0x00, 0x73, 0x00, 0x23, 0x00,
};
static const uint8_t polydata3[] = {
    0x33, 0xff, 0x80, 0x38, 0x89, 0x00, 0x0b, 0x00, 0x33, 0xff, 0x80, 0x00, 0xa6, 0x00, 0x0a, 0x00,
    0x33, 0xff, 0x80, 0x00, 0x7f, 0x00, 0x37, 0x00, 0x33, 0xff, 0x80, 0x00, 0xa9, 0x00, 0x31, 0x00,
};
static const uint8_t polydata4[] = {
    0x33, 0x80, 0xff, 0x38, 0xb6, 0x00, 0x0f, 0x00, 0x33, 0x80, 0xff, 0x00, 0xda, 0x00, 0x0d, 0x00,
    0x33, 0x80, 0xff, 0x00, 0xbb, 0x00, 0x3e, 0x00, 0x33, 0x80, 0xff, 0x00, 0xdf, 0x00, 0x3e, 0x00,
};
static const uint8_t polydata5[] = {
    0xff, 0x00, 0x00, 0x38, 0x01, 0x00, 0x4e, 0x00, 0xff, 0x00, 0x00, 0x00, 0x2d, 0x00, 0x55, 0x00,
    0xff, 0x00, 0x00, 0x00, 0x08, 0x00, 0x77, 0x00, 0xff, 0x00, 0x00, 0x00, 0x30, 0x00, 0x7e, 0x00,
};
static const uint8_t polydata6[] = {
    0x00, 0xff, 0x00, 0x38, 0x3e, 0x00, 0x57, 0x00, 0x00, 0xff, 0x00, 0x00, 0x6f, 0x00, 0x56, 0x00,
    0x00, 0xff, 0x00, 0x00, 0x43, 0x00, 0x7e, 0x00, 0x00, 0xff, 0x00, 0x00, 0x72, 0x00, 0x75, 0x00,
};
static const uint8_t polydata7[] = {
    0x00, 0x00, 0xff, 0x38, 0x87, 0x00, 0x5e, 0x00, 0x00, 0x00, 0xff, 0x00, 0xa9, 0x00, 0x57, 0x00,
    0x00, 0x00, 0xff, 0x00, 0x80, 0x00, 0x86, 0x00, 0x00, 0x00, 0xff, 0x00, 0xa8, 0x00, 0x81, 0x00,
};
static const uint8_t polydata8[] = {
    0xff, 0xff, 0x00, 0x38, 0xb5, 0x00, 0x5e, 0x00, 0xff, 0xff, 0x00, 0x00, 0xdb, 0x00, 0x5d, 0x00,
    0xff, 0xff, 0x00, 0x00, 0xbc, 0x00, 0x8f, 0x00, 0xff, 0xff, 0x00, 0x00, 0xde, 0x00, 0x8e, 0x00,
};
static const uint8_t polydata9[] = {
    0xff, 0x00, 0xff, 0x38, 0xff, 0xff, 0xa2, 0x00, 0xff, 0x00, 0xff, 0x00, 0x2f, 0x00, 0xa3, 0x00,
    0xff, 0x00, 0xff, 0x00, 0x08, 0x00, 0xc6, 0x00, 0xff, 0x00, 0xff, 0x00, 0x30, 0x00, 0xcd, 0x00,
};
static const uint8_t polydata10[] = {
    0x00, 0xff, 0xff, 0x38, 0x3e, 0x00, 0xa7, 0x00, 0x00, 0xff, 0xff, 0x00, 0x6e, 0x00, 0xa5, 0x00,
    0x00, 0xff, 0xff, 0x00, 0x43, 0x00, 0xce, 0x00, 0x00, 0xff, 0xff, 0x00, 0x73, 0x00, 0xc6, 0x00,
};
static const uint8_t polydata11[] = {
    0xff, 0xff, 0xff, 0x38, 0x86, 0x00, 0xad, 0x00, 0xff, 0xff, 0xff, 0x00, 0xaa, 0x00, 0xa7, 0x00,
    0xff, 0xff, 0xff, 0x00, 0x7f, 0x00, 0xd6, 0x00, 0xff, 0xff, 0xff, 0x00, 0xa9, 0x00, 0xd2, 0x00,
};
static const uint8_t polydata12[] = {
    0x80, 0x80, 0x80, 0x38, 0xb5, 0x00, 0xae, 0x00, 0x80, 0x80, 0x80, 0x00, 0xdb, 0x00, 0xae, 0x00,
    0x80, 0x80, 0x80, 0x00, 0xbc, 0x00, 0xdf, 0x00, 0x80, 0x80, 0x80, 0x00, 0xde, 0x00, 0xdd, 0x00,
};

static void reset() {
    IMASK = 0;
    IREG = 0;
    for (unsigned i = 0; i < 7; i++) {
        DMA_CTRL[i].CHCR = 0;
        DMA_CTRL[i].BCR = 0;
        DMA_CTRL[i].MADR = 0;
    }
    DPCR = 0x800;
    uint32_t dicr = DICR;
    DICR = dicr;
    DICR = 0;
    GPU_STATUS = 0x00000000;
    struct DisplayModeConfig config = {
        .hResolution = HR_320,
        .vResolution = VR_240,
        .videoMode = VM_NTSC,
        .colorDepth = CD_15BITS,
        .videoInterlace = VI_OFF,
        .hResolutionExtended = HRE_NORMAL,
    };
    setDisplayMode(&config);
    setHorizontalRange(0, 0xa00);
    setVerticalRange(16, 255);
    setDisplayArea(0, 0);
    setDrawingArea(0, 0, 320, 240);
}

static int s_frame = 0;
static void setRelativeDrawingOffset(int16_t x, int16_t y) { setDrawingOffset(s_frame ? x : x + 320, y); }

static void flip() {
    uint32_t imask = IMASK;
    IMASK = imask | IRQ_VBLANK;
    while ((IREG & IRQ_VBLANK) == 0);
    IREG &= ~IRQ_VBLANK;
    IMASK = imask;
    s_frame ^= 1;
    setDisplayArea(s_frame ? 320 : 0, 0);
    setDrawingArea(s_frame ? 0 : 320, 0, s_frame ? 320 : 640, 240);
    setRelativeDrawingOffset(0, 0);
    struct FastFill ff = {
        .c = {{.r = 0x68, .g = 0xb0, .b = 0xd8}},
        .x = s_frame ? 0 : 320,
        .y = 0,
        .w = 320,
        .h = 240,
    };
    fastFill(&ff);
}

static void sendOnePolygon(const uint8_t* data_) {
    const uint32_t* data = (const uint32_t*)data_;
    waitGPU();
    for (unsigned i = 0; i < 8; i++) {
        GPU_DATA = data[i];
    }
}

static void sendOnePolygonNoWait(const uint8_t* data_) {
    const uint32_t* data = (const uint32_t*)data_;
    for (unsigned i = 0; i < 8; i++) {
        GPU_DATA = data[i];
    }
}

static int s_frameCount = 0;
static int s_sequenceId = 0;

static uint32_t s_singleBlock[8 * 12];
static uint32_t s_DMAChain[9 * 12];

static void sendSingleBlock(unsigned blockSize) {
    uint32_t bcr = (sizeof(s_singleBlock) >> 2) / blockSize;
    DMA_CTRL[DMA_GPU].MADR = (uintptr_t)s_singleBlock;
    DMA_CTRL[DMA_GPU].BCR = (bcr << 16) | blockSize;
    DMA_CTRL[DMA_GPU].CHCR = 0x01000201;
}

int main() {
    __builtin_memcpy(s_singleBlock, polydata1, sizeof(polydata1));
    __builtin_memcpy(s_singleBlock + 8, polydata2, sizeof(polydata2));
    __builtin_memcpy(s_singleBlock + 16, polydata3, sizeof(polydata3));
    __builtin_memcpy(s_singleBlock + 24, polydata4, sizeof(polydata4));
    __builtin_memcpy(s_singleBlock + 32, polydata5, sizeof(polydata5));
    __builtin_memcpy(s_singleBlock + 40, polydata6, sizeof(polydata6));
    __builtin_memcpy(s_singleBlock + 48, polydata7, sizeof(polydata7));
    __builtin_memcpy(s_singleBlock + 56, polydata8, sizeof(polydata8));
    __builtin_memcpy(s_singleBlock + 64, polydata9, sizeof(polydata9));
    __builtin_memcpy(s_singleBlock + 72, polydata10, sizeof(polydata10));
    __builtin_memcpy(s_singleBlock + 80, polydata11, sizeof(polydata11));
    __builtin_memcpy(s_singleBlock + 88, polydata12, sizeof(polydata12));

    __builtin_memcpy(s_DMAChain + 1, polydata1, sizeof(polydata1));
    __builtin_memcpy(s_DMAChain + 10, polydata2, sizeof(polydata2));
    __builtin_memcpy(s_DMAChain + 19, polydata3, sizeof(polydata3));
    __builtin_memcpy(s_DMAChain + 28, polydata4, sizeof(polydata4));
    __builtin_memcpy(s_DMAChain + 37, polydata5, sizeof(polydata5));
    __builtin_memcpy(s_DMAChain + 46, polydata6, sizeof(polydata6));
    __builtin_memcpy(s_DMAChain + 55, polydata7, sizeof(polydata7));
    __builtin_memcpy(s_DMAChain + 64, polydata8, sizeof(polydata8));
    __builtin_memcpy(s_DMAChain + 73, polydata9, sizeof(polydata9));
    __builtin_memcpy(s_DMAChain + 82, polydata10, sizeof(polydata10));
    __builtin_memcpy(s_DMAChain + 91, polydata11, sizeof(polydata11));
    __builtin_memcpy(s_DMAChain + 100, polydata12, sizeof(polydata12));

    for (unsigned i = 0; i < 11; i++) {
        s_DMAChain[i * 9] = 0x08000000 | ((uintptr_t)(&s_DMAChain[i * 9 + 9]) & 0xffffff);
    }
    s_DMAChain[99] = 0x08ffffff;

    reset();
    flip();
    flip();
    enableDisplay();
    while (1) {
        if (s_frameCount == 0) {
            *(volatile uint8_t*)(s_sequenceId) = s_sequenceId;
        }
        setRelativeDrawingOffset(0, 0);
        switch (s_sequenceId) {
            case 0:
                sendOnePolygon(polydata1);
                sendOnePolygon(polydata2);
                sendOnePolygon(polydata3);
                sendOnePolygon(polydata4);
                sendOnePolygon(polydata5);
                sendOnePolygon(polydata6);
                sendOnePolygon(polydata7);
                sendOnePolygon(polydata8);
                sendOnePolygon(polydata9);
                sendOnePolygon(polydata10);
                sendOnePolygon(polydata11);
                sendOnePolygon(polydata12);
                break;
            case 1:  // derps
                sendOnePolygonNoWait(polydata1);
                sendOnePolygonNoWait(polydata2);
                sendOnePolygonNoWait(polydata3);
                sendOnePolygonNoWait(polydata4);
                sendOnePolygonNoWait(polydata5);
                sendOnePolygonNoWait(polydata6);
                sendOnePolygonNoWait(polydata7);
                sendOnePolygonNoWait(polydata8);
                sendOnePolygonNoWait(polydata9);
                sendOnePolygonNoWait(polydata10);
                sendOnePolygonNoWait(polydata11);
                sendOnePolygonNoWait(polydata12);
                break;
            case 2:
                sendGPUStatus(0x04000001);
                sendSingleBlock(1);
                break;
            case 3:  // freezes
                // sendGPUStatus(0x04000002);
                // sendSingleBlock(1);
                break;
            case 4:
                sendGPUStatus(0x04000001);
                sendSingleBlock(2);
                break;
            case 5:  // freezes
                // sendGPUStatus(0x04000002);
                // sendSingleBlock(2);
                break;
            case 6:
                sendGPUStatus(0x04000001);
                sendSingleBlock(4);
                break;
            case 7:  // freezes
                // sendGPUStatus(0x04000002);
                // sendSingleBlock(4);
                break;
            case 8:
                sendGPUStatus(0x04000001);
                sendSingleBlock(8);
                break;
            case 9:
                sendGPUStatus(0x04000002);
                sendSingleBlock(8);
                break;
            case 10:  // derps
                sendGPUStatus(0x04000001);
                sendSingleBlock(12);
                break;
            case 11:  // freezes
                // sendGPUStatus(0x04000002);
                // sendSingleBlock(12);
                break;
            case 12:  // derps
                sendGPUStatus(0x04000001);
                sendSingleBlock(16);
                break;
            case 13:
                sendGPUStatus(0x04000002);
                sendSingleBlock(16);
                break;
            case 14:
                sendGPUStatus(0x04000001);
                DMA_CTRL[DMA_GPU].MADR = (uintptr_t)s_DMAChain;
                DMA_CTRL[DMA_GPU].CHCR = 0x01000401;
                break;
            case 15:
                sendGPUStatus(0x04000002);
                DMA_CTRL[DMA_GPU].MADR = (uintptr_t)s_DMAChain;
                DMA_CTRL[DMA_GPU].CHCR = 0x01000401;
                break;
        }
        while ((DMA_CTRL[DMA_GPU].CHCR & 0x01000000) != 0);
        for (unsigned i = 0; i < s_sequenceId; i++) {
            setRelativeDrawingOffset(i * 10 + 10, 220);
            sendGPUData(0x70ffffff);
            GPU_DATA = 0x00000000;
        }
        flip();
        if (s_frameCount++ == 90) {
            s_sequenceId++;
            s_frameCount = 0;
            if (s_sequenceId == 16) {
                s_sequenceId = 0;
            }
        }
    }
    return 0;
}
