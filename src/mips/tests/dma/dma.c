/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

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

#ifndef PCSX_TESTS
#define PCSX_TESTS 0
#endif

#if PCSX_TESTS
#define CESTER_MAYBE_TEST CESTER_SKIP_TEST
#else
#define CESTER_MAYBE_TEST CESTER_TEST
#endif

#include "common/hardware/dma.h"

#include "common/hardware/gpu.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/irq.h"
#include "common/syscalls/syscalls.h"

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

// clang-format off

#include "../cop0/cester-cop0.c"

CESTER_TEST(normal_dma, dma_tests,
    sendGPUStatus(0);
    sendGPUStatus(0x04000001);
    sendGPUData(0xe1000000);
    DPCR = 0x00000800;
    DICR = 0x00840000;
    IMASK = IRQ_VBLANK | IRQ_DMA;
    uint32_t cmd = 0xe1000555;
    sendGPUStatus(0x04000002);
    while ((GPU_STATUS & 0x10000000) == 0);
    DMA_CTRL[DMA_GPU].MADR = (uintptr_t)&cmd;
    DMA_CTRL[DMA_GPU].BCR = 0x00010001;
    DMA_CTRL[DMA_GPU].CHCR = 0x01000201;
    unsigned count = 0;
    unsigned timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 128) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    uint32_t stat = GPU_STATUS & 0x000007ff;
    uintptr_t bcr = DMA_CTRL[DMA_GPU].BCR;
    uint32_t madr = DMA_CTRL[DMA_GPU].MADR;
    uint32_t chcr = DMA_CTRL[DMA_GPU].CHCR;
    uint32_t dicr = DICR;
    const uintptr_t expectedAddr = ((uintptr_t)(&cmd + 1)) & 0xffffff;
    cester_assert_uint_eq(0, timeout);
    cester_assert_uint_eq(0, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0, s_from);
    cester_assert_uint_eq(0, s_epc);
    cester_assert_uint_eq(0x555, stat);
    cester_assert_uint_eq(1, bcr);
    cester_assert_uint_eq(expectedAddr, madr);
    cester_assert_uint_eq(0x00000201, chcr);
    cester_assert_uint_eq(0x84840000, dicr);
    DICR = (dicr & ~0x7f000000) | 0x04000000;
    dicr = DICR;
    cester_assert_uint_eq(0x00840000, dicr);
)

CESTER_TEST(normal_dma_dicr_toggle, dma_tests,
    sendGPUStatus(0);
    sendGPUStatus(0x04000001);
    sendGPUData(0xe1000000);
    DPCR = 0x00000800;
    DICR = 0x00840000;
    IMASK = IRQ_VBLANK | IRQ_DMA;
    uint32_t cmd = 0xe1000555;
    sendGPUStatus(0x04000002);
    while ((GPU_STATUS & 0x10000000) == 0);
    DMA_CTRL[DMA_GPU].MADR = (uintptr_t)&cmd;
    DMA_CTRL[DMA_GPU].BCR = 0x00010001;
    DMA_CTRL[DMA_GPU].CHCR = 0x01000201;
    unsigned count;
    unsigned timeout;
    count = 0;
    timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 128) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    uint32_t stat = GPU_STATUS & 0x000007ff;
    uintptr_t bcr = DMA_CTRL[DMA_GPU].BCR;
    uint32_t madr = DMA_CTRL[DMA_GPU].MADR;
    uint32_t chcr = DMA_CTRL[DMA_GPU].CHCR;
    uint32_t dicr = DICR;
    const uintptr_t expectedAddr = ((uintptr_t)(&cmd + 1)) & 0xffffff;
    cester_assert_uint_eq(0, timeout);
    cester_assert_uint_eq(0, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0, s_from);
    cester_assert_uint_eq(0, s_epc);
    cester_assert_uint_eq(0x555, stat);
    cester_assert_uint_eq(1, bcr);
    cester_assert_uint_eq(expectedAddr, madr);
    cester_assert_uint_eq(0x00000201, chcr);
    cester_assert_uint_eq(0x84840000, dicr);
    DICR = 0x00800000;
    dicr = DICR;
    count = 0;
    timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 32) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    cester_assert_uint_eq(1, timeout);
    cester_assert_uint_eq(0x84800000, dicr);
    DICR = 0;
    dicr = DICR;
    count = 0;
    timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 32) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    cester_assert_uint_eq(1, timeout);
    cester_assert_uint_eq(0x04000000, dicr);
    DICR = 0x00800000;
    dicr = DICR;
    count = 0;
    timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 128) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    cester_assert_uint_eq(0, timeout);
    cester_assert_uint_eq(0x84800000, dicr);
    DICR = 0x00008000;
    dicr = DICR;
    count = 0;
    timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 32) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    cester_assert_uint_eq(1, timeout);
    cester_assert_uint_eq(0x84008000, dicr);
    DICR = 0x00800000;
    dicr = DICR;
    count = 0;
    timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 32) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    cester_assert_uint_eq(1, timeout);
    cester_assert_uint_eq(0x84800000, dicr);
)

CESTER_TEST(normal_dma_with_3_upper_bits, dma_tests,
    sendGPUStatus(0);
    sendGPUStatus(0x04000001);
    sendGPUData(0xe1000000);
    DPCR = 0x00000800;
    DICR = 0x00840000;
    IMASK = IRQ_VBLANK | IRQ_DMA;
    uint32_t cmd = 0xe1000555;
    sendGPUStatus(0x04000002);
    while ((GPU_STATUS & 0x10000000) == 0);
    DMA_CTRL[DMA_GPU].MADR = ((uintptr_t)&cmd) | 0xe0000000;
    DMA_CTRL[DMA_GPU].BCR = 0x00010001;
    DMA_CTRL[DMA_GPU].CHCR = 0x01000201;
    unsigned count = 0;
    unsigned timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 128) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    uint32_t stat = GPU_STATUS & 0x000007ff;
    uintptr_t bcr = DMA_CTRL[DMA_GPU].BCR;
    uint32_t madr = DMA_CTRL[DMA_GPU].MADR;
    uint32_t chcr = DMA_CTRL[DMA_GPU].CHCR;
    uint32_t dicr = DICR;
    const uintptr_t expectedAddr = ((uintptr_t)(&cmd + 1)) & 0xffffff;
    cester_assert_uint_eq(0, timeout);
    cester_assert_uint_eq(0, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0, s_from);
    cester_assert_uint_eq(0, s_epc);
    cester_assert_uint_eq(0x555, stat);
    cester_assert_uint_eq(1, bcr);
    cester_assert_uint_eq(expectedAddr, madr);
    cester_assert_uint_eq(0x00000201, chcr);
    cester_assert_uint_eq(0x84840000, dicr);
    DICR = (dicr & ~0x7f000000) | 0x04000000;
    dicr = DICR;
    cester_assert_uint_eq(0x00840000, dicr);
)

CESTER_TEST(normal_dma_with_8_upper_bits, dma_tests,
    sendGPUStatus(0);
    sendGPUStatus(0x04000001);
    sendGPUData(0xe1000000);
    DPCR = 0x00000800;
    DICR = 0x00840000;
    IMASK = IRQ_VBLANK | IRQ_DMA;
    uint32_t cmd = 0xe1000555;
    sendGPUStatus(0x04000002);
    while ((GPU_STATUS & 0x10000000) == 0);
    DMA_CTRL[DMA_GPU].MADR = ((uintptr_t)&cmd) | 0xff000000;
    DMA_CTRL[DMA_GPU].BCR = 0x00010001;
    DMA_CTRL[DMA_GPU].CHCR = 0x01000201;
    unsigned count = 0;
    unsigned timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 128) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    uint32_t stat = GPU_STATUS & 0x000007ff;
    uintptr_t bcr = DMA_CTRL[DMA_GPU].BCR;
    uint32_t madr = DMA_CTRL[DMA_GPU].MADR;
    uint32_t chcr = DMA_CTRL[DMA_GPU].CHCR;
    uint32_t dicr = DICR;
    const uintptr_t expectedAddr = ((uintptr_t)(&cmd + 1)) & 0xffffff;
    cester_assert_uint_eq(0, timeout);
    cester_assert_uint_eq(0, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0, s_from);
    cester_assert_uint_eq(0, s_epc);
    cester_assert_uint_eq(0x555, stat);
    cester_assert_uint_eq(1, bcr);
    cester_assert_uint_eq(expectedAddr, madr);
    cester_assert_uint_eq(0x00000201, chcr);
    cester_assert_uint_eq(0x84840000, dicr);
    DICR = (dicr & ~0x7f000000) | 0x04000000;
    dicr = DICR;
    cester_assert_uint_eq(0x00840000, dicr);
)

CESTER_TEST(normal_dma_odd_address, dma_tests,
    sendGPUStatus(0);
    sendGPUStatus(0x04000001);
    sendGPUData(0xe1000000);
    DPCR = 0x00000800;
    DICR = 0x00840000;
    IMASK = IRQ_VBLANK | IRQ_DMA;
    uint32_t cmd = 0xe1000555;
    sendGPUStatus(0x04000002);
    while ((GPU_STATUS & 0x10000000) == 0);
    DMA_CTRL[DMA_GPU].MADR = ((uintptr_t)&cmd) | 1;
    DMA_CTRL[DMA_GPU].BCR = 0x00010001;
    DMA_CTRL[DMA_GPU].CHCR = 0x01000201;
    unsigned count = 0;
    unsigned timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 128) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    uint32_t stat = GPU_STATUS & 0x000007ff;
    uintptr_t bcr = DMA_CTRL[DMA_GPU].BCR;
    uint32_t madr = DMA_CTRL[DMA_GPU].MADR;
    uint32_t chcr = DMA_CTRL[DMA_GPU].CHCR;
    uint32_t dicr = DICR;
    const uintptr_t expectedAddr = ((uintptr_t)(&cmd + 1)) & 0xffffff;
    cester_assert_uint_eq(0, timeout);
    cester_assert_uint_eq(0, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0, s_from);
    cester_assert_uint_eq(0, s_epc);
    cester_assert_uint_eq(0x555, stat);
    cester_assert_uint_eq(1, bcr);
    cester_assert_uint_eq(expectedAddr, madr);
    cester_assert_uint_eq(0x00000201, chcr);
    cester_assert_uint_eq(0x84840000, dicr);
    DICR = (dicr & ~0x7f000000) | 0x04000000;
    dicr = DICR;
    cester_assert_uint_eq(0x00840000, dicr);
)

CESTER_TEST(linked_dma_ffffff_terminator, dma_tests,
    sendGPUStatus(0);
    sendGPUStatus(0x04000001);
    sendGPUData(0xe1000000);
    DPCR = 0x00000800;
    DICR = 0x00840000;
    IMASK = IRQ_VBLANK | IRQ_DMA;
    uint32_t cmd[2] = { 0x01ffffff, 0xe1000555 };
    sendGPUStatus(0x04000002);
    while ((GPU_STATUS & 0x10000000) == 0);
    DMA_CTRL[DMA_GPU].MADR = (uintptr_t)&cmd;
    DMA_CTRL[DMA_GPU].BCR = 0x12345678;
    DMA_CTRL[DMA_GPU].CHCR = 0x01000401;
    unsigned count = 0;
    unsigned timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 128) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    uint32_t stat = GPU_STATUS & 0x000007ff;
    uintptr_t bcr = DMA_CTRL[DMA_GPU].BCR;
    uint32_t madr = DMA_CTRL[DMA_GPU].MADR;
    uint32_t chcr = DMA_CTRL[DMA_GPU].CHCR;
    uint32_t dicr = DICR;
    cester_assert_uint_eq(0, timeout);
    cester_assert_uint_eq(0, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0, s_from);
    cester_assert_uint_eq(0, s_epc);
    cester_assert_uint_eq(0x555, stat);
    cester_assert_uint_eq(0x12345678, bcr);
    cester_assert_uint_eq(0x00ffffff, madr);
    cester_assert_uint_eq(0x00000401, chcr);
    cester_assert_uint_eq(0x84840000, dicr);
    DICR = (dicr & ~0x7f000000) | 0x04000000;
    dicr = DICR;
    cester_assert_uint_eq(0x00840000, dicr);
)

CESTER_TEST(linked_dma_fffff0_terminator, dma_tests,
    sendGPUStatus(0);
    sendGPUStatus(0x04000001);
    sendGPUData(0xe1000000);
    DPCR = 0x00000800;
    DICR = 0x00840000;
    IMASK = IRQ_VBLANK | IRQ_DMA;
    uint32_t cmd[2] = { 0x01fffff0, 0xe1000555 };
    sendGPUStatus(0x04000002);
    while ((GPU_STATUS & 0x10000000) == 0);
    DMA_CTRL[DMA_GPU].MADR = (uintptr_t)&cmd;
    DMA_CTRL[DMA_GPU].BCR = 0x12345678;
    DMA_CTRL[DMA_GPU].CHCR = 0x01000401;
    unsigned count = 0;
    unsigned timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 128) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    uint32_t stat = GPU_STATUS & 0x000007ff;
    uintptr_t bcr = DMA_CTRL[DMA_GPU].BCR;
    uint32_t madr = DMA_CTRL[DMA_GPU].MADR;
    uint32_t chcr = DMA_CTRL[DMA_GPU].CHCR;
    uint32_t dicr = DICR;
    cester_assert_uint_eq(0, timeout);
    cester_assert_uint_eq(0, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0, s_from);
    cester_assert_uint_eq(0, s_epc);
    cester_assert_uint_eq(0x555, stat);
    cester_assert_uint_eq(0x12345678, bcr);
    cester_assert_uint_eq(0x00fffff0, madr);
    cester_assert_uint_eq(0x00000401, chcr);
    cester_assert_uint_eq(0x84848000, dicr);
    dicr &= 0xffffff;
    DICR = dicr | 0x04000000;
    dicr = DICR;
    cester_assert_uint_eq(0x80848000, dicr);
    dicr &= 0xff7fff;
    DICR = dicr;
    dicr = DICR;
    cester_assert_uint_eq(0x00840000, dicr);
)

CESTER_TEST(linked_dma_800000_terminator, dma_tests,
    sendGPUStatus(0);
    sendGPUStatus(0x04000001);
    sendGPUData(0xe1000000);
    DPCR = 0x00000800;
    DICR = 0x00840000;
    IMASK = IRQ_VBLANK | IRQ_DMA;
    uint32_t cmd[2] = { 0x01800000, 0xe1000555 };
    sendGPUStatus(0x04000002);
    while ((GPU_STATUS & 0x10000000) == 0);
    DMA_CTRL[DMA_GPU].MADR = (uintptr_t)&cmd;
    DMA_CTRL[DMA_GPU].BCR = 0x12345678;
    DMA_CTRL[DMA_GPU].CHCR = 0x01000401;
    unsigned count = 0;
    unsigned timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 128) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    uint32_t stat = GPU_STATUS & 0x000007ff;
    uintptr_t bcr = DMA_CTRL[DMA_GPU].BCR;
    uint32_t madr = DMA_CTRL[DMA_GPU].MADR;
    uint32_t chcr = DMA_CTRL[DMA_GPU].CHCR;
    uint32_t dicr = DICR;
    cester_assert_uint_eq(0, timeout);
    cester_assert_uint_eq(0, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0, s_from);
    cester_assert_uint_eq(0, s_epc);
    cester_assert_uint_eq(0x555, stat);
    cester_assert_uint_eq(0x12345678, bcr);
    cester_assert_uint_eq(0x00800000, madr);
    cester_assert_uint_eq(0x00000401, chcr);
    cester_assert_uint_eq(0x84848000, dicr);
    dicr &= 0xffffff;
    DICR = dicr | 0x04000000;
    dicr = DICR;
    cester_assert_uint_eq(0x80848000, dicr);
    dicr &= 0xff7fff;
    DICR = dicr;
    dicr = DICR;
    cester_assert_uint_eq(0x00840000, dicr);
)

CESTER_TEST(linked_dma_800000_terminator_dicr_toggle, dma_tests,
    sendGPUStatus(0);
    sendGPUStatus(0x04000001);
    sendGPUData(0xe1000000);
    DPCR = 0x00000800;
    DICR = 0x00840000;
    IMASK = IRQ_VBLANK | IRQ_DMA;
    uint32_t cmd[2] = { 0x01800000, 0xe1000555 };
    sendGPUStatus(0x04000002);
    while ((GPU_STATUS & 0x10000000) == 0);
    DMA_CTRL[DMA_GPU].MADR = (uintptr_t)&cmd;
    DMA_CTRL[DMA_GPU].BCR = 0x12345678;
    DMA_CTRL[DMA_GPU].CHCR = 0x01000401;
    unsigned count = 0;
    unsigned timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 128) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    uint32_t stat = GPU_STATUS & 0x000007ff;
    uintptr_t bcr = DMA_CTRL[DMA_GPU].BCR;
    uint32_t madr = DMA_CTRL[DMA_GPU].MADR;
    uint32_t chcr = DMA_CTRL[DMA_GPU].CHCR;
    uint32_t dicr = DICR;
    cester_assert_uint_eq(0, timeout);
    cester_assert_uint_eq(0, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0, s_from);
    cester_assert_uint_eq(0, s_epc);
    cester_assert_uint_eq(0x555, stat);
    cester_assert_uint_eq(0x12345678, bcr);
    cester_assert_uint_eq(0x00800000, madr);
    cester_assert_uint_eq(0x00000401, chcr);
    cester_assert_uint_eq(0x84848000, dicr);
    DICR = 0x00008000;
    dicr = DICR;
    cester_assert_uint_eq(0x84008000, dicr);
    DICR = 0x00000000;
    dicr = DICR;
    cester_assert_uint_eq(0x04000000, dicr);
)

CESTER_TEST(linked_dma_800001_terminator, dma_tests,
    sendGPUStatus(0);
    sendGPUStatus(0x04000001);
    sendGPUData(0xe1000000);
    DPCR = 0x00000800;
    DICR = 0x00840000;
    IMASK = IRQ_VBLANK | IRQ_DMA;
    uint32_t cmd[2] = { 0x01800001, 0xe1000555 };
    sendGPUStatus(0x04000002);
    while ((GPU_STATUS & 0x10000000) == 0);
    DMA_CTRL[DMA_GPU].MADR = (uintptr_t)&cmd;
    DMA_CTRL[DMA_GPU].BCR = 0x12345678;
    DMA_CTRL[DMA_GPU].CHCR = 0x01000401;
    unsigned count = 0;
    unsigned timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 128) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    uint32_t stat = GPU_STATUS & 0x000007ff;
    uintptr_t bcr = DMA_CTRL[DMA_GPU].BCR;
    uint32_t madr = DMA_CTRL[DMA_GPU].MADR;
    uint32_t chcr = DMA_CTRL[DMA_GPU].CHCR;
    uint32_t dicr = DICR;
    cester_assert_uint_eq(0, timeout);
    cester_assert_uint_eq(0, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0, s_from);
    cester_assert_uint_eq(0, s_epc);
    cester_assert_uint_eq(0x555, stat);
    cester_assert_uint_eq(0x12345678, bcr);
    cester_assert_uint_eq(0x00800001, madr);
    cester_assert_uint_eq(0x00000401, chcr);
    cester_assert_uint_eq(0x84848000, dicr);
    dicr &= 0xffffff;
    DICR = dicr | 0x04000000;
    dicr = DICR;
    cester_assert_uint_eq(0x80848000, dicr);
    dicr &= 0xff7fff;
    DICR = dicr;
    dicr = DICR;
    cester_assert_uint_eq(0x00840000, dicr);
)

CESTER_TEST(linked_dma_odd_terminator, dma_tests,
    sendGPUStatus(0);
    sendGPUStatus(0x04000001);
    sendGPUData(0xe1000000);
    DPCR = 0x00000800;
    DICR = 0x00840000;
    IMASK = IRQ_VBLANK | IRQ_DMA;
    uint32_t cmd[2] = { 0, 0xe1000555 };
    uint32_t terminator = 0x00ffffff;
    cmd[0] = (((uintptr_t)&terminator) & 0xffffff) | 0x01000001;
    sendGPUStatus(0x04000002);
    while ((GPU_STATUS & 0x10000000) == 0);
    DMA_CTRL[DMA_GPU].MADR = (uintptr_t)&cmd;
    DMA_CTRL[DMA_GPU].BCR = 0x12345678;
    DMA_CTRL[DMA_GPU].CHCR = 0x01000401;
    unsigned count = 0;
    unsigned timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 128) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    uint32_t stat = GPU_STATUS & 0x000007ff;
    uintptr_t bcr = DMA_CTRL[DMA_GPU].BCR;
    uint32_t madr = DMA_CTRL[DMA_GPU].MADR;
    uint32_t chcr = DMA_CTRL[DMA_GPU].CHCR;
    uint32_t dicr = DICR;
    cester_assert_uint_eq(0, timeout);
    cester_assert_uint_eq(0, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0, s_from);
    cester_assert_uint_eq(0, s_epc);
    cester_assert_uint_eq(0x555, stat);
    cester_assert_uint_eq(0x12345678, bcr);
    cester_assert_uint_eq(0x00ffffff, madr);
    cester_assert_uint_eq(0x00000401, chcr);
    cester_assert_uint_eq(0x84840000, dicr);
    dicr &= 0xffffff;
    DICR = dicr | 0x04000000;
    dicr = DICR;
    cester_assert_uint_eq(0x00840000, dicr);
)

CESTER_TEST(disabled_dma, dma_tests,
    sendGPUStatus(0);
    sendGPUStatus(0x04000001);
    sendGPUData(0xe1000000);
    DPCR = 0x00000000;
    DICR = 0x00840000;
    IMASK = IRQ_VBLANK | IRQ_DMA;
    uint32_t cmd = 0xe1000555;
    sendGPUStatus(0x04000002);
    while ((GPU_STATUS & 0x10000000) == 0);
    DMA_CTRL[DMA_GPU].MADR = (uintptr_t)&cmd;
    DMA_CTRL[DMA_GPU].BCR = 0x00010001;
    DMA_CTRL[DMA_GPU].CHCR = 0x01000201;
    unsigned count = 0;
    unsigned timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 32) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    uint32_t stat = GPU_STATUS & 0x000007ff;
    uintptr_t bcr = DMA_CTRL[DMA_GPU].BCR;
    uint32_t madr = DMA_CTRL[DMA_GPU].MADR;
    uint32_t chcr = DMA_CTRL[DMA_GPU].CHCR;
    uint32_t dicr = DICR;
    const uintptr_t expectedAddr = ((uintptr_t)&cmd) & 0xffffff;
    cester_assert_uint_eq(1, timeout);
    cester_assert_uint_eq(0, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0, s_from);
    cester_assert_uint_eq(0, s_epc);
    cester_assert_uint_eq(0, stat);
    cester_assert_uint_eq(0x00010001, bcr);
    cester_assert_uint_eq(expectedAddr, madr);
    cester_assert_uint_eq(0x01000201, chcr);
    cester_assert_uint_eq(0x00840000, dicr);
)

CESTER_TEST(disabled_dma_odd_address, dma_tests,
    sendGPUStatus(0);
    sendGPUStatus(0x04000001);
    sendGPUData(0xe1000000);
    DPCR = 0x00000000;
    DICR = 0x00840000;
    IMASK = IRQ_VBLANK | IRQ_DMA;
    uint32_t cmd = 0xe1000555;
    sendGPUStatus(0x04000002);
    while ((GPU_STATUS & 0x10000000) == 0);
    DMA_CTRL[DMA_GPU].MADR = ((uintptr_t)&cmd) | 3;
    DMA_CTRL[DMA_GPU].BCR = 0x00010001;
    DMA_CTRL[DMA_GPU].CHCR = 0x01000201;
    unsigned count = 0;
    unsigned timeout = 0;
    while (1) {
        while ((IREG & (IRQ_VBLANK | IRQ_DMA)) == 0);
        if (IREG & IRQ_DMA) break;
        IREG &= ~IRQ_VBLANK;
        if (count++ == 32) {
            timeout = 1;
            break;
        }
    }
    IREG = 0;
    uint32_t stat = GPU_STATUS & 0x000007ff;
    uintptr_t bcr = DMA_CTRL[DMA_GPU].BCR;
    uint32_t madr = DMA_CTRL[DMA_GPU].MADR;
    uint32_t chcr = DMA_CTRL[DMA_GPU].CHCR;
    uint32_t dicr = DICR;
    const uintptr_t expectedAddr = (((uintptr_t)&cmd) & 0xffffff) | 3;
    cester_assert_uint_eq(1, timeout);
    cester_assert_uint_eq(0, s_got40);
    cester_assert_uint_eq(0, s_got80);
    cester_assert_uint_eq(0, s_from);
    cester_assert_uint_eq(0, s_epc);
    cester_assert_uint_eq(0, stat);
    cester_assert_uint_eq(0x00010001, bcr);
    cester_assert_uint_eq(expectedAddr, madr);
    cester_assert_uint_eq(0x01000201, chcr);
    cester_assert_uint_eq(0x00840000, dicr);
)
