/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

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

// clang-format off

CESTER_TEST(cdlReadN1x, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    // Mode after reset is undefined technically,
    // but seems to be using raw mode. Let's make
    // sure it's a known value.
    int setModeDone = setMode(0);
    if (!setModeDone) {
        cester_assert_true(setModeDone);
        return;
    }

    int setLocDone = setLoc(0, 2, 0x16);
    if (!setLocDone) {
        cester_assert_true(setLocDone);
        return;
    }

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_READN;
    uint32_t ackTime1 = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    uint32_t readyTime = waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl3 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t ctrl4 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    initializeTime();
    uint8_t sector[2048];
    uint32_t size = 0;

    CDROM_REG0 = 0;
    CDROM_REG3 = 0x80;

    while ((CDROM_REG0 & 0x40) == 0);
    while (((CDROM_REG0 & 0x40) != 0) && (size < 6)) {
        sector[size++] = CDROM_REG2;
    }
    CDROM_REG3 = 0;
    uint32_t readTime = updateTime();

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PAUSE;
    uint32_t ackTime2 = waitCDRomIRQ();
    uint8_t cause3 = ackCDRomCause();
    uint8_t ctrl5 = CDROM_REG0 & ~3;
    uint8_t response3[16];
    uint8_t responseSize3 = readResponse(response3);
    uint8_t ctrl6 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause3b = CDROM_REG3_UC;

    uint32_t completeTime = waitCDRomIRQ();
    uint8_t cause4 = ackCDRomCause();
    uint8_t ctrl7 = CDROM_REG0 & ~3;
    uint8_t response4[16];
    uint8_t responseSize4 = readResponse(response4);
    uint8_t ctrl8 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause4b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(1, cause2);
    cester_assert_uint_eq(0xe0, cause2b);
    cester_assert_uint_eq(3, cause3);
    cester_assert_uint_eq(0xe0, cause3b);
    cester_assert_uint_eq(2, cause4);
    cester_assert_uint_eq(0xe0, cause4b);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_eq(0x38, ctrl3);
    cester_assert_uint_eq(0x18, ctrl4);
    cester_assert_uint_eq(0x38, ctrl5);
    cester_assert_uint_eq(0x18, ctrl6);
    cester_assert_uint_eq(0x38, ctrl7);
    cester_assert_uint_eq(0x18, ctrl8);
    cester_assert_uint_eq(2, response1[0]);
    cester_assert_uint_eq(1, responseSize1);
    cester_assert_uint_eq(0x22, response2[0]);
    cester_assert_uint_eq(1, responseSize2);
    cester_assert_uint_eq(0x22, response3[0]);
    cester_assert_uint_eq(1, responseSize4);
    cester_assert_uint_eq(2, response4[0]);
    cester_assert_uint_eq(1, responseSize4);
    cester_assert_uint_ge(ackTime1, 500);
    cester_assert_uint_lt(ackTime1, 7000);
    cester_assert_uint_ge(ackTime2, 500);
    cester_assert_uint_lt(ackTime2, 7000);
    // Pausing at 1x is ~70ms
    cester_assert_uint_ge(completeTime, 65000);
    cester_assert_uint_eq(1, sector[0]);
    cester_assert_uint_eq('C', sector[1]);
    cester_assert_uint_eq('D', sector[2]);
    cester_assert_uint_eq('0', sector[3]);
    cester_assert_uint_eq('0', sector[4]);
    cester_assert_uint_eq('1', sector[5]);
    cester_assert_uint_eq(6, size);
    ramsyscall_printf("Basic single 6 bytes readN @1x at 00:02:16, ack1 in %ius, ready in %ius, read in %ius, ack2 in %ius, complete in %ius\n", ackTime1, readyTime, readTime, ackTime2, completeTime);
)

CESTER_TEST(cdlReadN1xwithDMA, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    // Mode after reset is undefined technically,
    // but seems to be using raw mode. Let's make
    // sure it's a known value.
    int setModeDone = setMode(0);
    if (!setModeDone) {
        cester_assert_true(setModeDone);
        return;
    }

    int setLocDone = setLoc(0, 2, 0x16);
    if (!setLocDone) {
        cester_assert_true(setLocDone);
        return;
    }

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_READN;
    uint32_t ackTime1 = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    uint32_t readyTime = waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl3 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t ctrl4 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    initializeTime();
    uint8_t sector[2048];

    CDROM_REG0 = 0;
    CDROM_REG3 = 0x80;

    uint32_t dicr = DICR;
    dicr &= 0x00ffffff;
    dicr |= 0x00880000;
    DICR = dicr;
    DPCR |= 0x8000;
    DMA_CTRL[DMA_CDROM].MADR = (uintptr_t)sector;
    DMA_CTRL[DMA_CDROM].BCR = (2048 >> 2) | 0x10000;
    DMA_CTRL[DMA_CDROM].CHCR = 0x11000000;

    while ((DMA_CTRL[DMA_CDROM].CHCR & 0x01000000) != 0);
    dicr = DICR;
    dicr &= 0x00ffffff;
    dicr |= 0x88000000;
    DICR = dicr;
    CDROM_REG3 = 0;
    uint32_t readTime = updateTime();

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PAUSE;
    uint32_t ackTime2 = waitCDRomIRQ();
    uint8_t cause3 = ackCDRomCause();
    uint8_t ctrl5 = CDROM_REG0 & ~3;
    uint8_t response3[16];
    uint8_t responseSize3 = readResponse(response3);
    uint8_t ctrl6 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause3b = CDROM_REG3_UC;

    uint32_t completeTime = waitCDRomIRQ();
    uint8_t cause4 = ackCDRomCause();
    uint8_t ctrl7 = CDROM_REG0 & ~3;
    uint8_t response4[16];
    uint8_t responseSize4 = readResponse(response4);
    uint8_t ctrl8 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause4b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(1, cause2);
    cester_assert_uint_eq(0xe0, cause2b);
    cester_assert_uint_eq(3, cause3);
    cester_assert_uint_eq(0xe0, cause3b);
    cester_assert_uint_eq(2, cause4);
    cester_assert_uint_eq(0xe0, cause4b);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_eq(0x38, ctrl3);
    cester_assert_uint_eq(0x18, ctrl4);
    cester_assert_uint_eq(0x38, ctrl5);
    cester_assert_uint_eq(0x18, ctrl6);
    cester_assert_uint_eq(0x38, ctrl7);
    cester_assert_uint_eq(0x18, ctrl8);
    cester_assert_uint_eq(2, response1[0]);
    cester_assert_uint_eq(1, responseSize1);
    cester_assert_uint_eq(0x22, response2[0]);
    cester_assert_uint_eq(1, responseSize2);
    cester_assert_uint_eq(0x22, response3[0]);
    cester_assert_uint_eq(1, responseSize4);
    cester_assert_uint_eq(2, response4[0]);
    cester_assert_uint_eq(1, responseSize4);
    cester_assert_uint_ge(ackTime1, 500);
    cester_assert_uint_lt(ackTime1, 7000);
    cester_assert_uint_ge(ackTime2, 500);
    cester_assert_uint_lt(ackTime2, 7000);
    // Pausing at 1x is ~70ms
    cester_assert_uint_ge(completeTime, 65000);
    cester_assert_uint_eq(1, sector[0]);
    cester_assert_uint_eq('C', sector[1]);
    cester_assert_uint_eq('D', sector[2]);
    cester_assert_uint_eq('0', sector[3]);
    cester_assert_uint_eq('0', sector[4]);
    cester_assert_uint_eq('1', sector[5]);
    ramsyscall_printf("Basic single full sector readN @1x with DMA at 00:02:16, ack1 in %ius, ready in %ius, read in %ius, ack2 in %ius, complete in %ius\n", ackTime1, readyTime, readTime, ackTime2, completeTime);
)

CESTER_TEST(cdlReadN2x, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    // Mode after reset is undefined technically,
    // but seems to be using raw mode. Let's make
    // sure it's a known value.
    int setModeDone = setMode(0x80);
    if (!setModeDone) {
        cester_assert_true(setModeDone);
        return;
    }

    int setLocDone = setLoc(0, 2, 0x16);
    if (!setLocDone) {
        cester_assert_true(setLocDone);
        return;
    }

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_READN;
    uint32_t ackTime1 = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    uint32_t readyTime = waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl3 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t ctrl4 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    initializeTime();
    uint8_t sector[2048];
    uint32_t size = 0;

    CDROM_REG0 = 0;
    CDROM_REG3 = 0x80;

    while ((CDROM_REG0 & 0x40) == 0);
    while (((CDROM_REG0 & 0x40) != 0) && (size < 6)) {
        sector[size++] = CDROM_REG2;
    }
    CDROM_REG3 = 0;
    uint32_t readTime = updateTime();

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PAUSE;
    uint32_t ackTime2 = waitCDRomIRQ();
    uint8_t cause3 = ackCDRomCause();
    uint8_t ctrl5 = CDROM_REG0 & ~3;
    uint8_t response3[16];
    uint8_t responseSize3 = readResponse(response3);
    uint8_t ctrl6 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause3b = CDROM_REG3_UC;

    uint32_t completeTime = waitCDRomIRQ();
    uint8_t cause4 = ackCDRomCause();
    uint8_t ctrl7 = CDROM_REG0 & ~3;
    uint8_t response4[16];
    uint8_t responseSize4 = readResponse(response4);
    uint8_t ctrl8 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause4b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(1, cause2);
    cester_assert_uint_eq(0xe0, cause2b);
    cester_assert_uint_eq(3, cause3);
    cester_assert_uint_eq(0xe0, cause3b);
    cester_assert_uint_eq(2, cause4);
    cester_assert_uint_eq(0xe0, cause4b);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_eq(0x38, ctrl3);
    cester_assert_uint_eq(0x18, ctrl4);
    cester_assert_uint_eq(0x38, ctrl5);
    cester_assert_uint_eq(0x18, ctrl6);
    cester_assert_uint_eq(0x38, ctrl7);
    cester_assert_uint_eq(0x18, ctrl8);
    cester_assert_uint_eq(2, response1[0]);
    cester_assert_uint_eq(1, responseSize1);
    cester_assert_uint_eq(0x22, response2[0]);
    cester_assert_uint_eq(1, responseSize2);
    cester_assert_uint_eq(0x22, response3[0]);
    cester_assert_uint_eq(1, responseSize4);
    cester_assert_uint_eq(2, response4[0]);
    cester_assert_uint_eq(1, responseSize4);
    cester_assert_uint_ge(ackTime1, 500);
    cester_assert_uint_lt(ackTime1, 7000);
    cester_assert_uint_ge(ackTime2, 500);
    cester_assert_uint_lt(ackTime2, 7000);
    // Switching speed is roughly 650ms for the speed up,
    // and then this also contains the seeking time.
    cester_assert_uint_ge(readyTime, 500000);
    // Pausing at 2x is ~35ms
    cester_assert_uint_ge(completeTime, 32500);
    cester_assert_uint_eq(1, sector[0]);
    cester_assert_uint_eq('C', sector[1]);
    cester_assert_uint_eq('D', sector[2]);
    cester_assert_uint_eq('0', sector[3]);
    cester_assert_uint_eq('0', sector[4]);
    cester_assert_uint_eq('1', sector[5]);
    cester_assert_uint_eq(6, size);
    ramsyscall_printf("Basic single 6 bytes readN @2x at 00:02:16, ack1 in %ius, ready in %ius, read in %ius, ack2 in %ius, complete in %ius\n", ackTime1, readyTime, readTime, ackTime2, completeTime);
)

CESTER_TEST(cdlReadN2xwithDMA, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    // Mode after reset is undefined technically,
    // but seems to be using raw mode. Let's make
    // sure it's a known value.
    int setModeDone = setMode(0x80);
    if (!setModeDone) {
        cester_assert_true(setModeDone);
        return;
    }

    int setLocDone = setLoc(0, 2, 0x16);
    if (!setLocDone) {
        cester_assert_true(setLocDone);
        return;
    }

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_READN;
    uint32_t ackTime1 = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    uint32_t readyTime = waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl3 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t ctrl4 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    initializeTime();
    uint8_t sector[2048];

    CDROM_REG0 = 0;
    CDROM_REG3 = 0x80;

    uint32_t dicr = DICR;
    dicr &= 0x00ffffff;
    dicr |= 0x00880000;
    DICR = dicr;
    DPCR |= 0x8000;
    DMA_CTRL[DMA_CDROM].MADR = (uintptr_t)sector;
    DMA_CTRL[DMA_CDROM].BCR = (2048 >> 2) | 0x10000;
    DMA_CTRL[DMA_CDROM].CHCR = 0x11000000;

    while ((DMA_CTRL[DMA_CDROM].CHCR & 0x01000000) != 0);
    dicr = DICR;
    dicr &= 0x00ffffff;
    dicr |= 0x88000000;
    DICR = dicr;
    CDROM_REG3 = 0;
    uint32_t readTime = updateTime();

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PAUSE;
    uint32_t ackTime2 = waitCDRomIRQ();
    uint8_t cause3 = ackCDRomCause();
    uint8_t ctrl5 = CDROM_REG0 & ~3;
    uint8_t response3[16];
    uint8_t responseSize3 = readResponse(response3);
    uint8_t ctrl6 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause3b = CDROM_REG3_UC;

    uint32_t completeTime = waitCDRomIRQ();
    uint8_t cause4 = ackCDRomCause();
    uint8_t ctrl7 = CDROM_REG0 & ~3;
    uint8_t response4[16];
    uint8_t responseSize4 = readResponse(response4);
    uint8_t ctrl8 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause4b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(1, cause2);
    cester_assert_uint_eq(0xe0, cause2b);
    cester_assert_uint_eq(3, cause3);
    cester_assert_uint_eq(0xe0, cause3b);
    cester_assert_uint_eq(2, cause4);
    cester_assert_uint_eq(0xe0, cause4b);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_eq(0x38, ctrl3);
    cester_assert_uint_eq(0x18, ctrl4);
    cester_assert_uint_eq(0x38, ctrl5);
    cester_assert_uint_eq(0x18, ctrl6);
    cester_assert_uint_eq(0x38, ctrl7);
    cester_assert_uint_eq(0x18, ctrl8);
    cester_assert_uint_eq(2, response1[0]);
    cester_assert_uint_eq(1, responseSize1);
    cester_assert_uint_eq(0x22, response2[0]);
    cester_assert_uint_eq(1, responseSize2);
    cester_assert_uint_eq(0x22, response3[0]);
    cester_assert_uint_eq(1, responseSize4);
    cester_assert_uint_eq(2, response4[0]);
    cester_assert_uint_eq(1, responseSize4);
    cester_assert_uint_ge(ackTime1, 500);
    cester_assert_uint_lt(ackTime1, 7000);
    cester_assert_uint_ge(ackTime2, 500);
    cester_assert_uint_lt(ackTime2, 7000);
    // Switching speed is roughly 650ms for the speed up,
    // and then this also contains the seeking time.
    cester_assert_uint_ge(readyTime, 500000);
    // Pausing at 2x is ~35ms
    cester_assert_uint_ge(completeTime, 32500);
    cester_assert_uint_eq(1, sector[0]);
    cester_assert_uint_eq('C', sector[1]);
    cester_assert_uint_eq('D', sector[2]);
    cester_assert_uint_eq('0', sector[3]);
    cester_assert_uint_eq('0', sector[4]);
    cester_assert_uint_eq('1', sector[5]);
    ramsyscall_printf("Basic single full sector readN @2x with DMA at 00:02:16, ack1 in %ius, ready in %ius, read in %ius, ack2 in %ius, complete in %ius\n", ackTime1, readyTime, readTime, ackTime2, completeTime);
)
