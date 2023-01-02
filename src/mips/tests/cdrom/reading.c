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

CESTER_TEST(simpleReading, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int setModeDone = setMode(0x80);
    if (!setModeDone) {
        cester_assert_true(setModeDone);
        return;
    }

    int setLocDone = setLoc(0x20, 2, 0);

    if (!setLocDone) {
        cester_assert_true(setLocDone);
        return;
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_READN;
    uint8_t response[16];
    waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    readResponse(response);

    uint32_t sectorData[100];
    uint8_t causes[100];

    __builtin_memset(sectorData, 0, sizeof(sectorData));
    __builtin_memset(causes, 0, sizeof(causes));

    for (unsigned i = 0; i < 100; i++) {
        waitCDRomIRQ();
        uint8_t cause = ackCDRomCause();
        causes[i] = cause;
        readResponse(response);
        if (cause != 1) break;

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

        uint32_t *sector32 = (uint32_t *)sector;
        sectorData[i] = sector32[0];
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PAUSE;
    waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    readResponse(response);
    waitCDRomIRQ();
    uint8_t cause3 = ackCDRomCause();
    readResponse(response);

    uint32_t start = 20 * 60 * 75;
    for (unsigned i = 0; i < 100; i++) {
        cester_assert_uint_eq(start + i, sectorData[i]);
        cester_assert_uint_eq(1, causes[i]);
    }
    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(3, cause2);
    cester_assert_uint_eq(2, cause3);
)

CESTER_TEST(setLocDuringSimpleReading, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int setModeDone = setMode(0x80);
    if (!setModeDone) {
        cester_assert_true(setModeDone);
        return;
    }

    int setLocDone = setLoc(0x20, 2, 0);

    if (!setLocDone) {
        cester_assert_true(setLocDone);
        return;
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_READN;
    uint8_t response[16];
    waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    readResponse(response);

    uint32_t sectorData[100];
    uint8_t causes[100];

    __builtin_memset(sectorData, 0, sizeof(sectorData));
    __builtin_memset(causes, 0, sizeof(causes));

    for (unsigned i = 0; i < 100; i++) {
        waitCDRomIRQ();
        uint8_t cause = ackCDRomCause();
        causes[i] = cause;
        readResponse(response);
        if (cause != 1) break;

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

        uint32_t *sector32 = (uint32_t *)sector;
        sectorData[i] = sector32[0];

        if (i == 50) setLocDone = setLoc(0x20, 2, 0);
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PAUSE;
    waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    readResponse(response);
    waitCDRomIRQ();
    uint8_t cause3 = ackCDRomCause();
    readResponse(response);

    uint32_t start = 20 * 60 * 75;
    for (unsigned i = 0; i < 100; i++) {
        cester_assert_uint_eq(start + i, sectorData[i]);
        cester_assert_uint_eq(1, causes[i]);
    }
    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(3, cause2);
    cester_assert_uint_eq(2, cause3);
    cester_assert_true(setLocDone);
)

CESTER_TEST(simpleReadingWithoutAck, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int setModeDone = setMode(0x80);
    if (!setModeDone) {
        cester_assert_true(setModeDone);
        return;
    }

    int setLocDone = setLoc(0x20, 0, 0);
    if (!setLocDone) {
        cester_assert_true(setLocDone);
        return;
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_READN;
    waitCDRomIRQ();
    ackCDRomCause();

    initializeTime();
    while (updateTime() <= 500000);

    initializeTime();
    uint32_t time1 = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    initializeTime();
    uint32_t time2 = waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl3 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t ctrl4 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PAUSE;

    initializeTime();
    uint32_t time3 = waitCDRomIRQ();
    uint8_t cause3 = ackCDRomCause();
    uint8_t ctrl5 = CDROM_REG0 & ~3;
    uint8_t response3[16];
    uint8_t responseSize3 = readResponse(response3);
    uint8_t ctrl6 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause3b = CDROM_REG3_UC;

    initializeTime();
    uint32_t time4 = waitCDRomIRQ();
    uint8_t cause4 = ackCDRomCause();
    uint8_t ctrl7 = CDROM_REG0 & ~3;
    uint8_t response4[16];
    uint8_t responseSize4 = readResponse(response4);
    uint8_t ctrl8 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause4b = CDROM_REG3_UC;

    cester_assert_uint_eq(1, cause1);
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
    cester_assert_uint_eq(0x22, response1[0]);
    cester_assert_uint_eq(1, responseSize1);
    cester_assert_uint_eq(0x22, response2[0]);
    cester_assert_uint_eq(1, responseSize2);
    cester_assert_uint_eq(0x22, response3[0]);
    cester_assert_uint_eq(1, responseSize3);
    cester_assert_uint_eq(2, response4[0]);
    cester_assert_uint_eq(1, responseSize4);
    ramsyscall_printf("Long read, ack then pause, ready1 in %ius, ready2 in %ius, ack in %ius, complete in %ius\n", time1, time2, time3, time3);
)

CESTER_TEST(simpleReadingPauseWithoutAck, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int setModeDone = setMode(0x80);
    if (!setModeDone) {
        cester_assert_true(setModeDone);
        return;
    }

    int setLocDone = setLoc(0x20, 0, 0);
    if (!setLocDone) {
        cester_assert_true(setLocDone);
        return;
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_READN;
    waitCDRomIRQ();
    ackCDRomCause();

    initializeTime();
    while (updateTime() <= 500000);

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PAUSE;

    initializeTime();
    uint32_t time1 = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    initializeTime();
    uint32_t time2 = waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl3 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t ctrl4 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PAUSE;

    initializeTime();
    uint32_t time3 = waitCDRomIRQ();
    uint8_t cause3 = ackCDRomCause();
    uint8_t ctrl5 = CDROM_REG0 & ~3;
    uint8_t response3[16];
    uint8_t responseSize3 = readResponse(response3);
    uint8_t ctrl6 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause3b = CDROM_REG3_UC;

    initializeTime();
    uint32_t time4 = waitCDRomIRQ();
    uint8_t cause4 = ackCDRomCause();
    uint8_t ctrl7 = CDROM_REG0 & ~3;
    uint8_t response4[16];
    uint8_t responseSize4 = readResponse(response4);
    uint8_t ctrl8 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause4b = CDROM_REG3_UC;

    cester_assert_uint_eq(5, cause1);
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
    // This bit will jitter
    uint8_t response1_0 = response1[0] & ~0x40;
    cester_assert_uint_eq(3, response1_0);
    cester_assert_uint_eq(0x80, response1[1]);
    cester_assert_uint_eq(2, responseSize1);
    cester_assert_uint_eq(0x23, response2[0]);
    cester_assert_uint_eq(1, responseSize2);
    cester_assert_uint_eq(0x22, response3[0]);
    cester_assert_uint_eq(1, responseSize3);
    cester_assert_uint_eq(2, response4[0]);
    cester_assert_uint_eq(1, responseSize4);
    ramsyscall_printf("Long read, pause then ack, error in %ius, ready in %ius, ack in %ius, complete in %ius\n", time1, time2, time3, time3);
)

CESTER_TEST(simpleReadingNopQuery, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int setModeDone = setMode(0x80);
    if (!setModeDone) {
        cester_assert_true(setModeDone);
        return;
    }

    int setLocDone = setLoc(0x20, 0, 0);
    if (!setLocDone) {
        cester_assert_true(setLocDone);
        return;
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_READN;
    waitCDRomIRQ();
    ackCDRomCause();

    initializeTime();

    for (unsigned i = 0; i < 100; i++) {
        CDROM_REG0 = 0;
        CDROM_REG1 = CDL_NOP;
        waitCDRomIRQ();
        ackCDRomCause();
        uint8_t response[16];
        readResponse(response);
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_NOP;

    initializeTime();
    uint32_t time1 = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    initializeTime();
    uint32_t time2 = waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl3 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t ctrl4 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PAUSE;

    initializeTime();
    uint32_t time3 = waitCDRomIRQ();
    uint8_t cause3 = ackCDRomCause();
    uint8_t ctrl5 = CDROM_REG0 & ~3;
    uint8_t response3[16];
    uint8_t responseSize3 = readResponse(response3);
    uint8_t ctrl6 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause3b = CDROM_REG3_UC;

    initializeTime();
    uint32_t time4 = waitCDRomIRQ();
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
    cester_assert_uint_eq(1, responseSize3);
    cester_assert_uint_eq(2, response4[0]);
    cester_assert_uint_eq(1, responseSize4);
    ramsyscall_printf("Long read, nop then pause, ack in %ius, ready in %ius, ack in %ius, complete in %ius\n", time1, time2, time3, time3);
)
