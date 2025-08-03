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

    int seekDone = seekLTo(0x20, 2, 0);

    if (!seekDone) {
        cester_assert_true(seekDone);
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

    int seekDone = seekLTo(0x20, 2, 0);
    int setLocDone = 0;

    if (!seekDone) {
        cester_assert_true(seekDone);
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
    cester_assert_true(seekDone);
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

    int seekDone = seekLTo(0x20, 0, 0);
    if (!seekDone) {
        cester_assert_true(seekDone);
        return;
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_READN;
    waitCDRomIRQ();
    ackCDRomCause();
    uint8_t response[16];
    readResponse(response);

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
    ramsyscall_printf("Long read, ack then pause, ready1 in %ius, ready2 in %ius, ack in %ius, complete in %ius\n", time1, time2, time3, time4);
)

CESTER_TEST(simpleReadingWithoutAckNorResponseReadThenInit, test_instances,
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

    int seekDone = seekLTo(0x20, 0, 0);
    if (!seekDone) {
        cester_assert_true(seekDone);
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
    CDROM_REG1 = CDL_INIT;

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
    ramsyscall_printf("Long read, no response read, ack then init, ready1 in %ius, ready2 in %ius, ack in %ius, complete in %ius\n", time1, time2, time3, time4);
)

CESTER_TEST(simpleReadingWithoutAckThenInit, test_instances,
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

    int seekDone = seekLTo(0x20, 0, 0);
    if (!seekDone) {
        cester_assert_true(seekDone);
        return;
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_READN;
    waitCDRomIRQ();
    ackCDRomCause();
    uint8_t response[16];
    readResponse(response);

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
    CDROM_REG1 = CDL_INIT;

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
    ramsyscall_printf("Long read, ack then init, ready1 in %ius, ready2 in %ius, ack in %ius, complete in %ius\n", time1, time2, time3, time4);
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

    int seekDone = seekLTo(0x20, 0, 0);
    if (!seekDone) {
        cester_assert_true(seekDone);
        return;
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_READN;
    waitCDRomIRQ();
    ackCDRomCause();
    uint8_t response[16];
    readResponse(response);

    initializeTime();
    while (updateTime() <= 500000);

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PAUSE;

    unsigned readyCount = 0;
    uint32_t time1;
    uint8_t cause1;
    uint8_t ctrl1, ctrl2;
    uint8_t response1[16];
    uint8_t responseSize1;
    while (1) {
        initializeTime();
        time1 = waitCDRomIRQ();
        cause1 = ackCDRomCause();
        ctrl1 = CDROM_REG0 & ~3;
        responseSize1 = readResponse(response1);
        ctrl2 = CDROM_REG0 & ~3;
        if (cause1 == 1) {
            readyCount++;
        } else {
            break;
        }
    }

    initializeTime();
    uint32_t time2 = waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl3 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t ctrl4 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(2, cause2);
    cester_assert_uint_eq(0xe0, cause2b);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_eq(0x38, ctrl3);
    cester_assert_uint_eq(0x18, ctrl4);
    cester_assert_uint_eq(0x22, response1[0]);
    cester_assert_uint_eq(1, responseSize1);
    cester_assert_uint_eq(2, response2[0]);
    cester_assert_uint_eq(1, responseSize2);
    cester_assert_uint_ge(readyCount, 1);
    cester_assert_uint_le(readyCount, 2);
    ramsyscall_printf("Long read, pause then ack, ack in %ius, complete in %ius\n", time1, time2);
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

    int seekDone = seekLTo(0x20, 0, 0);
    if (!seekDone) {
        cester_assert_true(seekDone);
        return;
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_READN;
    waitCDRomIRQ();
    ackCDRomCause();
    uint8_t response[16];
    readResponse(response);

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
    cester_assert_uint_eq(0x02, response1[0]);
    cester_assert_uint_eq(1, responseSize1);
    cester_assert_uint_eq(0x22, response2[0]);
    cester_assert_uint_eq(1, responseSize2);
    cester_assert_uint_eq(0x22, response3[0]);
    cester_assert_uint_eq(1, responseSize3);
    cester_assert_uint_eq(2, response4[0]);
    cester_assert_uint_eq(1, responseSize4);
    ramsyscall_printf("Long read, nop then pause, ack in %ius, ready in %ius, ack in %ius, complete in %ius\n", time1, time2, time3, time4);
)

CESTER_TEST(simpleReadingNopSeriesQuery, test_instances,
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

    int seekDone = seekLTo(0x20, 0, 0);
    if (!seekDone) {
        cester_assert_true(seekDone);
        return;
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_READN;
    waitCDRomIRQ();
    ackCDRomCause();
    uint8_t response[16];
    readResponse(response);

    initializeTime();

    unsigned countToRead = 0;
    unsigned gotInt1 = 0;

    do {
        CDROM_REG0 = 0;
        CDROM_REG1 = CDL_NOP;
        uint8_t cause = 0;
        do {
            waitCDRomIRQ();
            cause = ackCDRomCause();
            readResponse(response);
            if (cause == 1) {
                gotInt1 = 1;
            }
        } while (cause == 1);
        countToRead++;
    } while (!gotInt1);

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

    cester_assert_uint_lt(countToRead, 80);
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
    cester_assert_uint_eq(0x22, response1[0]);
    cester_assert_uint_eq(1, responseSize1);
    cester_assert_uint_eq(0x22, response2[0]);
    cester_assert_uint_eq(1, responseSize2);
    cester_assert_uint_eq(0x22, response3[0]);
    cester_assert_uint_eq(1, responseSize3);
    cester_assert_uint_eq(0x02, response4[0]);
    cester_assert_uint_eq(1, responseSize4);
    ramsyscall_printf("Long read, nop series of %i then pause, ack in %ius, ready in %ius, ack in %ius, complete in %ius\n", countToRead, time1, time2, time3, time4);
)

CESTER_TEST(simpleReadingNoSeekNopQueries, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int setLocDone = setLoc(0x60, 0x02, 0x00);
    if (!setLocDone) {
        cester_assert_true(setLocDone);
        return;
    }

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_READN;
    uint32_t time1 = waitCDRomIRQ();
    ackCDRomCause();
    uint8_t response[16];
    readResponse(response);

    uint8_t runningCause;
    uint8_t responses[32];
    uint32_t times[32];
    int32_t lastResponse = -1;
    unsigned responseCount = 0;

    do {
        CDROM_REG0 = 0;
        CDROM_REG1 = CDL_NOP;
        uint32_t time = waitCDRomIRQ();
        runningCause = ackCDRomCause();
        uint8_t runningResponse[16];
        readResponse(runningResponse);
        uint8_t r = runningResponse[0];
        if (r != lastResponse) {
            responses[responseCount] = lastResponse = r;
            times[responseCount] = time;
            responseCount++;
        }
    } while(runningCause == 3);

    uint32_t time2 = waitCDRomIRQ();
    uint8_t cause = ackCDRomCause();
    uint8_t response2[16];
    readResponse(response2);

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PAUSE;

    uint32_t time3 = waitCDRomIRQ();
    ackCDRomCause();
    uint8_t response3[16];
    readResponse(response3);

    uint32_t time4 = waitCDRomIRQ();
    ackCDRomCause();
    uint8_t response4[16];
    readResponse(response4);

    uint32_t dtime1 = times[0];
    uint32_t dtime2 = times[1] - times[0];
    uint32_t dtime3 = times[2] - times[1];

    cester_assert_uint_eq(3, cause);
    cester_assert_uint_eq(3, responseCount);
    cester_assert_uint_eq(0x02, responses[0]);
    cester_assert_uint_eq(0x42, responses[1]);
    cester_assert_uint_eq(0x22, responses[2]);
    cester_assert_uint_ge(dtime1, 1500);
    cester_assert_uint_le(dtime1, 4000);
    cester_assert_uint_ge(dtime2, 15000);
    cester_assert_uint_le(dtime2, 50000);
    cester_assert_uint_ge(dtime3, 700000);
    cester_assert_uint_le(dtime3, 2000000);
    ramsyscall_printf("Reading without seeking first, different nop count = %i, response1 = 0x%02x, dtime1 = %ius, response2 = 0x%02x, dtime2 = %ius, response3 = 0x%02x, dtime3 = %ius, time1 = %ius, time2 = %ius, time3 = %ius, time4 = %ius\n", responseCount, responses[0], dtime1, responses[1], dtime2, responses[2], dtime3, time1, time2, time3, time4);
)
