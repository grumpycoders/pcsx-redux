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

CESTER_SKIP_TEST(cdlSeekP, test_instance,
    uint32_t imask = IMASK;

    IMASK = imask | IRQ_CDROM;

    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int setlocDone = setLoc(0, 2, 0);

    initializeTime();
    // wait 10ms for things to settle
    while (updateTime() < 10000);
    initializeTime();

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_SEEKP;

    uint32_t ackTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t stat1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t stat2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    uint32_t completeTime = waitCDRomIRQ() - ackTime;
    uint8_t cause2 = ackCDRomCause();
    uint8_t stat3 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t stat4 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(2, cause2);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0xe0, cause2b);
    cester_assert_uint_eq(2, response1[0]);
    cester_assert_uint_eq(1, responseSize1);
    cester_assert_uint_eq(2, response2[0]);
    cester_assert_uint_eq(1, responseSize2);
    cester_assert_uint_eq(0x38, stat1);
    cester_assert_uint_eq(0x18, stat2);
    cester_assert_uint_eq(0x38, stat3);
    cester_assert_uint_eq(0x18, stat4);
    // Typical value seems to be around 750us.
    cester_assert_uint_ge(ackTime, 500);
    cester_assert_uint_lt(ackTime, 1500);
    // Typical value seems to be around 105ms. Of course, this is
    // with a proper laser assy.
    cester_assert_uint_ge(completeTime, 100000);
    cester_assert_uint_lt(completeTime, 110000);
    ramsyscall_printf("Basic seekP to 00:02:00: ack in %ius, complete in %ius\n", ackTime, completeTime);

    IMASK = imask;
)

CESTER_SKIP_TEST(cdlSeekL, test_instance,
    uint32_t imask = IMASK;

    IMASK = imask | IRQ_CDROM;

    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int setlocDone = setLoc(0, 2, 0);

    initializeTime();
    // wait 10ms for things to settle
    while (updateTime() < 10000);
    initializeTime();

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_SEEKL;

    uint32_t ackTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t stat1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t stat2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    uint32_t completeTime = waitCDRomIRQ() - ackTime;
    uint8_t cause2 = ackCDRomCause();
    uint8_t stat3 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t stat4 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(2, cause2);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0xe0, cause2b);
    cester_assert_uint_eq(2, response1[0]);
    cester_assert_uint_eq(1, responseSize1);
    cester_assert_uint_eq(2, response2[0]);
    cester_assert_uint_eq(1, responseSize2);
    cester_assert_uint_eq(0x38, stat1);
    cester_assert_uint_eq(0x18, stat2);
    cester_assert_uint_eq(0x38, stat3);
    cester_assert_uint_eq(0x18, stat4);
    // Typical value seems to be around 750us.
    cester_assert_uint_ge(ackTime, 500);
    cester_assert_uint_lt(ackTime, 2000);
    // Typical value seems to be around 145ms. Of course, this is
    // with a proper laser assy.
    cester_assert_uint_ge(completeTime, 140000);
    cester_assert_uint_lt(completeTime, 150000);
    ramsyscall_printf("Basic seekL to 00:02:00: ack in %ius, complete in %ius\n", ackTime, completeTime);

    IMASK = imask;
)
