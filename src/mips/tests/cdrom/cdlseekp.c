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

CESTER_TEST(cdlSeekP, test_instance,
    uint32_t imask = IMASK;

    IMASK = imask | IRQ_CDROM;

    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int setLocDone = setLoc(0, 2, 0);
    if (!setLocDone) {
        cester_assert_true(setLocDone);
        return;
    }

    initializeTime();
    // wait 50ms for things to settle
    while (updateTime() < 50000);
    initializeTime();

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_SEEKP;

    uint32_t ackTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    uint32_t completeTime = waitCDRomIRQ() - ackTime;
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl3 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t ctrl4 = CDROM_REG0 & ~3;
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
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_eq(0x38, ctrl3);
    cester_assert_uint_eq(0x18, ctrl4);
    cester_assert_uint_ge(ackTime, 500);
    cester_assert_uint_lt(ackTime, 2000);
    // Timings here won't really be relevant, as the CDRom's head will be hovering
    // already around the right place, so it's mostly a no-op to seek there, but
    // can vary a lot between 2ms and 500ms as the head is moving and re-aligning.
    ramsyscall_printf("Basic seekP to 00:02:00: ack in %ius, complete in %ius\n", ackTime, completeTime);

    IMASK = imask;
)

CESTER_TEST(cdlSeekPwithArgs, test_instance,
    uint32_t imask = IMASK;

    IMASK = imask | IRQ_CDROM;

    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int setLocDone = setLoc(0, 2, 0);
    if (!setLocDone) {
        cester_assert_true(setLocDone);
        return;
    }

    initializeTime();
    // wait 50ms for things to settle
    while (updateTime() < 50000);
    initializeTime();

    CDROM_REG0 = 0;
    CDROM_REG2 = 0;
    CDROM_REG2 = 0;
    CDROM_REG2 = 0;
    CDROM_REG2 = 0;
    CDROM_REG1 = CDL_SEEKP;

    uint32_t errorTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    cester_assert_uint_eq(5, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(3, response1[0]);
    cester_assert_uint_eq(0x20, response1[1]);
    cester_assert_uint_eq(2, responseSize1);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_ge(errorTime, 500);
    cester_assert_uint_lt(errorTime, 2000);
    ramsyscall_printf("Too many args seekP, errored in %ius\n", errorTime);

    IMASK = imask;
)

CESTER_TEST(cdlSeekP2to4, test_instance,
    uint32_t imask = IMASK;

    IMASK = imask | IRQ_CDROM;

    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int seekDone = seekPTo(0, 2, 0);
    if (!seekDone) {
        cester_assert_true(seekDone);
        return;
    }

    int setLocDone = setLoc(0, 4, 0);
    if (!setLocDone) {
        cester_assert_true(setLocDone);
        return;
    }

    initializeTime();
    // wait 50ms for things to settle
    while (updateTime() < 50000);
    initializeTime();

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_SEEKP;

    uint32_t ackTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    uint32_t completeTime = waitCDRomIRQ() - ackTime;
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl3 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t ctrl4 = CDROM_REG0 & ~3;
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
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_eq(0x38, ctrl3);
    cester_assert_uint_eq(0x18, ctrl4);
    cester_assert_uint_ge(ackTime, 500);
    cester_assert_uint_lt(ackTime, 2000);
    // It'd be difficult to put an interval check here, as the seek time will vary
    // a lot depending on the status of the drive, but it should probably be
    // at least 100ms, and more likely 150ms.
    ramsyscall_printf("Basic seekP from 00:02:00 to 00:04:00: ack in %ius, complete in %ius\n", ackTime, completeTime);

    IMASK = imask;
)

CESTER_TEST(cdlSeekP2to71, test_instance,
    uint32_t imask = IMASK;

    IMASK = imask | IRQ_CDROM;

    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int seekDone = seekPTo(0, 2, 0);
    if (!seekDone) {
        cester_assert_true(seekDone);
        return;
    }

    int setLocDone = setLoc(0x71, 0, 0);
    if (!setLocDone) {
        cester_assert_true(setLocDone);
        return;
    }

    initializeTime();
    // wait 50ms for things to settle
    while (updateTime() < 50000);
    initializeTime();

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_SEEKP;

    uint32_t ackTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    uint32_t completeTime = waitCDRomIRQ() - ackTime;
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl3 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t ctrl4 = CDROM_REG0 & ~3;
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
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_eq(0x38, ctrl3);
    cester_assert_uint_eq(0x18, ctrl4);
    cester_assert_uint_ge(ackTime, 500);
    cester_assert_uint_lt(ackTime, 2000);
    // This is a pretty long distance seek, which will take at least a full second.
    cester_assert_uint_ge(completeTime, 1000000);
    ramsyscall_printf("Basic seekP from 00:02:00 to 71:00:00: ack in %ius, complete in %ius\n", ackTime, completeTime);

    IMASK = imask;
)

CESTER_TEST(cdlSeekP2to99, test_instance,
    uint32_t imask = IMASK;

    IMASK = imask | IRQ_CDROM;

    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int seekDone = seekPTo(0, 2, 0);
    if (!seekDone) {
        cester_assert_true(seekDone);
        return;
    }

    int setLocDone = setLoc(0x99, 0, 0);
    if (!setLocDone) {
        cester_assert_true(setLocDone);
        return;
    }

    initializeTime();
    // wait 50ms for things to settle
    while (updateTime() < 50000);
    initializeTime();

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_SEEKP;

    uint32_t ackTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    uint32_t errorTime = waitCDRomIRQ() - ackTime;
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl3 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t ctrl4 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(5, cause2);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0xe0, cause2b);
    cester_assert_uint_eq(2, response1[0]);
    cester_assert_uint_eq(1, responseSize1);
    cester_assert_uint_eq(6, response2[0]);
    cester_assert_uint_eq(16, response2[1]);
    cester_assert_uint_eq(2, responseSize2);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_eq(0x38, ctrl3);
    cester_assert_uint_eq(0x18, ctrl4);
    cester_assert_uint_ge(ackTime, 500);
    cester_assert_uint_lt(ackTime, 2000);
    // The seekP won't be successful when targeting a sector past the end of the
    // disc. The failure can be faster than the previous test, because it won't
    // retry reading where there's clearly no information whatsoever. Will sometimes
    // fail in roughly 650ms, which is the seek time plus some minor retry.
    cester_assert_uint_ge(errorTime, 600000);
    ramsyscall_printf("Basic seekP from 00:02:00 to 99:00:00: ack in %ius, errored in %ius\n", ackTime, errorTime);

    IMASK = imask;
)
