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

CESTER_TEST(cdlSetLoc, test_instances,
    int resetDone = resetCDRom();
    cester_assert_true(resetDone);
    if (!resetDone) return;

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG2 = 0;
    CDROM_REG2 = 2;
    CDROM_REG2 = 0;
    CDROM_REG1 = CDL_SETLOC;
    uint32_t completeTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t stat1 = CDROM_REG0 & ~3;
    uint8_t response[16];
    uint8_t responseSize = readResponse(response);
    uint8_t stat2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0x38, stat1);
    cester_assert_uint_eq(0x18, stat2);
    cester_assert_uint_eq(2, response[0]);
    cester_assert_uint_eq(1, responseSize);
    // Typical value seems to be around 1ms, but has
    // been seen to spike high from time to time.
    cester_assert_uint_ge(completeTime, 500);
    cester_assert_uint_lt(completeTime, 6500);
    ramsyscall_printf("Basic setloc to 00:02:00, complete in %ius\n", completeTime);
)

CESTER_TEST(cdlSetLocNoArgs, test_instances,
    int resetDone = resetCDRom();
    cester_assert_true(resetDone);
    if (!resetDone) return;

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_SETLOC;
    uint32_t errorTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t stat1 = CDROM_REG0 & ~3;
    uint8_t response[16];
    uint8_t responseSize = readResponse(response);
    uint8_t stat2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    cester_assert_uint_eq(5, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0x38, stat1);
    cester_assert_uint_eq(0x18, stat2);
    cester_assert_uint_eq(3, response[0]);
    cester_assert_uint_eq(32, response[1]);
    cester_assert_uint_eq(2, responseSize);
    cester_assert_uint_ge(errorTime, 500);
    cester_assert_uint_lt(errorTime, 6500);
    ramsyscall_printf("Invalid setloc with no args, errored in %ius\n", errorTime);
)

CESTER_TEST(cdlSetLocMultiple, test_instances,
    int resetDone = resetCDRom();
    uint8_t cause;
    cester_assert_true(resetDone);
    if (!resetDone) return;

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG2 = 0;
    CDROM_REG2 = 2;
    CDROM_REG2 = 0;
    CDROM_REG1 = CDL_SETLOC;
    uint32_t time1 = waitCDRomIRQ();
    cause = ackCDRomCause();
    CDROM_REG1;
    if (cause != 3) {
        cester_assert_uint_eq(3, cause);
        return;
    }

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG2 = 0x99;
    CDROM_REG2 = 0x59;
    CDROM_REG2 = 0x74;
    CDROM_REG1 = CDL_SETLOC;
    uint32_t time2 = waitCDRomIRQ();
    cause = ackCDRomCause();
    CDROM_REG1;
    if (cause != 3) {
        cester_assert_uint_eq(3, cause);
        return;
    }

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG2 = 0x50;
    CDROM_REG2 = 0;
    CDROM_REG2 = 0;
    CDROM_REG1 = CDL_SETLOC;
    uint32_t time3 = waitCDRomIRQ();
    cause = ackCDRomCause();
    CDROM_REG1;
    if (cause != 3) {
        cester_assert_uint_eq(3, cause);
        return;
    }

    // Setloc is only changing an internal state.
    // Its response time is very fast, and won't
    // vary regardless of the location, but can
    // still spike to 6ms from time to time.
    cester_assert_uint_ge(time1, 500);
    cester_assert_uint_lt(time1, 6500);
    cester_assert_uint_ge(time2, 500);
    cester_assert_uint_lt(time2, 6500);
    cester_assert_uint_ge(time3, 500);
    cester_assert_uint_lt(time3, 6500);
    ramsyscall_printf("Multiple setloc to 00:02:00, complete in %ius, %ius, %ius\n", time1, time2, time3);
)

CESTER_TEST(cdlSetLocInvalid1, test_instances,
    int resetDone = resetCDRom();
    cester_assert_true(resetDone);
    if (!resetDone) return;

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG2 = 0;
    CDROM_REG2 = 2;
    CDROM_REG2 = 0x2a;
    CDROM_REG1 = CDL_SETLOC;
    uint32_t errorTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t stat1 = CDROM_REG0 & ~3;
    uint8_t response[16];
    uint8_t responseSize = readResponse(response);
    uint8_t stat2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    cester_assert_uint_eq(5, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0x38, stat1);
    cester_assert_uint_eq(0x18, stat2);
    cester_assert_uint_eq(3, response[0]);
    cester_assert_uint_eq(16, response[1]);
    cester_assert_uint_eq(2, responseSize);
    cester_assert_uint_ge(errorTime, 500);
    cester_assert_uint_lt(errorTime, 6500);
    ramsyscall_printf("Invalid setloc to 00:02:2a, errored in %ius\n", errorTime);
)

CESTER_TEST(cdlSetLocInvalid2, test_instances,
    int resetDone = resetCDRom();
    cester_assert_true(resetDone);
    if (!resetDone) return;

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG2 = 0;
    CDROM_REG2 = 2;
    CDROM_REG2 = 0x79;
    CDROM_REG1 = CDL_SETLOC;
    uint32_t errorTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t stat1 = CDROM_REG0 & ~3;
    uint8_t response[16];
    uint8_t responseSize = readResponse(response);
    uint8_t stat2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    cester_assert_uint_eq(5, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0x38, stat1);
    cester_assert_uint_eq(0x18, stat2);
    cester_assert_uint_eq(3, response[0]);
    cester_assert_uint_eq(16, response[1]);
    cester_assert_uint_eq(2, responseSize);
    cester_assert_uint_ge(errorTime, 500);
    cester_assert_uint_lt(errorTime, 6500);
    ramsyscall_printf("Invalid setloc to 00:02:79, errored in %ius\n", errorTime);
)

CESTER_TEST(cdlSetLocTooManyArgs, test_instances,
    int resetDone = resetCDRom();
    cester_assert_true(resetDone);
    if (!resetDone) return;

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG2 = 0;
    CDROM_REG2 = 2;
    CDROM_REG2 = 0;
    CDROM_REG2 = 0;
    CDROM_REG1 = CDL_SETLOC;
    uint32_t errorTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t stat1 = CDROM_REG0 & ~3;
    uint8_t response[16];
    uint8_t responseSize = readResponse(response);
    uint8_t stat2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    cester_assert_uint_eq(5, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0x38, stat1);
    cester_assert_uint_eq(0x18, stat2);
    cester_assert_uint_eq(3, response[0]);
    cester_assert_uint_eq(32, response[1]);
    cester_assert_uint_eq(2, responseSize);
    cester_assert_uint_ge(errorTime, 500);
    cester_assert_uint_lt(errorTime, 6500);
    ramsyscall_printf("Invalid setloc with too many args, errored in %ius\n", errorTime);
)

CESTER_TEST(cdlSetLocTooManyArgsAndInvalid, test_instances,
    int resetDone = resetCDRom();
    cester_assert_true(resetDone);
    if (!resetDone) return;

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG2 = 0;
    CDROM_REG2 = 2;
    CDROM_REG2 = 0x79;
    CDROM_REG2 = 0;
    CDROM_REG1 = CDL_SETLOC;
    uint32_t errorTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t stat1 = CDROM_REG0 & ~3;
    uint8_t response[16];
    uint8_t responseSize = readResponse(response);
    uint8_t stat2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    cester_assert_uint_eq(5, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0x38, stat1);
    cester_assert_uint_eq(0x18, stat2);
    cester_assert_uint_eq(3, response[0]);
    cester_assert_uint_eq(32, response[1]);
    cester_assert_uint_eq(2, responseSize);
    cester_assert_uint_ge(errorTime, 500);
    cester_assert_uint_lt(errorTime, 6500);
    ramsyscall_printf("Invalid setloc with too many invalid args, errored in %ius\n", errorTime);
)

