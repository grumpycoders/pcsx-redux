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

CESTER_TEST(cdlId, test_instance,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    initializeTime();

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_GETID;

    uint32_t ackTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    uint32_t completeTime = waitCDRomIRQ();
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
    cester_assert_uint_eq(8, responseSize2);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_eq(0x38, ctrl3);
    cester_assert_uint_eq(0x18, ctrl4);
    cester_assert_uint_ge(ackTime, 500);
    cester_assert_uint_lt(ackTime, 7000);
    ramsyscall_printf("Basic cdlId, ack in %ius, complete in %ius\n", ackTime, completeTime);
    ramsyscall_printf("Full response: %02x %02x %02x %02x %02x %02x %02x %02x\n",
        response2[0], response2[1], response2[2], response2[3],
        response2[4], response2[5], response2[6], response2[7]);
)

CESTER_TEST(cdlIdTooManyArgs, test_instance,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    initializeTime();

    CDROM_REG0 = 0;
    CDROM_REG2 = 0;
    CDROM_REG2 = 0;
    CDROM_REG2 = 0;
    CDROM_REG2 = 0;
    CDROM_REG1 = CDL_GETID;

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
    cester_assert_uint_lt(errorTime, 7000);
    ramsyscall_printf("Basic cdlId with too many args, errored in %ius\n", errorTime);
)

CESTER_TEST(cdlIdReadsTooMuch, test_instance,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    initializeTime();

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_GETID;

    uint32_t ackTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    uint32_t completeTime = waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl3 = CDROM_REG0 & ~3;
    uint8_t response2[17];
    for (unsigned i = 0; i < 17; i++) {
        response2[i] = CDROM_REG1;
    }
    uint8_t ctrl4 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(2, cause2);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0xe0, cause2b);
    cester_assert_uint_eq(2, response1[0]);
    cester_assert_uint_eq(1, responseSize1);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_eq(0x38, ctrl3);
    cester_assert_uint_eq(0x38, ctrl4);
    cester_assert_uint_ge(ackTime, 500);
    cester_assert_uint_lt(ackTime, 7000);
    ramsyscall_printf("cdlId reading too much data, ack in %ius, complete in %ius\n", ackTime, completeTime);
)

CESTER_TEST(cdlIdReadsWayTooMuchThencdlGetTN, test_instance,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    initializeTime();

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_GETID;

    uint32_t ackTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    uint32_t completeTime = waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl3 = CDROM_REG0 & ~3;
    uint8_t response2[32];
    for (unsigned i = 0; i < 32; i++) {
        response2[i] = CDROM_REG1;
    }
    uint8_t ctrl4 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_GETTN;

    waitCDRomIRQ();
    uint8_t cause3 = ackCDRomCause();
    uint8_t response3[32];
    for (unsigned i = 0; i < 32; i++) {
        response3[i] = CDROM_REG1;
    }

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(2, cause2);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0xe0, cause2b);
    cester_assert_uint_eq(2, response1[0]);
    cester_assert_uint_eq(1, responseSize1);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_eq(0x38, ctrl3);
    cester_assert_uint_eq(0x38, ctrl4);
    cester_assert_uint_ge(ackTime, 500);
    cester_assert_uint_lt(ackTime, 7000);
    for (unsigned i = 0; i < 16; i++) {
        cester_assert_uint_eq(response2[i], response2[i + 16]);
    }
    for (unsigned i = 8; i < 16; i++) {
        cester_assert_uint_eq(0, response2[i]);
    }
    for (unsigned i = 0; i < 16; i++) {
        cester_assert_uint_eq(response3[i], response3[i + 16]);
    }
    cester_assert_uint_eq(2, response3[0]);
    cester_assert_uint_eq(1, response3[1]);
    cester_assert_uint_eq(0x25, response3[2]);
    for (unsigned i = 3; i < 16; i++) {
        cester_assert_uint_eq(0, response3[i]);
    }
    ramsyscall_printf("cdlId reading way too much data, ack in %ius, complete in %ius\n", ackTime, completeTime);
    ramsyscall_printf("Full response:\n%02x %02x %02x %02x %02x %02x %02x %02x\n"
        "%02x %02x %02x %02x %02x %02x %02x %02x\n"
        "%02x %02x %02x %02x %02x %02x %02x %02x\n"
        "%02x %02x %02x %02x %02x %02x %02x %02x\n",
        response2[0], response2[1], response2[2], response2[3],
        response2[4], response2[5], response2[6], response2[7],
        response2[8], response2[9], response2[10], response2[11],
        response2[12], response2[13], response2[14], response2[15],
        response2[16], response2[17], response2[18], response2[19],
        response2[20], response2[21], response2[22], response2[23],
        response2[24], response2[25], response2[26], response2[27],
        response2[28], response2[29], response2[30], response2[31]);
    ramsyscall_printf("cdlGetTN reading too much data, full response:\n%02x %02x %02x %02x %02x %02x %02x %02x\n"
        "%02x %02x %02x %02x %02x %02x %02x %02x\n"
        "%02x %02x %02x %02x %02x %02x %02x %02x\n"
        "%02x %02x %02x %02x %02x %02x %02x %02x\n",
        response3[0], response3[1], response3[2], response3[3],
        response3[4], response3[5], response3[6], response3[7],
        response3[8], response3[9], response3[10], response3[11],
        response3[12], response3[13], response3[14], response3[15],
        response3[16], response3[17], response3[18], response3[19],
        response3[20], response3[21], response3[22], response3[23],
        response3[24], response3[25], response3[26], response3[27],
        response3[28], response3[29], response3[30], response3[31]);
)
