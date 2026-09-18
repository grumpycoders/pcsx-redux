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

// clang-format off

CESTER_TEST(simplePlayingUntilEnd, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int setModeDone = setMode(0x00);
    if (!setModeDone) {
        cester_assert_true(setModeDone);
        return;
    }

    int seekDone = seekPTo(0x71, 0x27, 0);

    if (!seekDone) {
        cester_assert_true(seekDone);
        return;
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PLAY;
    uint8_t response1[16];
    waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t responseSize1 = readResponse(response1);

    initializeTime();
    uint32_t time1 = waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(4, cause2);
    cester_assert_uint_eq(0xe0, cause2b);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_eq(2, response1[0]);
    cester_assert_uint_eq(1, responseSize1);
    cester_assert_uint_eq(2, response2[0]);
    cester_assert_uint_eq(1, responseSize2);
    // Should finish in 1640ms to 1960ms.
    cester_assert_uint_ge(time1, 1640000);
    cester_assert_uint_lt(time1, 1960000);
    ramsyscall_printf("Simple Playing until end, finished in %ius\n", time1);
)

CESTER_TEST(simplePlayingUntilEndDoubleTime, test_instances,
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

    int seekDone = seekPTo(0x71, 0x27, 0);

    if (!seekDone) {
        cester_assert_true(seekDone);
        return;
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PLAY;
    uint8_t response1[16];
    waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t responseSize1 = readResponse(response1);

    initializeTime();
    uint32_t time1 = waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(4, cause2);
    cester_assert_uint_eq(0xe0, cause2b);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_eq(2, response1[0]);
    cester_assert_uint_eq(1, responseSize1);
    cester_assert_uint_eq(2, response2[0]);
    cester_assert_uint_eq(1, responseSize2);
    // Should finish in 820ms to 980ms.
    cester_assert_uint_ge(time1, 820000);
    cester_assert_uint_lt(time1, 980000);
    ramsyscall_printf("Simple Playing until end, Double Time, finished in %ius\n", time1);
)

CESTER_TEST(simplePlayingUntilEndWithReport, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int setModeDone = setMode(0x04);
    if (!setModeDone) {
        cester_assert_true(setModeDone);
        return;
    }

    int seekDone = seekPTo(0x71, 0x26, 0);

    if (!seekDone) {
        cester_assert_true(seekDone);
        return;
    }

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_PLAY;
    uint8_t response[16];
    waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    readResponse(response);

    uint8_t causes[32];
    uint8_t responseSizes[32];
    uint8_t responses[32 * 16];

    __builtin_memset(causes, 0, sizeof(causes));
    __builtin_memset(responseSizes, 0, sizeof(responseSizes));

    unsigned count;

    for (count = 0; count < 32; count++) {
        waitCDRomIRQ();
        uint8_t cause = ackCDRomCause();
        causes[count] = cause;
        responseSizes[count] = readResponse(responses + count * 16);
        if (cause != 1) break;
    }

    for (unsigned i = 0; i < count; i++) {
        cester_assert_uint_eq(1, causes[i]);
        cester_assert_uint_eq(8, responseSizes[i]);
    }
    cester_assert_uint_eq(4, causes[count]);
    cester_assert_uint_eq(1, responseSizes[count]);
    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_ge(count, 15);
    cester_assert_uint_lt(count, 17);
    if (count >= 15) {
        unsigned offset = count - 15;
        unsigned upCount = 0;
        for (unsigned i = offset; i < count; i++) {
            // stat
            cester_assert_uint_eq(0x82, responses[i * 16 + 0]);
            // track
            cester_assert_uint_eq(0x25, responses[i * 16 + 1]);
            // index
            cester_assert_uint_eq(0x01, responses[i * 16 + 2]);
            unsigned index = i - offset;
            if ((index & 1) == 0) {
                // absolute minute time
                cester_assert_uint_eq(0x71, responses[i * 16 + 3]);
            } else {
                // relative minute time
                cester_assert_uint_eq(0, responses[i * 16 + 3]);
            }
            static uint8_t seconds[15] = { 0x26, 0x81, 0x27, 0x81, 0x27, 0x82, 0x27, 0x82, 0x27, 0x82, 0x28, 0x82, 0x28, 0x83, 0x28 };
            cester_assert_uint_eq(seconds[index], responses[i * 16 + 4]);
            static uint8_t frames[15] = { 0x60, 0x40, 0x00, 0x55, 0x20, 0x00, 0x40, 0x20, 0x60, 0x40, 0x00, 0x55, 0x20, 0x00, 0x40 };
            // This report might wobble a bit, but the above values ought to be close enough to our most likely values.
            cester_assert_uint_ge(responses[i * 16 + 5], frames[index]);
            cester_assert_uint_le(responses[i * 16 + 5], frames[index] + 1);
            uint16_t peak = (responses[i * 16 + 7] << 8) | responses[i * 16 + 6];
            uint16_t flag = peak & 0x8000;
            peak &= 0x7fff;
            cester_assert_uint_eq(0x619b, peak);
            if (flag == 0x8000) upCount++;
        }
        cester_assert_uint_ge(upCount, 6);
        cester_assert_uint_le(upCount, 8);
    }
    ramsyscall_printf("Simple Playing until end with reports:\n");
    for (unsigned i = 0; i < count; i++) {
        ramsyscall_printf(" - Response[%i] = %02x %02x %02x %02x %02x %02x %02x %02x\n", i,
            responses[i * 16 + 0], responses[i * 16 + 1], responses[i * 16 + 2], responses[i * 16 + 3],
            responses[i * 16 + 4], responses[i * 16 + 5], responses[i * 16 + 6], responses[i * 16 + 7]);
    }
)
