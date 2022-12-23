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
    // Typical value seems to be around 1ms.
    cester_assert_uint_ge(completeTime, 500);
    cester_assert_uint_lt(completeTime, 2000);
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
    // Typical value seems to be around 1ms.
    cester_assert_uint_ge(errorTime, 500);
    cester_assert_uint_lt(errorTime, 1500);
    ramsyscall_printf("Invalid setloc with no args, errored in %ius\n", errorTime);
)
