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

CESTER_TEST(cdlInit, test_instance,
    initializeTime();

    uint32_t imask = IMASK;

    IMASK = imask | IRQ_CDROM;

    CDROM_REG0 = 1;
    CDROM_REG3 = 0x1f;
    CDROM_REG0 = 1;
    CDROM_REG2 = 0x1f;
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_INIT;

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
    // Typical value seems to be around 2ms.
    cester_assert_uint_ge(ackTime, 800);
    cester_assert_uint_lt(ackTime, 5000);
    // These may be a bit flaky on real hardware, depending on the motors status when starting.
    // Typical value seems to be around 120ms.
    cester_assert_uint_ge(completeTime, 50000);
    cester_assert_uint_lt(completeTime, 150000);
    ramsyscall_printf("Basic initialization: CD-Rom controller initialized, ack in %ius, complete in %ius\n", ackTime, completeTime);

    IMASK = imask;
)

CESTER_TEST(cdlInitDelayed, test_instance,
    initializeTime();

    uint32_t imask = IMASK;

    IMASK = imask | IRQ_CDROM;

    CDROM_REG0 = 1;
    CDROM_REG3 = 0x1f;
    CDROM_REG0 = 1;
    CDROM_REG2 = 0x1f;
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_INIT;

    uint32_t ackTime = waitCDRomIRQ();

    // We shouldn't get another IRQ until we acknowledge the previous one
    // directly to the controller. But the initialization will continue
    // in the background nonetheless. Wait 500ms, since the controller
    // finishes its initialization in roughly 120ms.
    uint32_t delayedTime;
    do {
        delayedTime = updateTime();
    } while (((IREG & IRQ_CDROM) == 0) && (delayedTime <= 500000));
    int gotIRQ = (IREG & IRQ_CDROM) != 0;
    if (gotIRQ) IREG &= ~IRQ_CDROM;

    uint8_t cause1 = ackCDRomCause();
    CDROM_REG1;
    uint8_t ctrl1 = CDROM_REG0 & ~3;


    initializeTime();

    uint32_t completeTime = waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    CDROM_REG1;
    uint8_t ctrl2 = CDROM_REG0 & ~3;


    cester_assert_false(gotIRQ);
    cester_assert_uint_ge(delayedTime, 500000);
    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(2, cause2);
    cester_assert_uint_eq(0x18, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    // This still takes about 2ms.
    cester_assert_uint_ge(ackTime, 800);
    cester_assert_uint_lt(ackTime, 5000);
    // Since the initialization completes in the background of the controller
    // waiting its ack, we're really only measuring the roundtrip of the
    // communication between the CPU and the mechacon. It typically takes 350us
    // to do this roundtrip.
    cester_assert_uint_ge(completeTime, 100);
    cester_assert_uint_lt(completeTime, 1000);
    ramsyscall_printf("Delayed initialization: CD-Rom controller initialized, ack in %ius, complete in %ius\n", ackTime, completeTime);

    IMASK = imask;
)

CESTER_TEST(cdlInitWithArgs, test_instance,
    initializeTime();

    uint32_t imask = IMASK;

    IMASK = imask | IRQ_CDROM;

    CDROM_REG0 = 1;
    CDROM_REG3 = 0x1f;
    CDROM_REG0 = 1;
    CDROM_REG2 = 0x1f;
    CDROM_REG0 = 0;
    CDROM_REG2 = 0xff;
    CDROM_REG2 = 0xff;
    CDROM_REG2 = 0xff;
    CDROM_REG2 = 0xff;
    CDROM_REG1 = CDL_INIT;

    uint32_t errorTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    uint8_t response1[16];
    uint8_t responseSize1 = readResponse(response1);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_NOP;
    uint32_t ackTime = waitCDRomIRQ();
    uint8_t cause2 = ackCDRomCause();
    uint8_t ctrl3 = CDROM_REG0 & ~3;
    uint8_t response2[16];
    uint8_t responseSize2 = readResponse(response2);
    uint8_t ctrl4 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause2b = CDROM_REG3_UC;

    cester_assert_uint_eq(5, cause1);
    cester_assert_uint_eq(3, cause2);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0xe0, cause2b);
    cester_assert_uint_eq(3, response1[0]);
    cester_assert_uint_eq(0x20, response1[1]);
    cester_assert_uint_eq(2, responseSize1);
    cester_assert_uint_eq(2, response2[0]);
    cester_assert_uint_eq(1, responseSize2);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    cester_assert_uint_eq(0x38, ctrl3);
    cester_assert_uint_eq(0x18, ctrl4);
    // Typical value seems to be around 1ms.
    cester_assert_uint_ge(errorTime, 500);
    cester_assert_uint_lt(errorTime, 2000);
    // Typical value seems to be around 1.5ms.
    cester_assert_uint_ge(ackTime, 1000);
    cester_assert_uint_lt(ackTime, 3500);
    ramsyscall_printf("Initialization with args: CD-Rom controller errored, error in %ius\n", errorTime);
    ramsyscall_printf("Initialization with args: requested status, ack in %ius\n", ackTime);

    IMASK = imask;
)

