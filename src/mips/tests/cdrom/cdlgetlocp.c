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

CESTER_TEST(cdlGetLocP, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_GETLOCP;
    uint32_t ackTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    struct LocPResult response;
    uint8_t responseSize = readResponse((uint8_t*)&response);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    // Right after reset, the drive will over close to 00:02:00, so
    // the GetLocP will return values around that. Track will always
    // be 01, and the oscillation will be of roughly 4 frames. Index
    // will be 00 or 01 depending if the head is over the pregap,
    // before or equal to absolute 00:01:74. The absolute time will
    // be around 00:02:00, and the relative time will be around
    // 00:00:00. The pregap relative time counts down to 0, so
    // for an absolute time of 00:01:74, the relative time will be
    // 00:00:01. For an absolute time of 00:01:73, the relative time
    // will be 00:00:02, and so on.
    int inPregap = response.index == 0;
    uint32_t relative = MSF2LBA(btoi(response.m), btoi(response.s), btoi(response.f));
    uint32_t absolute = MSF2LBA(btoi(response.am), btoi(response.as), btoi(response.af));
    uint32_t onefifty = absolute;
    if (inPregap) {
        onefifty = absolute + relative;
    } else {
        onefifty = absolute - relative;
    }
    cester_assert_uint_eq(1, response.track);
    cester_assert_uint_ge(onefifty, 150);
    cester_assert_uint_ge(response.index, 0);
    cester_assert_uint_le(response.index, 1);
    cester_assert_uint_ge(absolute, 145);
    cester_assert_uint_lt(absolute, 155);
    cester_assert_uint_lt(relative, 5);
    cester_assert_uint_eq(8, responseSize);
    // Typical value seems to be around 1ms, but has
    // been seen to spike high from time to time.
    cester_assert_uint_ge(ackTime, 500);
    cester_assert_uint_lt(ackTime, 7000);
    ramsyscall_printf("Basic getlocP, ack in %ius\n", ackTime);
    ramsyscall_printf("Full response: track: %02x, index: %02x, relative: %02x:%02x:%02x(%2i), absolute: %02x:%02x:%02x(%2i)\n",
        response.track, response.index,
        response.m, response.s, response.f, relative,
        response.am, response.as, response.af, absolute
    );
)

CESTER_TEST(cdlGetLocPafterSeekP, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int seekDone = seekPTo(0x50, 0, 0);
    if (!seekDone) {
        cester_assert_true(seekDone);
        return;
    }

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_GETLOCP;
    uint32_t ackTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    struct LocPResult response;
    uint8_t responseSize = readResponse((uint8_t*)&response);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    // After a simple seekP, the head will hover around the seeked
    // position, so the GetLocP will return values before that. Distance
    // from the seeked position will be up to 50 frames around this location.
    int inPregap = response.index == 0;
    uint32_t relative = MSF2LBA(btoi(response.m), btoi(response.s), btoi(response.f));
    uint32_t absolute = MSF2LBA(btoi(response.am), btoi(response.as), btoi(response.af));
    uint32_t onefifty = absolute;
    if (inPregap) {
        onefifty = absolute + relative;
    } else {
        onefifty = absolute - relative;
    }
    cester_assert_uint_eq(1, response.track);
    cester_assert_uint_ge(onefifty, 150);
    cester_assert_uint_eq(0, inPregap);
    cester_assert_uint_eq(1, response.index);
    cester_assert_uint_ge(absolute, 224950);
    cester_assert_uint_lt(absolute, 225000);
    cester_assert_uint_ge(relative, 224800);
    cester_assert_uint_lt(relative, 224850);
    cester_assert_uint_eq(8, responseSize);
    // Typical value seems to be around 1ms, but has
    // been seen to spike high from time to time.
    cester_assert_uint_ge(ackTime, 500);
    cester_assert_uint_lt(ackTime, 7000);
    ramsyscall_printf("Basic getlocP after seekP, ack in %ius\n", ackTime);
    ramsyscall_printf("Full response: track: %02x, index: %02x, relative: %02x:%02x:%02x(%2i), absolute: %02x:%02x:%02x(%2i)\n",
        response.track, response.index,
        response.m, response.s, response.f, relative,
        response.am, response.as, response.af, absolute
    );
)

CESTER_TEST(cdlGetLocPafterSeekL, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int seekDone = seekLTo(0x50, 0, 0);
    if (!seekDone) {
        cester_assert_true(seekDone);
        return;
    }

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_GETLOCP;
    uint32_t ackTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    struct LocPResult response;
    uint8_t responseSize = readResponse((uint8_t*)&response);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    // After a simple seekL, the head will hover around the seeked
    // position, so the GetLocP will return values around that. Distance
    // from the seeked position will be up to 10 frames around this location,
    // and sometimes a little bit after it too. It will be much more precise
    // than seekP however, and most of the time, will be exactly at the
    // seeked position.
    int inPregap = response.index == 0;
    uint32_t relative = MSF2LBA(btoi(response.m), btoi(response.s), btoi(response.f));
    uint32_t absolute = MSF2LBA(btoi(response.am), btoi(response.as), btoi(response.af));
    uint32_t onefifty = absolute;
    if (inPregap) {
        onefifty = absolute + relative;
    } else {
        onefifty = absolute - relative;
    }
    cester_assert_uint_eq(1, response.track);
    cester_assert_uint_ge(onefifty, 150);
    cester_assert_uint_eq(0, inPregap);
    cester_assert_uint_eq(1, response.index);
    cester_assert_uint_ge(absolute, 224990);
    cester_assert_uint_le(absolute, 225005);
    cester_assert_uint_ge(relative, 224840);
    cester_assert_uint_le(relative, 224855);
    cester_assert_uint_eq(8, responseSize);
    // Typical value seems to be around 1ms, but has
    // been seen to spike high from time to time.
    cester_assert_uint_ge(ackTime, 500);
    cester_assert_uint_lt(ackTime, 7000);
    ramsyscall_printf("Basic getlocP after seekL, ack in %ius\n", ackTime);
    ramsyscall_printf("Full response: track: %02x, index: %02x, relative: %02x:%02x:%02x(%2i), absolute: %02x:%02x:%02x(%2i)\n",
        response.track, response.index,
        response.m, response.s, response.f, relative,
        response.am, response.as, response.af, absolute
    );
)


CESTER_TEST(cdlGetLocPinT5, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int seekDone = seekPTo(0x70, 0x21, 0);
    if (!seekDone) {
        cester_assert_true(seekDone);
        return;
    }

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_GETLOCP;
    uint32_t ackTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    struct LocPResult response;
    uint8_t responseSize = readResponse((uint8_t*)&response);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    // Let's go inside of track 5, and see what we get.
    int inPregap = response.index == 0;
    uint32_t relative = MSF2LBA(btoi(response.m), btoi(response.s), btoi(response.f));
    uint32_t absolute = MSF2LBA(btoi(response.am), btoi(response.as), btoi(response.af));
    uint32_t start = absolute;
    if (inPregap) {
        start = absolute + relative;
    } else {
        start = absolute - relative;
    }
    cester_assert_uint_eq(5, response.track);
    cester_assert_uint_eq(316500, start);
    cester_assert_uint_eq(0, inPregap);
    cester_assert_uint_eq(1, response.index);
    cester_assert_uint_ge(absolute, 316535);
    cester_assert_uint_lt(absolute, 316575);
    cester_assert_uint_ge(relative, 35);
    cester_assert_uint_lt(relative, 75);
    cester_assert_uint_eq(8, responseSize);
    // Typical value seems to be around 1ms, but has
    // been seen to spike high from time to time.
    cester_assert_uint_ge(ackTime, 500);
    cester_assert_uint_lt(ackTime, 7000);
    ramsyscall_printf("Basic getlocP after seekP in track5's, ack in %ius\n", ackTime);
    ramsyscall_printf("Full response: track: %02x, index: %02x, relative: %02x:%02x:%02x(%2i), absolute: %02x:%02x:%02x(%2i)\n",
        response.track, response.index,
        response.m, response.s, response.f, relative,
        response.am, response.as, response.af, absolute
    );
)

CESTER_TEST(cdlGetLocPinT5Pregap, test_instances,
    int resetDone = resetCDRom();
    if (!resetDone) {
        cester_assert_true(resetDone);
        return;
    }

    int seekDone = seekPTo(0x70, 0x19, 0x73);
    if (!seekDone) {
        cester_assert_true(seekDone);
        return;
    }

    initializeTime();
    CDROM_REG0 = 0;
    CDROM_REG1 = CDL_GETLOCP;
    uint32_t ackTime = waitCDRomIRQ();
    uint8_t cause1 = ackCDRomCause();
    uint8_t ctrl1 = CDROM_REG0 & ~3;
    struct LocPResult response;
    uint8_t responseSize = readResponse((uint8_t*)&response);
    uint8_t ctrl2 = CDROM_REG0 & ~3;
    CDROM_REG0 = 1;
    uint8_t cause1b = CDROM_REG3_UC;

    cester_assert_uint_eq(3, cause1);
    cester_assert_uint_eq(0xe0, cause1b);
    cester_assert_uint_eq(0x38, ctrl1);
    cester_assert_uint_eq(0x18, ctrl2);
    // This time, the head is in the pregap of track 5.
    int inPregap = response.index == 0;
    uint32_t relative = MSF2LBA(btoi(response.m), btoi(response.s), btoi(response.f));
    uint32_t absolute = MSF2LBA(btoi(response.am), btoi(response.as), btoi(response.af));
    uint32_t start = absolute;
    if (inPregap) {
        start = absolute + relative;
    } else {
        start = absolute - relative;
    }
    cester_assert_uint_eq(5, response.track);
    cester_assert_uint_eq(316500, start);
    cester_assert_uint_eq(1, inPregap);
    cester_assert_uint_eq(0, response.index);
    cester_assert_uint_ge(absolute, 316460);
    cester_assert_uint_lt(absolute, 316500);
    cester_assert_uint_lt(relative, 40);
    cester_assert_uint_eq(8, responseSize);
    // Typical value seems to be around 1ms, but has
    // been seen to spike high from time to time.
    cester_assert_uint_ge(ackTime, 500);
    cester_assert_uint_lt(ackTime, 7000);
    ramsyscall_printf("Basic getlocP after seekP in track5's pregap, ack in %ius\n", ackTime);
    ramsyscall_printf("Full response: track: %02x, index: %02x, relative: %02x:%02x:%02x(%2i), absolute: %02x:%02x:%02x(%2i)\n",
        response.track, response.index,
        response.m, response.s, response.f, relative,
        response.am, response.as, response.af, absolute
    );
)
