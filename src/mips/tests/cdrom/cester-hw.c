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

// This file isn't to be compiled directly. It's to be included in every
// sub test .c file that wants to do hardware measurements.

// clang-format off

#include <stdint.h>

CESTER_BODY(
    static void hexdump(const void* data_, unsigned size) {
        const uint8_t* data = (const uint8_t*)data_;
        char ascii[17];
        ascii[16] = 0;
        for (unsigned i = 0; i < size; i++) {
            if (i % 16 == 0) ramsyscall_printf("%08x  |", i);
            ramsyscall_printf("%02X ", data[i]);
            ascii[i % 16] = data[i] >= ' ' && data[i] <= '~' ? data[i] : '.';
            unsigned j = i + 1;
            if ((j % 8 == 0) || (j == size)) {
                ramsyscall_printf(" ");
                if (j % 16 == 0) {
                    ramsyscall_printf("|  %s \n", ascii);
                } else if (j == size) {
                    ascii[j % 16] = 0;
                    if (j % 16 <= 8) ramsyscall_printf(" ");
                    for (j %= 16; j < 16; j++) ramsyscall_printf("   ");
                    ramsyscall_printf("|  %s \n", ascii);
                }
            }
        }
    }

    static int s_interruptsWereEnabled = 0;
    static uint16_t s_oldMode = 0;
    static uint32_t s_lastHSyncCounter = 0;
    static uint32_t s_currentTime = 0;
    static uint32_t s_oldIMASK = 0;
    static const unsigned US_PER_HBLANK = 64;

    struct LocPResult {
        uint8_t track, index, m, s, f, am, as, af;
        uint8_t padding[8];
    };

    static uint8_t btoi(uint8_t b) {
        return (b >> 4) * 10 + (b & 0xf);
    }

    static uint8_t itob(uint8_t i) {
        return (i / 10) * 16 + (i % 10);
    }

    static int isValidBCD(uint8_t b) {
        return (b & 0xf) < 10 && (b >> 4) < 10;
    }

    static uint32_t MSF2LBA(uint8_t m, uint8_t s, uint8_t f) {
        return (m * 60 + s) * 75 + f;
    }

    static uint8_t readResponse(uint8_t response[16]) {
        uint8_t responseSize = 0;
        while ((CDROM_REG0 & 0x20) && (responseSize < 16)) {
            response[responseSize++] = CDROM_REG1;
        }
        return responseSize;
    }

    static uint8_t discardResponse() {
        uint8_t response[16];
        return readResponse(response);
    }

    static inline void initializeTime() {
        while (1) {
            uint32_t init = COUNTERS[1].value;
            uint32_t counter;
            while ((counter = COUNTERS[1].value) == init);
            if (counter != COUNTERS[1].value) continue;
            s_lastHSyncCounter = counter;
            break;
        }
        s_currentTime = 0;
    }

    static inline uint32_t updateTime() {
        uint32_t lastHSyncCounter = s_lastHSyncCounter;
        uint32_t hsyncCounter;
        while (1) {
            hsyncCounter = COUNTERS[1].value;
            if (hsyncCounter != COUNTERS[1].value) continue;
            break;
        }
        if (hsyncCounter < lastHSyncCounter) {
            hsyncCounter += 0x10000;
        }
        uint32_t currentTime = s_currentTime = s_currentTime + (hsyncCounter - lastHSyncCounter) * US_PER_HBLANK;
        s_lastHSyncCounter = hsyncCounter;
        return currentTime;
    }

    static inline uint32_t waitCDRomIRQ() {
        uint32_t time;
        do {
            time = updateTime();
        } while ((IREG & IRQ_CDROM) == 0);
        IREG &= ~IRQ_CDROM;
        return time;
    }

    static inline int waitCDRomIRQWithTimeout(uint32_t* timeoutp) {
        uint32_t time = updateTime();
        uint32_t timeout = *timeoutp + time;
        do {
            time = updateTime();
        } while (((IREG & IRQ_CDROM) == 0) && (time <= timeout));
        int ret = (IREG & IRQ_CDROM) != 0;
        *timeoutp = time;
        IREG &= ~IRQ_CDROM;
        return ret;
    }

    static inline uint8_t ackCDRomCause() {
        CDROM_REG0 = 1;
        uint8_t cause = CDROM_REG3_UC;
        if (cause & 7) {
            CDROM_REG0 = 1;
            CDROM_REG3 = 7;
        }
        if (cause & 0x18) {
            CDROM_REG0 = 1;
            CDROM_REG3 = cause & 0x18;
        }
        return cause & 7;
    }

    int setMode(uint8_t mode) {
        uint8_t cause;
        CDROM_REG0 = 0;
        CDROM_REG2 = mode;
        CDROM_REG1 = CDL_SETMODE;
        waitCDRomIRQ();
        cause = ackCDRomCause();
        CDROM_REG1;
        if (cause != 3) return 0;
        return 1;
    }

    static inline int resetCDRom() {
        uint8_t cause;

        CDROM_REG0 = 1;
        CDROM_REG3 = 0x1f;
        CDROM_REG0 = 1;
        CDROM_REG2 = 0x1f;
        CDROM_REG0 = 0;
        CDROM_REG1 = CDL_INIT;
        waitCDRomIRQ();
        cause = ackCDRomCause();
        CDROM_REG1;
        if (cause != 3) return 0;
        waitCDRomIRQ();
        cause = ackCDRomCause();
        CDROM_REG1;
        if (cause != 2) return 0;

        initializeTime();
        // wait 10ms for things to settle
        while (updateTime() < 10000);
        return setMode(0);
    }

    static int setLoc(uint8_t minute, uint8_t second, uint8_t frame) {
        uint8_t cause;

        CDROM_REG0 = 0;
        CDROM_REG2 = minute;
        CDROM_REG2 = second;
        CDROM_REG2 = frame;
        CDROM_REG1 = CDL_SETLOC;
        waitCDRomIRQ();
        cause = ackCDRomCause();
        CDROM_REG1;
        if (cause != 3) return 0;

        return 1;
    }

    static int seekPTo(uint8_t minute, uint8_t second, uint8_t frame) {
        uint8_t cause;

        CDROM_REG0 = 0;
        CDROM_REG2 = minute;
        CDROM_REG2 = second;
        CDROM_REG2 = frame;
        CDROM_REG1 = CDL_SETLOC;
        waitCDRomIRQ();
        cause = ackCDRomCause();
        CDROM_REG1;
        if (cause != 3) return 0;

        CDROM_REG0 = 0;
        CDROM_REG1 = CDL_SEEKP;
        waitCDRomIRQ();
        cause = ackCDRomCause();
        CDROM_REG1;
        if (cause != 3) return 0;
        waitCDRomIRQ();
        cause = ackCDRomCause();
        CDROM_REG1;
        if (cause != 2) return 0;
        return 1;
    }

    static int seekLTo(uint8_t minute, uint8_t second, uint8_t frame) {
        uint8_t cause;

        CDROM_REG0 = 0;
        CDROM_REG2 = minute;
        CDROM_REG2 = second;
        CDROM_REG2 = frame;
        CDROM_REG1 = CDL_SETLOC;
        waitCDRomIRQ();
        cause = ackCDRomCause();
        CDROM_REG1;
        if (cause != 3) return 0;

        CDROM_REG0 = 0;
        CDROM_REG1 = CDL_SEEKL;
        waitCDRomIRQ();
        cause = ackCDRomCause();
        CDROM_REG1;
        if (cause != 3) return 0;
        waitCDRomIRQ();
        cause = ackCDRomCause();
        CDROM_REG1;
        if (cause != 2) return 0;

        return 1;
    }

    uint8_t getCtrl() {
        uint8_t cause;

        CDROM_REG0 = 0;
        CDROM_REG1 = CDL_NOP;
        waitCDRomIRQ();
        ackCDRomCause();
        uint8_t ctrl = CDROM_REG1;

        return ctrl;
    }
)

CESTER_BEFORE_ALL(cpu_tests,
    s_interruptsWereEnabled = enterCriticalSection();
    s_oldMode = COUNTERS[1].mode;
    COUNTERS[1].mode = 0x0100;
    SBUS_DEV5_CTRL = 0x20943;
    SBUS_COM_CTRL = 0x132c;
    s_oldIMASK = IMASK;
    IMASK = IRQ_CDROM;
)

CESTER_AFTER_ALL(cpu_tests,
    IMASK = s_oldIMASK;
    COUNTERS[1].mode = s_oldMode;
    if (s_interruptsWereEnabled) leaveCriticalSection();
)
