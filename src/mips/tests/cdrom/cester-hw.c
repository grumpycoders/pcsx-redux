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

#include "common/syscalls/syscalls.h"

CESTER_BODY(
    static int s_interruptsWereEnabled = 0;
    static uint16_t s_oldMode = 0;
    static uint32_t s_lastHSyncCounter = 0;
    static uint32_t s_currentTime = 0;
    static const unsigned US_PER_HBLANK = 64;

    static uint8_t readResponse(uint8_t response[16]) {
        uint8_t responseSize = 0;
        while ((CDROM_REG0 & 0x20) && (responseSize < 16)) {
            response[responseSize++] = CDROM_REG1;
        }
        return responseSize;
    }

    static inline void initializeTime() {
        s_lastHSyncCounter = COUNTERS[1].value;
        s_currentTime = 0;
    }

    static inline uint32_t updateTime() {
        uint32_t lastHSyncCounter = s_lastHSyncCounter;
        uint32_t hsyncCounter = COUNTERS[1].value;
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

    static inline int resetCDRom() {
        uint32_t imask = IMASK;
        uint8_t cause;

        IMASK = imask | IRQ_CDROM;

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
        IMASK = imask;
        return 1;
    }
)

CESTER_BEFORE_ALL(cpu_tests,
    s_interruptsWereEnabled = enterCriticalSection();
    s_oldMode = COUNTERS[1].mode;
    COUNTERS[1].mode = 0x0100;
)

CESTER_AFTER_ALL(cpu_tests,
    COUNTERS[1].mode = s_oldMode;
    if (s_interruptsWereEnabled) leaveCriticalSection();
)
