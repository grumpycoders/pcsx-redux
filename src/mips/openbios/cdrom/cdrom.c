/*

MIT License

Copyright (c) 2020 PCSX-Redux authors

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

#include "common/hardware/cdrom.h"

#include <stddef.h>

#include "common/psxlibc/device.h"
#include "common/syscalls/syscalls.h"
#include "openbios/cdrom/cdrom.h"
#include "openbios/cdrom/events.h"
#include "openbios/cdrom/filesystem.h"
#include "openbios/kernel/libcmisc.h"

void initializeCDRomHandlersAndEvents() {
    syscall_enqueueCDRomHandlers();
    g_cdEventACK = syscall_openEvent(EVENT_CDROM, 0x0010, EVENT_MODE_NO_CALLBACK, NULL);
    g_cdEventDNE = syscall_openEvent(EVENT_CDROM, 0x0020, EVENT_MODE_NO_CALLBACK, NULL);
    g_cdEventRDY = syscall_openEvent(EVENT_CDROM, 0x0040, EVENT_MODE_NO_CALLBACK, NULL);
    g_cdEventEND = syscall_openEvent(EVENT_CDROM, 0x0080, EVENT_MODE_NO_CALLBACK, NULL);
    g_cdEventERR = syscall_openEvent(EVENT_CDROM, 0x8000, EVENT_MODE_NO_CALLBACK, NULL);
    syscall_enableEvent(g_cdEventACK);
    syscall_enableEvent(g_cdEventDNE);
    syscall_enableEvent(g_cdEventRDY);
    syscall_enableEvent(g_cdEventEND);
    syscall_enableEvent(g_cdEventERR);
    leaveCriticalSection();
    g_cdromCWD[0] = 0;
}

static void initializeSoftwareAndHardware() {
    initializeCDRomHandlersAndEvents();
    while (!syscall_cdromInnerInit())
        ;
}

void initCDRom() {
    initializeSoftwareAndHardware();
    int delay = 0;
    while (++delay < 50000) __asm__ volatile("");
    cdromReadPathTable();
}

void deinitCDRom() {
    enterCriticalSection();
    syscall_closeEvent(g_cdEventACK);
    syscall_closeEvent(g_cdEventDNE);
    syscall_closeEvent(g_cdEventRDY);
    syscall_closeEvent(g_cdEventEND);
    syscall_closeEvent(g_cdEventERR);
    syscall_dequeueCDRomHandlers();
}

int cdromBlockGetStatus() {
    uint8_t status;

    int cyclesToWait = 9;
    while (!syscall_cdromGetStatus(&status) && (--cyclesToWait > 0))
        ;
    if (cyclesToWait < 1) {
        syscall_exception(0x44, 0x1f);
        return -1;
    }

    while (cyclesToWait > 0) {
        if (syscall_testEvent(g_cdEventDNE)) return status;
        if (syscall_testEvent(g_cdEventERR)) {
            syscall_exception(0x44, 0x20);
            return -1;
        }
    }

    return status;
}

static const struct Device s_cdromDevice = {
    .name = "cdrom",
    .flags = 0x14,
    .blockSize = 0x800,
    .desc = "CD-ROM",
    .init = psxdummy,
    .open = dev_cd_open,
    .action = psxdummy,
    .close = psxdummy,
    .ioctl = psxdummy,
    .read = dev_cd_read,
    .write = psxdummy,
    .erase = psxdummy,
    .undelete = psxdummy,
    .firstfile = dev_cd_firstfile,
    .nextfile = dev_cd_nextfile,
    .format = psxdummy,
    .chdir = dev_cd_chdir,
    .rename = psxdummy,
    .deinit = deinitCDRom,
    .check = psxdummy,
};

int addCDRomDevice() { return syscall_addDevice(&s_cdromDevice); }

// Most likely a poor man's flushWriteQueue,
// but messes up the NULL pointer data,
// so we need to keep it this way.
extern volatile uint32_t __vector_00;

static void resetAllCDRomIRQs() {
    CDROM_REG0 = 1;
    CDROM_REG3 = 0x1f;
    for (int i = 0; i < 4; i++) __vector_00 = i;
}

static void disableCDRomIRQs() {
    CDROM_REG0 = 1;
    CDROM_REG2 = 0x18;
}

static int waitForCDRomIRQCompletion() {
    int ret;
    uint8_t t;
    unsigned irqs = 0;

    while (irqs < 5) {
        CDROM_REG0 = 1;
        t = CDROM_REG3;
        if (t & 7) {
            irqs += t & 7;
            resetAllCDRomIRQs();
            ret = CDROM_REG1;
        }
    }
    if ((t & 7) == 5) return -1;
    return ret;
}

static int enableAllCDRomIRQs() {
    CDROM_REG0 = 1;
    CDROM_REG2 = 0x1f;
}

int cdromReadTOC() {
    resetAllCDRomIRQs();
    disableCDRomIRQs();
    CDROM_REG0 = 0;
    CDROM_REG1 = 0x1e;
    uint8_t t = waitForCDRomIRQCompletion();
    if ((t < 0) || (t & 0x1d)) {
        enableAllCDRomIRQs();
        return -1;
    }
    resetAllCDRomIRQs();
    enableAllCDRomIRQs();
    return 0;
}

int cdromReset() {
    resetAllCDRomIRQs();
    disableCDRomIRQs();
    CDROM_REG0 = 0;
    CDROM_REG1 = 0x1a;
    uint8_t t = waitForCDRomIRQCompletion();
    if ((t < 0) || (t & 0x1d)) {
        enableAllCDRomIRQs();
        return -1;
    }
    resetAllCDRomIRQs();
    enableAllCDRomIRQs();
    return 0;
}
