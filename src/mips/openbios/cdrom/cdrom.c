/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include <stddef.h>

#include "common/hardware/cdrom.h"
#include "common/syscalls/syscalls.h"
#include "common/psxlibc/device.h"
#include "openbios/cdrom/cdrom.h"
#include "openbios/cdrom/events.h"
#include "openbios/cdrom/filesystem.h"
#include "openbios/kernel/libcmisc.h"

static void initializeHandlersAndEvents() {
    syscall_enqueueCDRomHandlers();
    g_cdEventACK = syscall_openEvent(0xf0000003, 0x0010, 0x2000, NULL);
    g_cdEventDNE = syscall_openEvent(0xf0000003, 0x0020, 0x2000, NULL);
    g_cdEventRDY = syscall_openEvent(0xf0000003, 0x0040, 0x2000, NULL);
    g_cdEventEND = syscall_openEvent(0xf0000003, 0x0080, 0x2000, NULL);
    g_cdEventERR = syscall_openEvent(0xf0000003, 0x8000, 0x2000, NULL);
    leaveCriticalSection();
    g_cdromCWD[0] = 0;
}

static void initializeSoftwareAndHardware() {
    initializeHandlersAndEvents();
    while (!syscall_cdromInnerInit());
}

void initCDRom() {
    initializeSoftwareAndHardware();
    volatile int delay = 0;
    while(++delay < 50000);
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
    while (!syscall_cdromGetStatus(&status) && (--cyclesToWait > 0));
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

int addCDRomDevice() {
    return syscall_addDevice(&s_cdromDevice);
}

static volatile uint32_t * const dummy = (volatile uint32_t * const) 0;

static void resetAllCDRomIRQs() {
    CDROM_REG0 = 1;
    CDROM_REG3 = 0x1f;
    for (int i = 0; i < 4; i++) *dummy = i;
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
