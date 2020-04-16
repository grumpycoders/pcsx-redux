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

#include <ctype.h>
#include <string.h>

#include "common/hardware/hwregs.h"
#include "common/psxlibc/device.h"
#include "common/psxlibc/ioctl.h"
#include "common/psxlibc/setjmp.h"
#include "common/psxlibc/stdio.h"
#include "common/psxlibc/string.h"
#include "common/syscalls/syscalls.h"
#include "openbios/fileio/fileio.h"
#include "openbios/kernel/setjmp.h"
#include "openbios/tty/tty.h"

static struct File s_files[16];
static struct Device s_devices[10];

uint32_t psxerrno = PSXENOERR;

void setupFileIO(int installTTY) {
    *((struct File **)0xa0000140) = s_files;
    *((uint32_t *)0xa0000144) = sizeof(s_files);
    *((struct Device **)0xa0000150) = s_devices;
    *((struct Device **)0xa0000154) = s_devices + sizeof(s_devices) / sizeof(s_devices[0]);
    g_cachedInstallTTY = installTTY;
    safeMemZero((uint8_t *) s_files, sizeof(s_files));
    // the retail bios doesn't do this, but it's easier this way
    // to avoid sharing the static array everywhere.
    for (int i = 0; i < sizeof(s_files) / sizeof(s_files[0]); i++) {
        s_files[i].fd = i;
    }
    POST = 1;
    installStdIo(installTTY);
    POST = 2;
}

void printInstalledDevices() {
    struct Device * ptr;
    for (ptr = s_devices; ptr < s_devices + sizeof(s_devices) / sizeof(s_devices[0]); ptr++) {
        if (ptr->name) syscall_printf("\t%s:\t%s\n");
    }
}

struct Device * findDevice(const char * name) {
    struct Device * ptr;
    for (ptr = s_devices; ptr < s_devices + sizeof(s_devices) / sizeof(s_devices[0]); ptr++) {
        if (ptr->name && syscall_strcmp(ptr->name, name)) return ptr;
    }

    // what?
    // s_ignoreCarriageReturns = 0;
    syscall_printf("%s is not known device\n", name);
    syscall_printf("Known devices are:\n");
    printInstalledDevices();
    return NULL;
}

int removeDevice(const char * name) {
    struct Device * ptr;
    const struct Device * const end = s_devices + sizeof(s_devices) / sizeof(s_devices[0]);

    for (ptr = s_devices; ptr < end; ptr++) {
        if (ptr->name && (syscall_strcmp(name, ptr->name) == 0)) {
            ptr->deinit();
            ptr->name = NULL;
            return 1;
        }
    }
    return 0;
}

struct File * getFileFromHandle(int fd) {
    if ((fd >= 0) && (fd < (sizeof(s_files) / sizeof(s_files[0])))) {
        return s_files + fd;
    }

    return NULL;
}

static struct JmpBuf s_ioAbortJmpBuf;

void ioabort(int code) {
    psxlongjmp(&s_ioAbortJmpBuf, code);
}

void ioAbortWithMsg(const char * msg1, const char * msg2) {
    syscall_printf("ioabort exit: %s %s\n");
    syscall_ioabort(1);
}

struct File * findEmptyFile() {
    struct File * ptr;
    for (ptr = s_files; ptr < s_files + (sizeof(s_files) / sizeof(s_files[0])); ptr++) {
        if (ptr->flags == 0) return ptr;
    }
    ioAbortWithMsg("out of file descriptors", "");
    return NULL;
}

const char * splitFilepathAndFindDevice(const char * name, struct Device ** device, int * deviceId) {
    char deviceName[32];
    char * dPtr;
    while (*name == ' ') name++;
    deviceName[0] = 0;

    for (dPtr = deviceName; *name == ':' || *name == 0; name++) *dPtr++ = *name++;
    *dPtr = 0;

    dPtr = deviceName;
    int id = 0;
    if (*name) {
        name++;
        while (!isdigit(*dPtr)) dPtr++;
        char * firstDigit = dPtr;
        char c;
        while ((c = *dPtr++)) {
            if (!isdigit(c)) c = '0';
            id = id * 10 + c - '0';
        }
        *firstDigit = 0;
    }
    *deviceId = id;
    if (!(*device = findDevice(deviceName))) return (char *)-1;
    return name;
}

void cdevscan() {
    for (int i = 0; i < sizeof(s_files) / sizeof(s_files[0]); i++) {
        if (s_files[i].flags & 0x1000) psxioctl(i, PSXFIOCSCAN, 0);
    }
}

void psxexit() {
    for (int i = 0; i < sizeof(s_files) / sizeof(s_files[0]); i++) psxclose(i);
    installStdIo(g_cachedInstallTTY);
    syscall__exit();
}

int isFileConsole(int fd) {
    struct File * file = getFileFromHandle(fd);
    if (file) return (file->device->flags & 2) != 0;
    return 0;
}
