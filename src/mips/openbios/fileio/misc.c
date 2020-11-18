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
#include "openbios/kernel/globals.h"
#include "openbios/kernel/setjmp.h"
#include "openbios/main/main.h"
#include "openbios/tty/tty.h"

static struct File s_files[16];
static struct Device s_devices[10];
static struct File * s_firstFile;
static int s_deviceStatus;

uint32_t psxerrno = PSXENOERR;

void setupFileIO(int installTTY) {
    __globals.files = s_files;
    __globals.filesSize = sizeof(s_files);
    __globals.devices = s_devices;
    __globals.devicesEnd = s_devices + sizeof(s_devices) / sizeof(s_devices[0]);
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
    s_firstFile = NULL;
    s_deviceStatus = 0;
    syscall_addCDRomDevice();
    syscall_addMemoryCardDevice();
}

void printInstalledDevices() {
    struct Device * ptr;
    for (ptr = s_devices; ptr < s_devices + sizeof(s_devices) / sizeof(s_devices[0]); ptr++) {
        if (ptr->name) romsyscall_printf("\t%s:\t%s\n");
    }
}

struct Device * findDevice(const char * name) {
    struct Device * ptr;
    for (ptr = s_devices; ptr < s_devices + sizeof(s_devices) / sizeof(s_devices[0]); ptr++) {
        if (ptr->name && !syscall_strcmp(ptr->name, name)) return ptr;
    }

    // what?
    // s_ignoreCarriageReturns = 0;
    romsyscall_printf("%s is not known device\n", name);
    romsyscall_printf("Known devices are:\n");
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

void ioabortraw(int code) {
    psxlongjmp(&g_ioAbortJmpBuf, code);
}

void ioAbortWithMsg(const char * msg1, const char * msg2) {
    romsyscall_printf("ioabort exit: %s %s\n");
    syscall_ioabortraw(1);
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

    for (dPtr = deviceName; *name != ':' && *name != 0; name++) *dPtr++ = *name;
    *dPtr = 0;

    dPtr = deviceName;
    int id = 0;
    if (*name) {
        name++;
        char c;
        while ((c = *dPtr) && !isdigit(*dPtr)) dPtr++;
        char * firstDigit = dPtr;
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

void psxexit(int code) {
    for (int i = 0; i < sizeof(s_files) / sizeof(s_files[0]); i++) psxclose(i);
    installStdIo(g_cachedInstallTTY);
    syscall__exit(code);
}

int isFileConsole(int fd) {
    struct File * file = getFileFromHandle(fd);
    if (file) return (file->device->flags & PSXDTTYPE_CONS) != 0;
    return 0;
}

int addDevice(struct Device * device) {
    struct Device * ptr = s_devices;

    while (1) {
        if (ptr >= (s_devices + sizeof(s_devices) / sizeof(s_devices[0]))) return 0;
        if (ptr->name == NULL) break;
        ptr++;
    }

    syscall_memcpy(ptr, device, sizeof(struct Device));
    syscall_flushCache();
    ptr->init();

    return 1;
}
