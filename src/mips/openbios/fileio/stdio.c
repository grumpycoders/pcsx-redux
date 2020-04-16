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

#include <stdarg.h>
#include <stdio.h>

#include "common/hardware/hwregs.h"
#include "common/psxlibc/ioctl.h"
#include "common/syscalls/syscalls.h"
#include "openbios/fileio/fileio.h"

static int s_currentTabulationColumn;
// not sure about this one
static int s_ignoreCarriageReturns;

static void flushStInOutPut() {
    psxclose(0);
    psxclose(1);
    int r = psxopen("tty00:", 1);
    if (r == 0) {
        psxopen("tty00:", 2);
    }
}

void installStdIo(int installTTY) {
    POST = 3;
    s_currentTabulationColumn = 0;
    s_ignoreCarriageReturns = 0;
    removeDevice("tty");
    POST = 4;
    if (installTTY == 0) {
        syscall_addDummyConsoleDevice();
    } else if (installTTY == 1) {
        syscall_addConsoleDevice();
    } else {
        return;
    }

    POST = 5;

    POST = 6;
}

int psxopen(const char * name, int mode) {
    struct File * file = findEmptyFile();

    char * filename;
    int deviceId;
    struct Device * device;

    if (!file) {
        // technically, this isn't reachable, as ioabort isn't supposed
        // to return, but if someone overrides syscall_ioabort with
        // something else, then it could still happen.
        psxerrno = PSXEMFILE;
        return -1;
    }
}

int psxlseek(int fd, int offset, int whence) {
    struct File * file = getFileFromHandle(fd);
    if (!file || !file->flags) {
        psxerrno = PSXEBADF;
        return -1;
    }

    switch(whence) {
        case 0:
            file->offset = offset;
            break;
        case 1:
            file->offset += offset;
            break;
        case 2:
            break;
        default:
            syscall_printf("invalid lseek arg");
            file->errno = psxerrno = PSXEINVAL;
            return -1;
    }
    return file->offset;
}

int psxread(int fd, void * buffer, int size) {
    struct File * file = getFileFromHandle(fd);
    if (!file || file->flags == 0) {
        psxerrno = PSXEBADF;
        return -1;
    }

    cdevscan();

    int ret;

    if (file->deviceFlags & 0x10) {
        ret = file->device->read(file, buffer, size);
    } else {
        struct Device * device = file->device;
        file->buffer = buffer;
        file->count = size;
        if (device->flags & 4) {
            int blockSize = device->blockSize;
            if (file->offset % blockSize) {
                syscall_printf("offset not on block boundary");
                return -1;
            }
            file->count /= blockSize;
        }
        ret = device->action(file, PSXREAD);
        if (ret > 0) file->offset += ret;
    }

    if (ret < 0) {
        errno = file->errno;
    }

    return ret;}

int psxclose(int fd) {
    struct File * file = getFileFromHandle(fd);
    if (!file || !file->flags) {
        psxerrno = PSXEBADF;
        return -1;
    }
    int ret = file->device->close(file);
    file->flags = 0;
    if (ret != 0) {
        psxerrno = file->errno;
        return -1;
    }
    return fd;
}

static void xprintfcallback(const char * str, int size, void * dummy) {
    while (size--) syscall_putchar(*str++);
}

int psxprintf(const char * fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vxprintf(xprintfcallback, NULL, fmt, ap);
    va_end(ap);
}

void psxputchar(int c) {
    if (c == '\t') {
        do {
            psxputchar(' ');
        } while (s_currentTabulationColumn & 7);
    } else if (c == '\n') {
        psxputchar('\r');
        s_currentTabulationColumn = 0;
    } else {
        s_currentTabulationColumn++;
        psxwrite(1, &c, 1);
    }
}

int psxwrite(int fd, void * buffer, int size) {
    struct File * file = getFileFromHandle(fd);
    if (!file || file->flags == 0) {
        psxerrno = PSXEBADF;
        return -1;
    }

    cdevscan();

    int ret;

    if (file->deviceFlags & 0x10) {
        ret = file->device->write(file, buffer, size);
    } else {
        struct Device * device = file->device;
        file->buffer = buffer;
        file->count = size;
        if (device->flags & 4) {
            int blockSize = device->blockSize;
            if (file->offset % blockSize) {
                syscall_printf("offset not on block boundary");
                return -1;
            }
            file->count /= blockSize;
        }
        ret = device->action(file, PSXWRITE);
        if (ret > 0) file->offset += ret;
    }

    if (ret < 0) {
        errno = file->errno;
    }

    return ret;
}

int psxioctl(int fd, int cmd, int arg) {
    struct File * file = getFileFromHandle(fd);
    uint32_t flags;
    if (!file || !(flags = file->flags)) {
        psxerrno = PSXEBADF;
        return -1;
    }

    if (cmd == PSXFIOCNBLOCK) {
        if (arg == 0) {
            file->flags = flags & ~4;
        } else {
            file->flags = flags | 4;
        }
        return 1;
    }

    int ret = file->device->ioctl(file, cmd, arg);
    if (ret < 0) {
        psxerrno = file->errno;
        return 0;
    }
    return 1;
}
