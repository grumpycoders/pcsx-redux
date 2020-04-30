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

int psxopen(const char * path, int mode) {
    struct File * file = findEmptyFile();

    const char * filename;
    int deviceId;
    struct Device * device;

    if (!file) {
        // technically, this isn't reachable, as ioabort isn't supposed
        // to return, but if someone overrides syscall_ioabort with
        // something else, then it could still happen.
        psxerrno = PSXEMFILE;
        return -1;
    }

    filename = splitFilepathAndFindDevice(path, &device, &deviceId);
    if (filename == ((char*)-1)) {
        psxerrno = PSXENODEV;
        // technically not needed, as the file never got effectively
        // opened, but doesn't really hurt at the end of the day.
        file->flags = 0;
        return -1;
    }

    file->flags = mode;
    file->deviceId = deviceId;
    file->device = device;
    file->deviceFlags = device->flags;
    if (device->open(file, filename) != 0) {
        psxerrno = file->errno;
        file->flags = 0;
        return -1;
    }

    file->offset = 0;
    return file->fd;
}

int psxlseek(int fd, int offset, int whence) {
    struct File * file = getFileFromHandle(fd);
    if (!file || !file->flags) {
        psxerrno = PSXEBADF;
        return -1;
    }

    switch(whence) {
        case PSXSEEK_SET:
            file->offset = offset;
            break;
        case PSXSEEK_CUR:
            file->offset += offset;
            break;
        case PSXSEEK_END:
            // yes, this is actually what the retail bios does.
            break;
        default:
            romsyscall_printf("invalid lseek arg");
            file->errno = psxerrno = PSXEINVAL;
            return -1;
    }
    return file->offset;
}

int psxread(int fd, void * buffer, int size) {
    struct File * file = getFileFromHandle(fd);
    if (!file || !file->flags) {
        psxerrno = PSXEBADF;
        return -1;
    }

    cdevscan();

    int ret;

    if (file->deviceFlags & PSXDTTYPE_FS) {
        ret = file->device->read(file, buffer, size);
    } else {
        struct Device * device = file->device;
        file->buffer = buffer;
        file->count = size;
        if (device->flags & PSXDTTYPE_BLOCK) {
            int blockSize = device->blockSize;
            if (file->offset % blockSize) {
                romsyscall_printf("offset not on block boundary");
                return -1;
            }
            file->count /= blockSize;
        }
        ret = device->action(file, PSXREAD);
        if (ret > 0) file->offset += ret;
    }

    if (ret < 0) errno = file->errno;

    return ret;
}

int psxwrite(int fd, void * buffer, int size) {
    struct File * file = getFileFromHandle(fd);
    if (!file || file->flags == 0) {
        psxerrno = PSXEBADF;
        return -1;
    }

    cdevscan();

    int ret;

    if (file->deviceFlags & PSXDTTYPE_FS) {
        ret = file->device->write(file, buffer, size);
    } else {
        struct Device * device = file->device;
        file->buffer = buffer;
        file->count = size;
        if (device->flags & PSXDTTYPE_BLOCK) {
            int blockSize = device->blockSize;
            if (file->offset % blockSize) {
                romsyscall_printf("offset not on block boundary");
                return -1;
            }
            file->count /= blockSize;
        }
        ret = device->action(file, PSXWRITE);
        if (ret > 0) file->offset += ret;
    }

    if (ret < 0) errno = file->errno;

    return ret;
}

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

    if (file->device->ioctl(file, cmd, arg) < 0) {
        psxerrno = file->errno;
        return 0;
    }
    return 1;
}

int psxgetc(int fd) {
    char c;
    if (psxread(fd, &c, 1) < 1) return -1;
    return c;
}

void psxputc(int c, int fd) {
    char ch = c;
    psxwrite(fd, &ch, 1);
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
        char ch = c;
        psxwrite(1, &ch, 1);
    }
}

int psxgetchar() {
    char b;
    read(0, &b, 1);
    return b & 0x7f;
}

/* This most likely is trying to do an 'echo' console back to whatever this
   is reading from, as if it's reading one character at a time from a terminal.
   It's doing a lot of terminal shenanigans. Whatever this terminal is, it
   also has a special meanings for the values 0x13, 0x16, and 0x7f. Also,
   it's sort of assuming a maximum buffer length. It's wild. */
char * psxgets(char * const s) {
    char c;
    char * ptr = s;
    char * const end = s + 125;
    while (1) {
        c = psxgetchar();
        if (c == '\b' || c == 0x7f) {
            if (ptr > s) {
                ptr--;
                // this tries to 'erase' the previously typed character
                // from the input terminal.
                psxputchar('\b');
                psxputchar(' ');
                psxputchar('\b');
                continue;
            }
        }
        if (c == '\t') c = ' '; // replace tabs by spaces, with no tabulation control...
        if ((c == '\n') || (c == '\r')) {
            psxputchar('\n');
            *ptr = 0;
            break; // sweet deliverance
        }
        if (c == 0x16) {
            c = psxgetchar();
            if (ptr < end) {
                *ptr++ = c;
                psxputchar(c);
            } else {
                psxputchar(7); // meep
            }
            continue;
        }
        if (iscntrl(c) || (ptr >= end)) {
            psxputchar(7); // meep
        } else {
            *ptr++ = c;
            psxputchar(c);
        }
    }
    return s;
}

void psxputs(const char * s) {
    if (!s) s = "<NULL>";
    char c;
    while ((c = *s++)) {
        psxputchar(c);
    }
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
