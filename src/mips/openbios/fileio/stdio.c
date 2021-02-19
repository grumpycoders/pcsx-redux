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
#include <stdarg.h>
#include <stdio.h>

#include "common/hardware/hwregs.h"
#include "common/psxlibc/ioctl.h"
#include "common/syscalls/syscalls.h"
#include "openbios/fileio/fileio.h"

static int s_currentTabulationColumn;
// not sure about this one
static int s_ignoreCarriageReturns;

void reopenStdio() {
    psxclose(0);
    psxclose(1);
    int r = psxopen("tty00:", PSXF_READ);
    if (r == 0) {
        psxopen("tty00:", PSXF_WRITE);
    }
}

void installStdIo(int installTTY) {
    POST = 3;
    s_currentTabulationColumn = 0;
    s_ignoreCarriageReturns = 0;
    removeDevice("tty");
    POST = 4;
    switch (installTTY) {
        case 0:
            syscall_addDummyConsoleDevice();
            break;
        case 1:
            syscall_addConsoleDevice();
            break;
        default:
            return;
    }
    POST = 5;
    reopenStdio();
    POST = 6;
}

int psxopen(const char* path, int mode) {
    struct File* file = findEmptyFile();

    const char* filename;
    int deviceId;
    struct Device* device;

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
    struct File* file = getFileFromHandle(fd);
    if (!file || !file->flags) {
        psxerrno = PSXEBADF;
        return -1;
    }

    switch (whence) {
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

int psxread(int fd, void* buffer, int size) {
    struct File* file = getFileFromHandle(fd);
    if (!file || !file->flags) {
        psxerrno = PSXEBADF;
        return -1;
    }

    cdevscan();

    int ret;

    if (file->deviceFlags & PSXDTTYPE_FS) {
        ret = file->device->read(file, buffer, size);
    } else {
        struct Device* device = file->device;
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

    if (ret < 0) psxerrno = file->errno;

    return ret;
}

int psxwrite(int fd, void* buffer, int size) {
    struct File* file = getFileFromHandle(fd);
    if (!file || file->flags == 0) {
        psxerrno = PSXEBADF;
        return -1;
    }

    cdevscan();

    int ret;

    if (file->deviceFlags & PSXDTTYPE_FS) {
        ret = file->device->write(file, buffer, size);
    } else {
        struct Device* device = file->device;
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

    if (ret < 0) psxerrno = file->errno;

    return ret;
}

int psxclose(int fd) {
    struct File* file = getFileFromHandle(fd);
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
    struct File* file = getFileFromHandle(fd);
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
    psxread(0, &b, 1);
    return b & 0x7f;
}

/* This most likely is trying to do an 'echo' console back to whatever this
   is reading from, as if it's reading one character at a time from a terminal.
   It's doing a lot of terminal shenanigans. Whatever this terminal is, it
   also has a special meanings for the values 0x13, 0x16, and 0x7f. Also,
   it's sort of assuming a maximum buffer length. It's wild. */
char* psxgets(char* const s) {
    char c;
    char* ptr = s;
    char* const end = s + 125;
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
        if (c == '\t') c = ' ';  // replace tabs by spaces, with no tabulation control...
        if ((c == '\n') || (c == '\r')) {
            psxputchar('\n');
            *ptr = 0;
            break;  // sweet deliverance
        }
        if (c == 0x16) {
            c = psxgetchar();
            if (ptr < end) {
                *ptr++ = c;
                psxputchar(c);
            } else {
                psxputchar(7);  // meep
            }
            continue;
        }
        if (iscntrl(c) || (ptr >= end)) {
            psxputchar(7);  // meep
        } else {
            *ptr++ = c;
            psxputchar(c);
        }
    }
    return s;
}

void psxputs(const char* s) {
    if (!s) s = "<NULL>";
    char c;
    while ((c = *s++)) {
        psxputchar(c);
    }
}

static void xprintfcallback(const char* str, int size, void* dummy) {
    while (size--) syscall_putchar(*str++);
}

int psxprintf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vxprintf(xprintfcallback, NULL, fmt, ap);
    va_end(ap);
}
