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

#include "openbios/tty/tty.h"

#include <stddef.h>

#include "common/compiler/stdint.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/util.h"
#include "common/psxlibc/circularbuffer.h"
#include "common/psxlibc/ioctl.h"
#include "common/psxlibc/stdio.h"
#include "common/syscalls/syscalls.h"
#include "openbios/kernel/libcmisc.h"

#ifdef OPENBIOS_INSTALL_TTY_CONSOLE
#define DEFAULT_TTY_INSTALL 1
#else
#define DEFAULT_TTY_INSTALL 0
#endif

int g_cachedInstallTTY;
int g_installTTY = DEFAULT_TTY_INSTALL;

static const struct Device s_ttyDevice = {
    .name = "tty",
    .flags = 3,
    .blockSize = 1,
    .desc = "CONSOLE",
    .init = dev_tty_init,
    .open = dev_tty_open,
    .action = dev_tty_action,
    .close = psxdummy,
    .ioctl = dev_tty_ioctl,
    .read = psxdummy,
    .write = psxdummy,
    .erase = psxdummy,
    .undelete = psxdummy,
    .firstFile = psxdummy,
    .nextFile = psxdummy,
    .format = psxdummy,
    .chdir = psxdummy,
    .rename = psxdummy,
    .deinit = psxdummy,
    .check = psxdummy,
};

int addConsoleDevice() { return syscall_addDevice(&s_ttyDevice); }

static const struct Device s_dummyDevice = {
    .name = "tty",
    .flags = 1,
    .blockSize = 1,
    .desc = "CONSOLE",
    .init = psxdummy,
    .open = psxdummy,
    .action = psxdummy,
    .close = psxdummy,
    .ioctl = psxdummy,
    .read = psxdummy,
    .write = psxdummy,
    .erase = psxdummy,
    .undelete = psxdummy,
    .firstFile = psxdummy,
    .nextFile = psxdummy,
    .format = psxdummy,
    .chdir = psxdummy,
    .rename = psxdummy,
    .deinit = psxdummy,
    .check = psxdummy,
};

int addDummyConsoleDevice() { return syscall_addDevice(&s_dummyDevice); }

static volatile uint8_t *s_atconsStatPtr;
static volatile uint8_t *s_atconsIRQPtr;
static struct CircularBuffer s_circ;

/* The following code is from the DTL-H2000 bios,
   instead of the retail bios, which is much more
   complex, and useless for the purpose of this project. */
void dev_tty_init() {
    s_atconsStatPtr = &ATCONS_STAT;
    ATCONS_IRQ2 &= 0xfe;
    s_atconsIRQPtr = &ATCONS_IRQ;
    flushWriteQueue();
    s_atconsIRQPtr[0] = 0x20;
    s_atconsIRQPtr[2] |= 0x10;
    flushWriteQueue();
    s_circ.start = s_circ.end = NULL;
}

int dev_tty_open(struct File *file, const char * filename, int mode) {
    POST = 0x0c;
    if (file->deviceId < 2) {
        file->flags |= PSXF_SCAN2;
        s_circ.start = s_circ.end = s_circ.buffer;
        return 0;
    } else {
        file->errno = PSXENXIO;
        return -1;
    }
}

static int ttyGetChar() {
    if ((*s_atconsStatPtr & 0x10) != 0) {
        int c = s_atconsStatPtr[2];
        s_atconsIRQPtr[0] = 0x20;
        s_atconsIRQPtr[2] |= 0x10;
        flushWriteQueue();
        return c | 0x100;
    }
    return 0;
}

static void ttyPutChar(int c) {
    while (s_circ.flags & PSXCIRC_STOPPED) syscall_cdevscan();
    while ((*s_atconsStatPtr & 8) == 0) syscall_cdevscan();
    s_atconsStatPtr[2] = c;
    s_atconsIRQPtr[2] |= 0x10;
    flushWriteQueue();
}

int dev_tty_action(struct File *file, enum FileAction action) {
    int count = file->count;
    switch (action) {
        case PSXREAD:
            while (count > 0) {
                int c;
                while ((c = ttyGetChar())) syscall_cdevinput(&s_circ, c);
                if (((file->flags & PSXF_NBLOCK) == 0) && (s_circ.start == s_circ.end)) {
                    do {
                        syscall_cdevscan();
                    } while (s_circ.start == s_circ.end);
                }
                if (s_circ.start == s_circ.end) return count - file->count;
                *file->buffer++ = syscall_circgetc(&s_circ);
                count = --file->count;
            }
            break;
        case PSXWRITE:
            if ((file->flags & PSXF_WRITE) != 0) {
                while (count > 0) {
                    ttyPutChar(*file->buffer++);
                    count = file->count--;
                }
                break;
            }
        default:
            count = syscall_ioabort("tty(atcons) bad function");
            break;
    }
    return count;
}

int dev_tty_ioctl(struct File *file, int req, int arg) {
    char c;
    switch (req) {
        case PSXFIOCSCAN:
            while ((c = ttyGetChar())) syscall_cdevinput(&s_circ, c);
            break;
        case PSXTIOCRAW:
            if (arg) {
                s_circ.flags |= PSXCIRC_RAW;
            } else {
                s_circ.flags &= ~PSXCIRC_RAW;
            }
            break;
        case PSXTIOCFLUSH:
            s_circ.start = s_circ.end = s_circ.buffer;
            break;
        case PSXTIOCREOPEN:
            return dev_tty_open(file, (char *) 0x7403, arg);
            break;
        default:
            file->errno = PSXEINVAL;
            return -1;
            break;
    }
    return 0;
}
