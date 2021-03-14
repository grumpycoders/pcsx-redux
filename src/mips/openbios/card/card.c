/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

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

#include "openbios/card/card.h"

#include "common/hardware/pcsxhw.h"
#include "common/psxlibc/device.h"
#include "common/syscalls/syscalls.h"
#include "openbios/kernel/libcmisc.h"
#include "osdebug.h"

static __attribute__((noreturn)) void mcUnimplemented(const char *function, uint32_t ra) {
    osDbgPrintf("=== Unimplemented memory card function %s from %p ===\r\n", function, ra);
    osDbgPrintf("=== halting ===\r\n");
    pcsx_debugbreak();
    while (1)
        ;
}

static int mcOpen(struct File *file, const char *filename) {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    mcUnimplemented("mcOpen", ra);
}

static int mcClose(struct File *file) {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    mcUnimplemented("mcClose", ra);
}

static int mcRead(struct File *file, void *buffer, int size) {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    mcUnimplemented("mcRead", ra);
}

static int mcWrite(struct File *file, void *buffer, int size) {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    mcUnimplemented("mcWrite", ra);
}

static void mcErase() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    mcUnimplemented("mcErase", ra);
}

static void mcUndelete() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    mcUnimplemented("mcUndelete", ra);
}

static void mcFirstFile() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    mcUnimplemented("mcFirstFile", ra);
}

static void mcNextFile() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    mcUnimplemented("mcNextFile", ra);
}

static void mcFormat() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    mcUnimplemented("mcFormat", ra);
}

static void mcRename() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    mcUnimplemented("mcRename", ra);
}

static void mcDeinit() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    mcUnimplemented("mcDeinit", ra);
}

static const struct Device s_cardDevice = {
    .name = "bu",
    .flags = 0x14,
    .blockSize = 0x80,
    .desc = "MEMORY CARD",
    .init = psxdummy,
    .open = mcOpen,
    .action = psxdummy,
    .close = mcClose,
    .ioctl = psxdummy,
    .read = mcRead,
    .write = mcWrite,
    .erase = mcErase,
    .undelete = mcUndelete,
    .firstfile = mcFirstFile,
    .nextfile = mcNextFile,
    .format = mcFormat,
    .chdir = psxdummy,
    .rename = mcRename,
    .deinit = mcDeinit,
    .check = psxdummy,
};

int addMemoryCardDevice() { return syscall_addDevice(&s_cardDevice); }
