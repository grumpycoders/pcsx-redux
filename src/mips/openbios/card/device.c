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

static __attribute__((noreturn)) void buUnimplemented(const char *function, uint32_t ra) {
    osDbgPrintf("=== Unimplemented memory card function %s from %p ===\r\n", function, ra);
    osDbgPrintf("=== halting ===\r\n");
    pcsx_debugbreak();
    while (1)
        ;
}

static int buOpen(struct File *file, const char *filename) {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    buUnimplemented("mcOpen", ra);
}

static int buClose(struct File *file) {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    buUnimplemented("mcClose", ra);
}

static int buRead(struct File *file, void *buffer, int size) {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    buUnimplemented("mcRead", ra);
}

static int buWrite(struct File *file, void *buffer, int size) {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    buUnimplemented("mcWrite", ra);
}

static void buErase() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    buUnimplemented("mcErase", ra);
}

static void buUndelete() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    buUnimplemented("mcUndelete", ra);
}

static void buFirstFile() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    buUnimplemented("mcFirstFile", ra);
}

static void buNextFile() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    buUnimplemented("mcNextFile", ra);
}

static void buFormat() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    buUnimplemented("mcFormat", ra);
}

static void buRename() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    buUnimplemented("mcRename", ra);
}

static void buDeinit() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    buUnimplemented("mcDeinit", ra);
}

static const struct Device s_cardDevice = {
    .name = "bu",
    .flags = 0x14,
    .blockSize = 0x80,
    .desc = "MEMORY CARD",
    .init = psxdummy,
    .open = buOpen,
    .action = psxdummy,
    .close = buClose,
    .ioctl = psxdummy,
    .read = buRead,
    .write = buWrite,
    .erase = buErase,
    .undelete = buUndelete,
    .firstfile = buFirstFile,
    .nextfile = buNextFile,
    .format = buFormat,
    .chdir = psxdummy,
    .rename = buRename,
    .deinit = buDeinit,
    .check = psxdummy,
};

int addMemoryCardDevice() { return syscall_addDevice(&s_cardDevice); }
