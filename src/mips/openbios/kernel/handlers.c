/*

MIT License

Copyright (c) 2019 PCSX-Redux authors

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
#include <memory.h>
#include <stdlib.h>
#include <string.h>

#include "osdebug.h"

#include "common/compiler/stdint.h"
#include "common/hardware/pcsxhw.h"
#include "common/psxlibc/stdio.h"
#include "common/psxlibc/setjmp.h"
#include "common/syscalls/syscalls.h"
#include "openbios/cdrom/cdrom.h"
#include "openbios/cdrom/filesystem.h"
#include "openbios/cdrom/statemachine.h"
#include "openbios/fileio/fileio.h"
#include "openbios/gpu/gpu.h"
#include "openbios/handlers/handlers.h"
#include "openbios/kernel/events.h"
#include "openbios/kernel/flushcache.h"
#include "openbios/kernel/handlers.h"
#include "openbios/kernel/libcmisc.h"
#include "openbios/kernel/misc.h"
#include "openbios/kernel/psxexe.h"
#include "openbios/kernel/setjmp.h"
#include "openbios/kernel/threads.h"
#include "openbios/main/main.h"
#include "openbios/sio0/pad.h"
#include "openbios/sio0/sio0.h"
#include "openbios/tty/tty.h"

void unimplemented() __attribute__((long_call));
void breakVector();
void exceptionVector();
void A0Vector();
void B0Vector();
void C0Vector();

static void __inline__ installHandler(const uint32_t * src, uint32_t * dst) {
    for (int i = 0; i < 4; i++) dst[i] = src[i];
}

void installKernelHandlers() {
    installHandler((uint32_t*) A0Vector, (uint32_t *) 0xa0);
    installHandler((uint32_t*) B0Vector, (uint32_t *) 0xb0);
    installHandler((uint32_t*) C0Vector, (uint32_t *) 0xc0);
}

static void installExceptionHandler() {
    installHandler((uint32_t*) exceptionVector, (uint32_t *) 0x80);
}

void __attribute__((noreturn)) returnFromException();

#define EXCEPTION_STACK_SIZE 0x180

static uint32_t s_exceptionStack[EXCEPTION_STACK_SIZE];
void * g_exceptionStackPtr = s_exceptionStack + EXCEPTION_STACK_SIZE;

struct JmpBuf * g_exceptionJmpBufPtr = NULL;
static struct JmpBuf defaultExceptionJmpBuf = {
    .ra = (uint32_t) returnFromException,
    .sp = (uint32_t) s_exceptionStack + EXCEPTION_STACK_SIZE,
    .s8 = 0,
    .s0 = 0,
    .s1 = 0,
    .s2 = 0,
    .s3 = 0,
    .s4 = 0,
    .s5 = 0,
    .s6 = 0,
    .s7 = 0,
    .gp = 0,
};

static void setDefaultExceptionJmpBuf() {
    g_exceptionJmpBufPtr = &defaultExceptionJmpBuf;
}

static void setExceptionJmpBuf(struct JmpBuf * jmpBup) {
    g_exceptionJmpBufPtr = jmpBup;
}

extern void * __ramA0table[0xc0];
void * B0table[0x60];
void * C0table[0x20];

static void __inline__ subPatchA0table(int src, int dst, int len) {
    while (len--) __ramA0table[dst++] = B0table[src++];
}

static void patchA0table() {
    subPatchA0table(0x32, 0x00, 10);
    subPatchA0table(0x3c, 0x3b, 4);
}

static void clearFileError(struct File * file) { file->errno = PSXENOERR; }

static void * getB0table();
static void * getC0table();
static void dummyMC() { }

static const void * romA0table[0xc0] = {
    unimplemented, unimplemented, unimplemented, unimplemented, // 00
    unimplemented, unimplemented, unimplemented, unimplemented, // 04
    unimplemented, unimplemented, psxtodigit, unimplemented /*atof*/, // 08
    strtol, strtol, psxabs, psxabs, // 0c
    atoi, atol, psxatob, psxsetjmp, // 10
    psxlongjmp, strcat, strncat, strcmp, // 14
    strncmp, strcpy, strncpy, strlen, // 18
    strchr, strrchr, strchr, strrchr, // 1c
    psxstrpbrk, psxstrspn, psxstrcspn, psxstrtok, // 20
    strstr, toupper, tolower, psxbcopy, // 24
    psxbzero, psxbcmp, memcpy, memset, // 28
    memmove, psxbcmp, memchr, psxrand, // 2c
    psxsrand, qsort, unimplemented /*atof*/, base_malloc, // 30
    base_free, psxlsearch, psxbsearch, calloc, // 34
    realloc, psxdummy /*heapinit*/, unimplemented /*abort*/, unimplemented, // 38
    unimplemented, unimplemented, unimplemented, psxprintf, // 3c
    unimplemented /*unresolved exception */, loadExeHeader, loadExe, exec, // 40
    flushCache, installKernelHandlers, GPU_dw, GPU_mem2vram, // 44
    GPU_send, GPU_cw, GPU_cwb, GPU_sendPackets, // 48
    GPU_abort, GPU_getStatus, GPU_sync, unimplemented, // 4c
    unimplemented, loadAndExec, unimplemented, unimplemented, // 50
    initCDRom, unimplemented, deinitCDRom, psxdummy, // 54
    psxdummy, psxdummy, psxdummy, dev_tty_init, // 58
    dev_tty_open, dev_tty_action, dev_tty_ioctl, dev_cd_open, // 5c
    dev_cd_read, psxdummy, dev_cd_firstfile, dev_cd_nextfile, // 60
    dev_cd_chdir, unimplemented, unimplemented, unimplemented, // 64
    unimplemented, unimplemented, unimplemented, unimplemented, // 68
    unimplemented, unimplemented, unimplemented, clearFileError, // 6c
    dummyMC, initCDRom, deinitCDRom, psxdummy, // 70
    psxdummy, psxdummy, psxdummy, psxdummy, // 74
    cdromSeekL, psxdummy, psxdummy, psxdummy, // 78
    cdromGetStatus, psxdummy, cdromRead, psxdummy, // 7c
    psxdummy, cdromSetMode, psxdummy, psxdummy, // 80
    psxdummy, psxdummy, psxdummy, psxdummy, // 84
    psxdummy, psxdummy, psxdummy, psxdummy, // 88
    psxdummy, psxdummy, psxdummy, psxdummy, // 8c
    cdromIOVerifier, cdromDMAVerifier, cdromIOHandler, cdromDMAVerifier, // 90
    getLastCDRomError, cdromInnerInit, addCDRomDevice, dummyMC /* addMemoryCardDevice */, // 94
    addConsoleDevice, addDummyConsoleDevice, unimplemented, unimplemented, // 98
    setConfiguration, getConfiguration, setCDRomIRQAutoAck, setMemSize, // 9c
    unimplemented, unimplemented, enqueueCDRomHandlers, dequeueCDRomHandlers, // a0
    unimplemented, unimplemented, unimplemented, unimplemented, // a4
    unimplemented, unimplemented, unimplemented, unimplemented, // a8
    unimplemented, unimplemented, unimplemented, unimplemented, // ac
    unimplemented, unimplemented, ioabortraw, unimplemented, // b0
    unimplemented, unimplemented, unimplemented, unimplemented, // b4
    unimplemented, unimplemented, unimplemented, unimplemented, // b8
    unimplemented, unimplemented, unimplemented, unimplemented, // bc
};

void * B0table[0x60] = {
    malloc, free, unimplemented, unimplemented, // 00
    unimplemented, unimplemented, unimplemented, deliverEvent, // 04
    openEvent, closeEvent, waitEvent, testEvent, // 08
    enableEvent, disableEvent, openThread, closeThread, // 0c
    changeThread, unimplemented, initPad, startPad, // 10
    stopPad, initPadHighLevel, readPadHighLevel, returnFromException, // 14
    setDefaultExceptionJmpBuf, setExceptionJmpBuf, unimplemented, unimplemented, // 18
    unimplemented, unimplemented, unimplemented, unimplemented, // 1c
    undeliverEvent, unimplemented, unimplemented, unimplemented, // 20
    unimplemented, unimplemented, unimplemented, unimplemented, // 24
    unimplemented, unimplemented, unimplemented, unimplemented, // 28
    unimplemented, unimplemented, unimplemented, unimplemented, // 2c
    unimplemented, unimplemented, psxopen, psxlseek, // 30
    psxread, psxwrite, psxclose, psxioctl, // 34
    psxexit, isFileConsole, psxgetc, psxputc, // 38
    psxgetchar, psxputchar, psxgets, psxputs, // 3c
    unimplemented, unimplemented, unimplemented, unimplemented, // 40
    unimplemented, unimplemented, unimplemented, addDevice, // 44
    removeDevice, unimplemented, dummyMC, dummyMC, // 48
    unimplemented, unimplemented, unimplemented, unimplemented, // 4c
    unimplemented, unimplemented, unimplemented, unimplemented, // 50
    unimplemented, unimplemented, getC0table, getB0table, // 54
    unimplemented, unimplemented, unimplemented, setSIO0AutoAck, // 58
    unimplemented, unimplemented, unimplemented, unimplemented, // 5c
};

void * C0table[0x20] = {
    enqueueRCntIrqs, enqueueSyscallHandler, sysEnqIntRP, sysDeqIntRP, // 00
    unimplemented, getFreeTCBslot, unimplemented, installExceptionHandler, // 04
    unimplemented, unimplemented, setTimerAutoAck, unimplemented, // 08
    enqueueIrqHandler, unimplemented, unimplemented, unimplemented, // 0c
    unimplemented, unimplemented, setupFileIO, unimplemented, // 10
    unimplemented, unimplemented, unimplemented, unimplemented, // 14
    setupFileIO, unimplemented, unimplemented, unimplemented, // 18
    patchA0table, unimplemented, unimplemented, unimplemented, // 1c
};

void * getB0table() { return B0table; }
void * getC0table() { return C0table; }

/* This is technically all done by our crt0, but since there's
   logic that relies on this being a thing, we're repeating
   this code here too. We should have better code for these
   however, instead of memcpy and memset. */
extern uint32_t __data_start;
extern uint32_t __rom_data_start;
extern uint32_t __data_len;
extern uint32_t __bss_start;
extern uint32_t __bss_len;
void copyDataAndInitializeBSS() {
    /* This part is technically a chicken-and-egg problem.
       We can't rely on the code to already exist in RAM,
       so we have to do this in ROM, which will be slower. */
    memcpy(&__data_start, &__rom_data_start, __data_len);
    /* The original code does this step by jumping into 0x500.
       Likely the intend being that there's a faster memset at
       this location, for the specific purpose of handling
       a memset using the i-cache. We can tune this later. */
    memset(&__bss_start, 0, __data_len);
}

/* This also could be handled by the crt0, by putting the
   A0 table into the proper data section, but in the
   spirit of doing exactly what the original code does,
   we're going to do it manually instead. */
void copyA0table() {
    memcpy(&__ramA0table, romA0table, sizeof(romA0table));
}
