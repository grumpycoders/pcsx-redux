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

#include "openbios/handlers/handlers.h"

#include <ctype.h>
#include <memory.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/hardware/pcsxhw.h"
#include "common/kernel/openbios.h"
#include "common/psxlibc/setjmp.h"
#include "common/psxlibc/stdio.h"
#include "common/syscalls/syscalls.h"
#include "openbios/card/card.h"
#include "openbios/cdrom/cdrom.h"
#include "openbios/cdrom/filesystem.h"
#include "openbios/cdrom/helpers.h"
#include "openbios/cdrom/statemachine.h"
#include "openbios/charset/sjis.h"
#include "openbios/fileio/fileio.h"
#include "openbios/gpu/gpu.h"
#include "openbios/kernel/alloc.h"
#include "openbios/kernel/events.h"
#include "openbios/kernel/flushcache.h"
#include "openbios/kernel/globals.h"
#include "openbios/kernel/handlers.h"
#include "openbios/kernel/libcmisc.h"
#include "openbios/kernel/misc.h"
#include "openbios/kernel/psxexe.h"
#include "openbios/kernel/setjmp.h"
#include "openbios/kernel/threads.h"
#include "openbios/main/main.h"
#include "openbios/patches/patches.h"
#include "openbios/sio0/card.h"
#include "openbios/sio0/pad.h"
#include "openbios/sio0/sio0.h"
#include "openbios/tty/tty.h"
#include "osdebug.h"

void unimplementedThunk() __attribute__((long_call));
void breakVector();
void exceptionVector();
void exceptionHandler();
void A0Vector();
void B0Vector();
void C0Vector();
void OBHandler();

static void __inline__ installHandler(const uint32_t *src, uint32_t *dst) {
    for (unsigned i = 0; i < 4; i++) dst[i] = src[i];
}

void installKernelHandlers() {
    installHandler((uint32_t *)A0Vector, (uint32_t *)0xa0);
    installHandler((uint32_t *)B0Vector, (uint32_t *)0xb0);
    installHandler((uint32_t *)C0Vector, (uint32_t *)0xc0);
}

void unimplemented(uint32_t table, uint32_t call, uint32_t ra) {
    struct Registers *regs = &__globals.threads[0].registers;
    uint32_t badv;
    asm("mfc0 %0, $8\nnop\n" : "=r"(badv));
    osDbgPrintf("=== Unimplemented %x:%x syscall from %p ===\r\n", table, call, ra);
    osDbgPrintf("epc = %p - status = %p - cause = %p - badv = %p\r\n", regs->returnPC, regs->SR, regs->Cause, badv);
    osDbgPrintf("r0 = %p - at = %p - v0 = %p - v1 = %p\r\n", regs->GPR.r[0], regs->GPR.r[1], regs->GPR.r[2],
                regs->GPR.r[3]);
    osDbgPrintf("a0 = %p - a1 = %p - a2 = %p - a3 = %p\r\n", regs->GPR.r[4], regs->GPR.r[5], regs->GPR.r[6],
                regs->GPR.r[7]);
    osDbgPrintf("t0 = %p - t1 = %p - t2 = %p - t3 = %p\r\n", regs->GPR.r[8], regs->GPR.r[9], regs->GPR.r[10],
                regs->GPR.r[11]);
    osDbgPrintf("t4 = %p - t5 = %p - t6 = %p - t7 = %p\r\n", regs->GPR.r[12], regs->GPR.r[13], regs->GPR.r[14],
                regs->GPR.r[15]);
    osDbgPrintf("s0 = %p - s1 = %p - s2 = %p - s3 = %p\r\n", regs->GPR.r[16], regs->GPR.r[17], regs->GPR.r[18],
                regs->GPR.r[19]);
    osDbgPrintf("s4 = %p - s5 = %p - s6 = %p - s7 = %p\r\n", regs->GPR.r[20], regs->GPR.r[21], regs->GPR.r[22],
                regs->GPR.r[23]);
    osDbgPrintf("t8 = %p - t9 = %p - k0 = %p - k1 = %p\r\n", regs->GPR.r[24], regs->GPR.r[25], regs->GPR.r[26],
                regs->GPR.r[27]);
    osDbgPrintf("gp = %p - sp = %p - s8 = %p - ra = %p\r\n", regs->GPR.r[28], regs->GPR.r[29], regs->GPR.r[30],
                regs->GPR.r[31]);
    osDbgPrintf("hi = %p - lo = %p\r\n", regs->GPR.r[32], regs->GPR.r[33]);
    osDbgPrintf("=== halting ===\r\n");
    pcsx_debugbreak();
    while (1)
        ;
}

static void installExceptionHandler() { installHandler((uint32_t *)exceptionVector, (uint32_t *)0x80); }

void __attribute__((noreturn)) returnFromException();

#define EXCEPTION_STACK_SIZE 0x800

static uint32_t s_exceptionStack[EXCEPTION_STACK_SIZE];
void *g_exceptionStackPtr = s_exceptionStack + EXCEPTION_STACK_SIZE;

struct JmpBuf *g_exceptionJmpBufPtr = NULL;
static struct JmpBuf defaultExceptionJmpBuf = {
    .ra = (uint32_t)returnFromException,
    .sp = (uint32_t)s_exceptionStack + EXCEPTION_STACK_SIZE,
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

static void setDefaultExceptionJmpBuf() { g_exceptionJmpBufPtr = &defaultExceptionJmpBuf; }

static void setExceptionJmpBuf(struct JmpBuf *jmpBup) { g_exceptionJmpBufPtr = jmpBup; }

extern void *__ramA0table[0xc0];
void *B0table[0x60];
void *C0table[0x20];

static void __inline__ subPatchA0table(int src, int dst, int len) {
    while (len--) __ramA0table[dst++] = B0table[src++];
}

static void patchA0table() {
    subPatchA0table(0x32, 0x00, 10);
    subPatchA0table(0x3c, 0x3b, 4);
    // marking OpenBIOS' entry point
    *((uintptr_t *)(__ramA0table + 11)) |= 1;
}

static void clearFileError(struct File *file) { file->errno = PSXENOERR; }

static void *getB0table();
static void *getC0table();

static __attribute__((section(".ramtext"))) void *wrapper_calloc(size_t nitems, size_t size) {
    uint8_t *ptr = user_malloc(nitems * size);
    syscall_memset(ptr, 0, nitems * size);
}

// clang-format off

static const void *romA0table[0xc0] = {
    unimplementedThunk, unimplementedThunk, unimplementedThunk, unimplementedThunk, // 00
    unimplementedThunk, unimplementedThunk, unimplementedThunk, unimplementedThunk, // 04
    unimplementedThunk, unimplementedThunk, psxtodigit, OBHandler /*atof*/, // 08
    strtol, strtol, psxabs, psxabs, // 0c
    atoi, atol, psxatob, psxsetjmp, // 10
    psxlongjmp, strcat, strncat, strcmp, // 14
    strncmp, strcpy, strncpy, strlen, // 18
    strchr, strrchr, strchr, strrchr, // 1c
    psxstrpbrk, psxstrspn, psxstrcspn, psxstrtok, // 20
    strstr, toupper, tolower, psxbcopy, // 24
    psxbzero, psxbcmp, memcpy, memset, // 28
    memmove, psxbcmp, memchr, psxrand, // 2c
    psxsrand, qsort, unimplementedThunk /*atof*/, user_malloc, // 30
    user_free, psxlsearch, psxbsearch, wrapper_calloc, // 34
    user_realloc, user_initheap, unimplementedThunk /*abort*/, unimplementedThunk, // 38
    unimplementedThunk, unimplementedThunk, unimplementedThunk, psxprintf, // 3c
    unimplementedThunk /*unresolved exception */, loadExeHeader, loadExe, exec, // 40
    flushCache, installKernelHandlers, GPU_dw, GPU_mem2vram, // 44
    GPU_send, GPU_cw, GPU_cwb, GPU_sendPackets, // 48
    GPU_abort, GPU_getStatus, GPU_sync, unimplementedThunk, // 4c
    unimplementedThunk, loadAndExec, unimplementedThunk, unimplementedThunk, // 50
    initCDRom, unimplementedThunk, deinitCDRom, psxdummy, // 54
    psxdummy, psxdummy, psxdummy, dev_tty_init, // 58
    dev_tty_open, dev_tty_action, dev_tty_ioctl, dev_cd_open, // 5c
    dev_cd_read, psxdummy, dev_cd_firstFile, dev_cd_nextFile, // 60
    dev_cd_chdir, dev_bu_open, dev_bu_read, dev_bu_write, // 64
    dev_bu_close, dev_bu_firstFile, dev_bu_nextFile, dev_bu_erase, // 68
    dev_bu_undelete, dev_bu_format, dev_bu_rename, clearFileError, // 6c
    initBackupUnit, initCDRom, deinitCDRom, unimplementedThunk, // 70
    psxdummy, psxdummy, psxdummy, psxdummy, // 74
    cdromSeekL, psxdummy, psxdummy, psxdummy, // 78
    cdromGetStatus, psxdummy, cdromRead, psxdummy, // 7c
    psxdummy, cdromSetMode, psxdummy, psxdummy, // 80
    psxdummy, psxdummy, psxdummy, psxdummy, // 84
    psxdummy, psxdummy, psxdummy, psxdummy, // 88
    psxdummy, psxdummy, psxdummy, psxdummy, // 8c
    cdromIOVerifier, cdromDMAVerifier, cdromIOHandler, cdromDMAVerifier, // 90
    getLastCDRomError, cdromInnerInit, addCDRomDevice, addMemoryCardDevice, // 94
    addConsoleDevice, addDummyConsoleDevice, unimplementedThunk, unimplementedThunk, // 98
    setConfiguration, getConfiguration, setCDRomIRQAutoAck, setMemSize, // 9c
    unimplementedThunk, unimplementedThunk, enqueueCDRomHandlers, dequeueCDRomHandlers, // a0
    unimplementedThunk, cdromBlockReading, cdromBlockGetStatus, buLowLevelOpCompleted, // a4
    buLowLevelOpError1, buLowLevelOpError2, buLowLevelOpError3, cardInfo, // a8
    buReadTOC, unimplementedThunk, unimplementedThunk, unimplementedThunk, // ac
    unimplementedThunk, unimplementedThunk, ioabortraw, unimplementedThunk, // b0
    unimplementedThunk, unimplementedThunk, unimplementedThunk, unimplementedThunk, // b4
    unimplementedThunk, unimplementedThunk, unimplementedThunk, unimplementedThunk, // b8
    unimplementedThunk, unimplementedThunk, unimplementedThunk, unimplementedThunk, // bc
};

void *B0table[0x60] = {
    kern_malloc, kern_free, initTimer, getTimer, // 00
    enableTimerIRQ, disableTimerIRQ, restartTimer, deliverEvent, // 04
    openEvent, closeEvent, waitEvent, testEvent, // 08
    enableEvent, disableEvent, openThread, closeThread, // 0c
    changeThread, unimplementedThunk, initPad, startPad, // 10
    stopPad, initPadHighLevel, readPadHighLevel, returnFromException, // 14
    setDefaultExceptionJmpBuf, setExceptionJmpBuf, unimplementedThunk, unimplementedThunk, // 18
    unimplementedThunk, unimplementedThunk, unimplementedThunk, unimplementedThunk, // 1c
    undeliverEvent, unimplementedThunk, unimplementedThunk, unimplementedThunk, // 20
    unimplementedThunk, unimplementedThunk, unimplementedThunk, unimplementedThunk, // 24
    unimplementedThunk, unimplementedThunk, unimplementedThunk, unimplementedThunk, // 28
    unimplementedThunk, unimplementedThunk, unimplementedThunk, unimplementedThunk, // 2c
    unimplementedThunk, unimplementedThunk, psxopen, psxlseek, // 30
    psxread, psxwrite, psxclose, psxioctl, // 34
    psxexit, isFileConsole, psxgetc, psxputc, // 38
    psxgetchar, psxputchar, psxgets, psxputs, // 3c
    unimplementedThunk, format, firstFile, nextFile, // 40
    unimplementedThunk, unimplementedThunk, unimplementedThunk, addDevice, // 44
    removeDevice, unimplementedThunk, initCard, startCard, // 48
    stopCard, cardInfoInternal, mcWriteSector, mcReadSector, // 4c
    mcAllowNewCard, Krom2RawAdd, unimplementedThunk, Krom2Offset, // 50
    unimplementedThunk, unimplementedThunk, getC0table, getB0table, // 54
    mcGetLastDevice, unimplementedThunk, unimplementedThunk, setSIO0AutoAck, // 58
    unimplementedThunk, unimplementedThunk, unimplementedThunk, unimplementedThunk, // 5c
};

void *C0table[0x20] = {
    enqueueRCntIrqs, enqueueSyscallHandler, sysEnqIntRP, sysDeqIntRP, // 00
    unimplementedThunk, getFreeTCBslot, exceptionHandler, installExceptionHandler, // 04
    kern_initheap, unimplementedThunk, setTimerAutoAck, unimplementedThunk, // 08
    enqueueIrqHandler, unimplementedThunk, unimplementedThunk, unimplementedThunk, // 0c
    unimplementedThunk, unimplementedThunk, setupFileIO, unimplementedThunk, // 10
    unimplementedThunk, unimplementedThunk, cdevscan, unimplementedThunk, // 14
    setupFileIO, unimplementedThunk, setDeviceStatus, unimplementedThunk, // 18
    patchA0table, getDeviceStatus, unimplementedThunk, unimplementedThunk, // 1c
};

// clang-format on

extern struct BuildId __build_id;

static uint32_t getOpenBiosApiVersionImpl() { return 0; }
static struct BuildId *getOpenBiosBuildIdImpl() { return &__build_id; }

void *OBtable[] = {
    getOpenBiosApiVersionImpl,
    getOpenBiosBuildIdImpl,
};

void *getB0table() {
    uint32_t ra;
    __asm__ volatile("move %0, $ra" : "=r"(ra));
    patch_hook((uint32_t *)ra, PATCH_TABLE_B0);
    return B0table;
}

void *getC0table() {
    uint32_t ra;
    __asm__ volatile("move %0, $ra" : "=r"(ra));
    patch_hook((uint32_t *)ra, PATCH_TABLE_C0);
    return C0table;
}

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
void copyA0table() { memcpy(&__ramA0table, romA0table, sizeof(romA0table)); }
