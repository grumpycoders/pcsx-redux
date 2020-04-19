/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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
#include <memory.h>
#include <stdlib.h>
#include <string.h>

#include "osdebug.h"

#include "common/compiler/stdint.h"
#include "common/psxlibc/stdio.h"
#include "common/psxlibc/setjmp.h"
#include "common/syscalls/syscalls.h"
#include "openbios/cdrom/cdrom.h"
#include "openbios/cdrom/filesystem.h"
#include "openbios/cdrom/statemachine.h"
#include "openbios/fileio/fileio.h"
#include "openbios/kernel/flushcache.h"
#include "openbios/kernel/handlers.h"
#include "openbios/kernel/libcmisc.h"
#include "openbios/kernel/psxexe.h"
#include "openbios/kernel/setjmp.h"
#include "openbios/main/main.h"
#include "openbios/gpu/gpu.h"
#include "openbios/tty/tty.h"

void unimplemented();
void breakVector();
void exceptionVector();
void A0Vector();
void B0Vector();
void C0Vector();

static void installHandler(const void * src, void * dst) {
    ((uint32_t *) dst)[0] = ((uint32_t *) src)[0];
    ((uint32_t *) dst)[1] = ((uint32_t *) src)[1];
    ((uint32_t *) dst)[2] = ((uint32_t *) src)[2];
    ((uint32_t *) dst)[3] = ((uint32_t *) src)[3];
}

void installKernelHandlers() {
    installHandler(A0Vector, (uint32_t *) 0xa0);
    installHandler(B0Vector, (uint32_t *) 0xb0);
    installHandler(C0Vector, (uint32_t *) 0xc0);
}

static void installExceptionHandler() {
    installHandler(exceptionVector, (uint32_t *) 0x80);
}

static void __attribute__((noreturn)) returnFromException() {

}

#define EXCEPTION_STACK_SIZE 0x40

static uint32_t s_exceptionStack[EXCEPTION_STACK_SIZE];

static struct JmpBuf * s_exceptionJmpBuf = NULL;
static struct JmpBuf defaultExceptionJmpBuf = {
    .ra = (uint32_t) returnFromException,
    .sp = (uint32_t) s_exceptionStack + EXCEPTION_STACK_SIZE * sizeof(uint32_t),
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

}

static void clearFileError(struct File * file) { file->errno = PSXENOERR; }

__attribute__((section(".a0table"))) void * A0table[0xc0] = {
    psxopen, psxlseek, psxread, psxwrite, // 00
    psxclose, psxioctl, psxexit, isFileConsole, // 04
    psxgetc, psxputc, psxtodigit, unimplemented /*atof*/, // 08
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
    realloc, psxdummy /*heapinit*/, unimplemented /*abort*/, psxgetchar, // 38
    psxputchar, psxgets, psxputs, psxprintf, // 3c
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
    unimplemented, initCDRom, deinitCDRom, psxdummy, // 70
    psxdummy, psxdummy, psxdummy, psxdummy, // 74
    cdromSeekL, psxdummy, psxdummy, psxdummy, // 78
    cdromGetStatus, psxdummy, cdromRead, psxdummy, // 7c
    psxdummy, cdromSetMode, psxdummy, psxdummy, // 80
    psxdummy, psxdummy, psxdummy, psxdummy, // 84
    psxdummy, psxdummy, psxdummy, psxdummy, // 88
    psxdummy, psxdummy, psxdummy, psxdummy, // 8c
    cdromIOVerifier, cdromDMAVerifier, cdromIOHandler, cdromDMAVerifier, // 90
    getLastCDRomError, cdromInnerInit, addCDRomDevice, unimplemented, // 94
    addConsoleDevice, addDummyConsoleDevice, unimplemented, unimplemented, // 98
    setConfiguration, getConfiguration, setCDRomIRQAutoAck, unimplemented, // 9c
    unimplemented, unimplemented, unimplemented, unimplemented, // a0
    unimplemented, unimplemented, unimplemented, unimplemented, // a4
    unimplemented, unimplemented, unimplemented, unimplemented, // a8
    unimplemented, unimplemented, unimplemented, unimplemented, // ac
    unimplemented, unimplemented, ioabortraw, unimplemented, // b0
    unimplemented, unimplemented, unimplemented, unimplemented, // b4
    unimplemented, unimplemented, unimplemented, unimplemented, // b8
    unimplemented, unimplemented, unimplemented, unimplemented, // bc
};

void *B0table[0x60] = {
    unimplemented, unimplemented, unimplemented, unimplemented, // 00
    unimplemented, unimplemented, unimplemented, unimplemented, // 04
    unimplemented, unimplemented, installExceptionHandler, unimplemented, // 08
    unimplemented, unimplemented, unimplemented, unimplemented, // 0c
    unimplemented, unimplemented, unimplemented, unimplemented, // 10
    unimplemented, unimplemented, unimplemented, unimplemented, // 14
    setDefaultExceptionJmpBuf, unimplemented, unimplemented, unimplemented, // 18
    unimplemented, unimplemented, unimplemented, unimplemented, // 1c
    unimplemented, unimplemented, unimplemented, unimplemented, // 20
    unimplemented, unimplemented, unimplemented, unimplemented, // 24
    unimplemented, unimplemented, unimplemented, unimplemented, // 28
    unimplemented, unimplemented, unimplemented, unimplemented, // 2c
    unimplemented, unimplemented, unimplemented, unimplemented, // 30
    unimplemented, unimplemented, unimplemented, unimplemented, // 34
    unimplemented, unimplemented, unimplemented, unimplemented, // 38
    unimplemented, psxputchar, unimplemented, unimplemented, // 3c
    unimplemented, unimplemented, unimplemented, unimplemented, // 40
    unimplemented, unimplemented, unimplemented, unimplemented, // 44
    unimplemented, unimplemented, unimplemented, unimplemented, // 48
    unimplemented, unimplemented, unimplemented, unimplemented, // 4c
    unimplemented, unimplemented, unimplemented, unimplemented, // 50
    unimplemented, unimplemented, unimplemented, unimplemented, // 54
    unimplemented, unimplemented, unimplemented, unimplemented, // 58
    unimplemented, unimplemented, unimplemented, unimplemented, // 5c
};

void * C0table[0x20] = {
    unimplemented, unimplemented, unimplemented, unimplemented, // 00
    unimplemented, unimplemented, unimplemented, unimplemented, // 04
    unimplemented, unimplemented, unimplemented, unimplemented, // 08
    unimplemented, unimplemented, unimplemented, unimplemented, // 0c
    unimplemented, unimplemented, unimplemented, unimplemented, // 10
    unimplemented, unimplemented, unimplemented, unimplemented, // 14
    setupFileIO, unimplemented, unimplemented, unimplemented, // 18
    unimplemented, unimplemented, unimplemented, unimplemented, // 1c
};

typedef struct {
    union {
        struct {
            uint32_t r0, at, v0, v1, a0, a1, a2, a3;
            uint32_t t0, t1, t2, t3, t4, t5, t6, t7;
            uint32_t s0, s1, s2, s3, s4, s5, s6, s7;
            uint32_t t8, t9, k0, k1, gp, sp, s8, ra;
            uint32_t lo, hi;
        } n;
        uint32_t r[34]; /* Lo, Hi in r[32] and r[33] */
    } GPR;
    uint32_t SR;
    uint32_t Cause;
    uint32_t EPC;
} InterruptData;

static void printInterruptData(InterruptData* data) {
    osDbgPrintf("epc = %p - status = %p - cause = %p\r\n", data->EPC, data->SR, data->Cause);
    osDbgPrintf("r0 = %p - at = %p - v0 = %p - v1 = %p\r\n", data->GPR.r[ 0], data->GPR.r[ 1], data->GPR.r[ 2], data->GPR.r[ 3]);
    osDbgPrintf("a0 = %p - a1 = %p - a2 = %p - a3 = %p\r\n", data->GPR.r[ 4], data->GPR.r[ 5], data->GPR.r[ 6], data->GPR.r[ 7]);
    osDbgPrintf("t0 = %p - t1 = %p - t2 = %p - t3 = %p\r\n", data->GPR.r[ 8], data->GPR.r[ 9], data->GPR.r[10], data->GPR.r[11]);
    osDbgPrintf("t4 = %p - t5 = %p - t6 = %p - t7 = %p\r\n", data->GPR.r[12], data->GPR.r[13], data->GPR.r[14], data->GPR.r[15]);
    osDbgPrintf("s0 = %p - s1 = %p - s2 = %p - s3 = %p\r\n", data->GPR.r[16], data->GPR.r[17], data->GPR.r[18], data->GPR.r[19]);
    osDbgPrintf("s4 = %p - s5 = %p - s6 = %p - s7 = %p\r\n", data->GPR.r[20], data->GPR.r[21], data->GPR.r[22], data->GPR.r[23]);
    osDbgPrintf("t8 = %p - t9 = %p - k0 = %p - k1 = %p\r\n", data->GPR.r[24], data->GPR.r[25], data->GPR.r[26], data->GPR.r[27]);
    osDbgPrintf("gp = %p - sp = %p - s8 = %p - ra = %p\r\n", data->GPR.r[28], data->GPR.r[29], data->GPR.r[30], data->GPR.r[31]);
    osDbgPrintf("hi = %p - lo = %p\r\n", data->GPR.r[32], data->GPR.r[33]);
}

void breakHandler(InterruptData* data) {
}

void exceptionHandler(InterruptData* data) {
    osDbgPrintf("***Exception***\r\n");
    printInterruptData(data);
}
