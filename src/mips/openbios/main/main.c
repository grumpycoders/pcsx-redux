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

#include <string.h>

#include "common/hardware/cop0.h"
#include "common/hardware/spu.h"
#include "common/psxlibc/handlers.h"
#include "common/psxlibc/setjmp.h"
#include "common/syscalls/syscalls.h"
#include "openbios/cdrom/cdrom.h"
#include "openbios/fileio/fileio.h"
#include "openbios/kernel/events.h"
#include "openbios/kernel/handlers.h"
#include "openbios/kernel/libcmisc.h"
#include "openbios/kernel/psxexe.h"
#include "openbios/kernel/setjmp.h"
#include "openbios/kernel/threads.h"
#include "openbios/kernel/util.h"
#include "openbios/main/main.h"
#include "openbios/pio/pio.h"
#include "openbios/shell/shell.h"
#include "openbios/tty/tty.h"

static void boot(const char * systemCnfPath, const char * binaryPath);

int main() {
    // RAM size
    *((uint32_t*) 0x60) = 0x02;
    // ??
    *((uint32_t*) 0x64) = 0x00;
    // ??
    *((uint32_t*) 0x68) = 0xff;

    POST = 0x0f;
    muteSpu();

    if (checkExp1PreHookLicense()) runExp1PreHook();
    POST = 0x0e;
    g_installTTY = 0;
    boot("cdrom:SYSTEM.CNF;1", "cdrom:PSX.EXE;1");
}

struct Configuration {
    int taskCount, eventsCount;
    void * stackBase;
};

static struct Configuration s_configuration;
extern const struct Configuration g_defaultConfiguration;

static void initHandlersArray(int priorities) {
    struct HandlerInfo ** array = (struct HandlerInfo **) 0xa0000100;
    unsigned size = priorities * sizeof(struct HandlerInfo);
    struct HandlerInfo * ptr = syscall_kmalloc(size);
    if (!ptr) return;
    psxbzero(ptr, size);
    *array = ptr;
    (*(unsigned *)0xa0000104) = size;
}

struct JmpBuf g_ioAbortJmpBuf;

// There's a sort of a flaw here. The exception syscall can be overriden,
// and there's sections of the cdrom code that expects it to be able to
// return. Therefore, syscall_exception isn't flagged as noreturn, but
// this one is, because the code in boot() and Main() aren't expecting it
// to return at all. At the end of the day, I think the cdrom code is
// being too defensive in how this behaves, and syscall_exception ought
// to be flagged noreturn.
static __attribute__((noreturn)) void fatal(int code) {
    POST = 0x0f;
    syscall_exception(0x42, code);
}

static char s_binaryPath[128];

#define SETJMPFATAL(code) { if (psxsetjmp(&g_ioAbortJmpBuf)) fatal(code); }

static void loadSystemCnf(const char * systemCnf, struct Configuration * configuration, const char * binaryPath) { }

static void kernelSetup() { }

static void zeroUserMemoryUntilStack() { }

static struct psxExeHeader s_binaryInfo;

// never written to...?
static int s_needsCDRomReset;

void gameMainThunk(struct psxExeHeader * binaryInfo, int argc, char **argv) {
    leaveCriticalSection();
    if (s_needsCDRomReset) {
        if (cdromReadTOC() < 0) syscall_exception(0x44, 0x38b);
        if (cdromReset() < 0) syscall_exception(0x44, 0x38b);
    }
    enterCriticalSection();
    exec(binaryInfo, argc, argv);
}

static void boot(const char * systemCnfPath, const char * binaryPath) {
    POST = 0x01;
    writeCOP0Status(readCOP0Status() & ~0x401);
    muteSpu();
    POST = 0x02;
    /* Here, the retail bios does something along the lines of
       copyDataAndInitializeBSS(), but our crt0 already took
       care of it for us. */
    // copyDataAndInitializeBSS();
    POST = 0x03;
    /* Same punishment as above: the retail bios copies the A0 table
       at this point, but our crt0 did it too, as it's part of our data
       section. */
    // copyA0table();
    installKernelHandlers();
    /* The next call is supposed to be the c0/1c syscall, which patches
       in the stdio functions from the C0 table into the A0 one.
       We're not doing this either. */
    // syscall_patchA0table();
    syscall_installExceptionHandler();
    syscall_setDefaultExceptionJmpBuf();
    POST = 0x04;
    muteSpu();
    IMASK = 0;
    IREG = 0;
    syscall_setupFileIO(g_installTTY);
    POST = 5;
    psxprintf("PS-X Realtime Kernel OpenBios version.\nCopyright 2019-2020 (C) PCSX-Redux authors.\n");
    POST = 6;
    muteSpu();
    s_configuration = g_defaultConfiguration;
    psxprintf("KERNEL SETUP!\n");
    // syscall_sysInitMemory(&heapBase, heapSize);
    initHandlersArray(4);
    syscall_enqueueSyscallHandler(0);
    syscall_enqueueIrqHandler(3);
    initEvents(s_configuration.eventsCount);
    initThreads(1, s_configuration.taskCount);
    syscall_enqueueRCntIrqs(1);
    muteSpu();
    SETJMPFATAL(0x385);
    POST = 7;
    // There's an obvious mistake here in the code.
    // startShell is called without an argument from this function,
    // but startShell is taking care of saving $a0 and passing it
    // down to the shell when calling it.
    // As a result, in the retail bios, the static value that's
    // always passed down to the shell is 0x07, due to the POST
    // set just above, and the way this is deterministic.
    startShell(7);
    POST = 8;
    IMASK = 0;
    IREG = 0;
    initCDRom();
    SETJMPFATAL(0x399);
    if (checkExp1PostHookLicense()) runExp1PostHook();
    psxprintf("\nBOOTSTRAP LOADER\n");
    SETJMPFATAL(0x386);
    POST = 9;
    SETJMPFATAL(0x387);
    int fd = syscall_open(systemCnfPath, PSXF_READ);
    if (fd < 0) {
        SETJMPFATAL(0x391);
        *((uint32_t*) 0x00000180) = 0;
        s_configuration = g_defaultConfiguration;
        strcpy(s_binaryPath, binaryPath);
    } else {
        psxprintf("setup file    : %s\n", systemCnfPath);
        SETJMPFATAL(0x38f);
        int sysCnfSize = syscall_read(fd, g_readBuffer, 2048);
        if (sysCnfSize == 0) {
            s_configuration = g_defaultConfiguration;
            strcpy(s_binaryPath, binaryPath);
        } else {
            g_readBuffer[sysCnfSize] = 0;
            syscall_close(fd);
            SETJMPFATAL(0x390);
            loadSystemCnf(g_readBuffer, &s_configuration, binaryPath);
        }
    }
    SETJMPFATAL(0x388);
    kernelSetup();
    psxprintf("boot file     : %s\n", binaryPath);
    SETJMPFATAL(0x389);
    zeroUserMemoryUntilStack();
    if (!loadExe(binaryPath, &s_binaryInfo)) fatal(0x38a);
    psxprintf("EXEC:PC0(%08x)  T_ADDR(%08x)  T_SIZE(%08x)\n", s_binaryInfo.pc, s_binaryInfo.text_addr, s_binaryInfo.text_size);
    psxprintf("boot address  : %08x %08x\nExecute !\n\n", s_binaryInfo.pc, s_configuration.stackBase);
    s_binaryInfo.stack_start = s_configuration.stackBase;
    s_binaryInfo.stack_size = 0;
    psxprintf("                S_ADDR(%08x)  S_SIZE(%08)\n", s_configuration.stackBase, 0);
    enterCriticalSection();
    SETJMPFATAL(0x38b);
    gameMainThunk(&s_binaryInfo, 1, NULL);
    psxprintf("End of Main\n");
    fatal(0x38c);
}

void setConfiguration(int eventsCount, int taskCount, void * stackBase) {
    s_configuration.taskCount = taskCount;
    s_configuration.eventsCount = eventsCount;
    s_configuration.stackBase = stackBase;
}

void getConfiguration(int * eventsCount, int * taskCount, void ** stackBase) {
    *stackBase = s_configuration.stackBase;
    *eventsCount = s_configuration.eventsCount;
    *taskCount = s_configuration.taskCount;
}
