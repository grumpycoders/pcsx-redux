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

#include "openbios/main/main.h"

#include <alloca.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>

#include "common/hardware/cop0.h"
#include "common/hardware/spu.h"
#include "common/kernel/openbios.h"
#include "common/psxlibc/handlers.h"
#include "common/psxlibc/setjmp.h"
#include "common/syscalls/syscalls.h"
#include "openbios/cdrom/cdrom.h"
#include "openbios/fileio/fileio.h"
#include "openbios/kernel/events.h"
#include "openbios/kernel/globals.h"
#include "openbios/kernel/handlers.h"
#include "openbios/kernel/libcmisc.h"
#include "openbios/kernel/psxexe.h"
#include "openbios/kernel/setjmp.h"
#include "openbios/kernel/threads.h"
#include "openbios/kernel/util.h"
#include "openbios/main/splash.h"
#include "openbios/pio/pio.h"
#include "openbios/shell/shell.h"
#include "openbios/tty/tty.h"

static void boot(char *systemCnfPath, char *binaryPath);

void bootThunk() {
#ifdef OPENBIOS_BOOT_MODE_NO_CDROM
    boot(NULL, NULL);
#else
    char binaryPath[80];
    char systemCnfPath[80];

    strcpy(systemCnfPath, "cdrom:");
    strcat(systemCnfPath, "SYSTEM.CNF;1");
    strcpy(binaryPath, "cdrom:");
    strcat(binaryPath, "PSX.EXE;1");
    boot(systemCnfPath, binaryPath);
#endif
}

int main() {
    // RAM size
    __globals60.ramsize = 0x02;
    // ??
    __globals60.unk1 = 0x00;
    // ??
    __globals60.unk2 = 0xff;

    POST = 0x0f;
    muteSpu();

    // Pre- and post-boot hooks are implemented in the retail BIOS through two
    // separate functions for each hook, one in charge of validating the
    // signature and the other actually jumping to the vector. For simplicity's
    // sake, both steps are combined into a call to a single function here. The
    // 573 kernel lacks these calls completely (rather than stubbing out the
    // function's body as done here).
    runExp1PreHook();
    POST = 0x0e;

    // Same as above, the retail BIOS lacks the drawSplashScreen() call
    // completely instead of merely stubbing out the function. Note that this
    // functionality is in no way 573-specific, so it makes sense to allow
    // enabling it regardless of the target platform.
    drawSplashScreen();
    g_installTTY = 0;
    bootThunk();
}

struct Configuration {
    int taskCount, eventsCount;
    void *stackBase;
};

static struct Configuration s_configuration;
extern const struct Configuration g_defaultConfiguration;

static void initHandlersArray(int priorities) {
    unsigned size = priorities * sizeof(struct HandlersStorage);
    struct HandlersStorage *ptr = syscall_kmalloc(size);
    if (!ptr) return;
    psxbzero(ptr, size);
    __globals.handlersArray = ptr;
    __globals.handlersArraySize = size;
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
    __builtin_unreachable();
}

static char s_binaryPath[128];

#define SETJMPFATAL(code)                             \
    {                                                 \
        if (psxsetjmp(&g_ioAbortJmpBuf)) fatal(code); \
    }

// The SYSTEM.CNF parser in the retail BIOS is hopelessly and
// irrevocably buggy. These bugs will not be reproduced here,
// because doing this sort of bugs on purpose would be, in fact
// a really difficult thing to do. So this parser is going to be
// a SYSTEM.CNF parser, but not the exact one from the retail bios.
// Specifically, the BOOT line parser will try to parse a command
// line argument. There are multiple ways this can happen on a
// retail bios, but this parser will chose to separate it using
// the tabulation character ('\t', or character 9) or a space.
// Last but not least, the retail bios will screw things up
// fairly badly if the file isn't terminated using CRLFs.
static void findWordItem(const char *systemCnf, void *item_, const char *name) {
    uint32_t *item = (uint32_t *)item_;
    char c;
    const unsigned size = strlen(name);
    while (strncmp(systemCnf, name, size) != 0) {
        while ((c = *systemCnf++)) {
            if (c == '\n') break;
            if (c == '\r') break;
        }
        if (!c) return;
    }

    systemCnf += size;
    while ((c = *systemCnf++)) {
        if (c == '=') break;
        if (!isspace(c)) return;
    }

    uint32_t value = 0;
    int started = 0;
    while (1) {
        c = *systemCnf++;
        if (isspace(c) && !started) continue;
        started = 1;
        if (isxdigit(c)) {
            value <<= 4;
            if (isdigit(c)) {
                value |= c - '0';
            } else {
                c = tolower(c);
                value |= c - 'a' + 10;
            }
        } else {
            if ((c == 0) || isspace(c)) {
                *item = value;
                psxprintf("%s\t%08x\n", name, value);
            }
            return;
        }
    }
}

static void findStringItem(const char *systemCnf, char *const binaryPath, char *const cmdLine, const char *const name) {
    char c;
    const unsigned size = strlen(name);
    while (strncmp(systemCnf, name, size) != 0) {
        while ((c = *systemCnf++)) {
            if (c == '\n') break;
            if (c == '\r') break;
        }
        if (!c) return;
    }

    systemCnf += size;
    while ((c = *systemCnf++)) {
        if (c == '=') break;
        if (!isspace(c)) return;
    }

    int parseArg = 0;
    char *binPtr = binaryPath;
    int started = 0;
    while (1) {
        c = *systemCnf++;
        if (isspace(c) && !started) continue;
        started = 1;
        if ((parseArg = (c == '\t') || (c == ' '))) break;
        if ((c == '\r') || (c == '\n') || (c == 0)) break;
        *binPtr++ = c;
    }
    *binPtr = 0;

    char *cmdPtr = cmdLine;
    while (parseArg) {
        c = *systemCnf++;
        if ((c == '\r') || (c == '\n') || (c == 0)) break;
        if ((cmdPtr - cmdLine) >= 0x7f) break;
        *cmdPtr++ = c;
    }
    *cmdPtr = 0;

    psxprintf("BOOT =\t%s\n", binaryPath);
    psxprintf("argument =\t%s\n", cmdLine);
}

static void loadSystemCnf(const char *systemCnf, struct Configuration *configuration, char *binaryPath) {
    memset(configuration, 0, sizeof(struct Configuration));
    *binaryPath = 0;
    char *cmdLine = (char *)0x180;

    *cmdLine = 0;
    findWordItem(systemCnf, &configuration->taskCount, "TCB");
    findWordItem(systemCnf, &configuration->eventsCount, "EVENT");
    findWordItem(systemCnf, &configuration->stackBase, "STACK");
    findStringItem(systemCnf, binaryPath, cmdLine, "BOOT");
}

#define HEAP_SIZE 0x2000
static uint8_t s_heap[HEAP_SIZE];

static void kernelSetup() {
    psxprintf("KERNEL SETUP!\n");
    syscall_kernInitheap(s_heap, HEAP_SIZE);

    initHandlersArray(4);
    syscall_enqueueSyscallHandler(0);
    syscall_enqueueIrqHandler(3);
    initEvents(s_configuration.eventsCount);
    initThreads(1, s_configuration.taskCount);
    syscall_enqueueRCntIrqs(1);
    initializeCDRomHandlersAndEvents();
}

void *__attribute__((long_call)) fastMemset(void *ptr, int value, size_t num);

static void zeroUserMemoryUntilStack() {
    uintptr_t stackPtr;
    __asm__ volatile("move %0, $sp" : "=r"(stackPtr));

    uintptr_t end = stackPtr & 0x3fffffff;
    fastMemset((void *)0xa0010000, 0, end - 0x10000);
}

static struct psxExeHeader s_binaryInfo;

// This is another horror. The location of this variable is technically
// 0xa000dffc, which is the upper part of the kernel memory section.
// It is however unset by the kernel itself, and written to directly
// by the shell. It'll be written to 1 by the shell before returning
// to the bios code. We'll just let it be set to 0, thus making
// the cdrom never being reset in the gameMainThunk function.
static int s_needsCDRomReset = 0;

void gameMainThunk(struct psxExeHeader *binaryInfo, int argc, char **argv) {
    leaveCriticalSection();
    if (s_needsCDRomReset) {
        if (cdromReadTOC() < 0) syscall_exception(0x44, 0x38b);
        if (cdromReset() < 0) syscall_exception(0x44, 0x38b);
    }
    enterCriticalSection();
    // Fixing SaGa Frontier (USA) when in fastboot mode, as it relies
    // on the side effect of the shell running to enable the display.
    GPU_STATUS = 0x03000000;
    exec(binaryInfo, argc, argv);
}

extern struct BuildId __build_id, __build_id_end;

static void boot(char *systemCnfPath, char *binaryPath) {
    POST = 1;
    writeCOP0Status(readCOP0Status() & ~0x401);
    muteSpu();
    POST = 2;
    // The 573 kernel kicks the watchdog before, after and in the middle of
    // copyDataAndInitializeBSS(), as it is by far the slowest part of the
    // initialization sequence. clearWatchdog() is an inline function that does
    // nothing in non-573 builds (see main.h).
    clearWatchdog();
    copyDataAndInitializeBSS();
    POST = 3;
    clearWatchdog();
    copyA0table();
    installKernelHandlers();
    syscall_patchA0table();
    // Even though we install the exception handler here, it won't be
    // working properly until we reach the initThreads call later.
    // If any exception or interrupt happens between these two calls,
    // things will go haywire very quickly.
    syscall_installExceptionHandler();
    syscall_setDefaultExceptionJmpBuf();
    POST = 4;
    muteSpu();
    IMASK = 0;
    IREG = 0;
    syscall_setupFileIO(g_installTTY);
    POST = 5;
    /* this is a bit specific to OpenBIOS to retrieve the buildid from the raw data */
    {
        char buildIDstring[65] = "unknown";
        if (&__build_id != &__build_id_end) {
            uint32_t count = __build_id.descsz;
            if (count > 32) count = 32;
            const uint8_t *buildId = __build_id.strings + __build_id.namesz;
            static const char *const hex = "0123456789abcdef";
            for (int i = 0; i < count; i++) {
                uint8_t c = buildId[i];
                buildIDstring[i * 2 + 0] = hex[c & 0xf];
                buildIDstring[i * 2 + 1] = hex[(c >> 4) & 0xf];
            }
            buildIDstring[count * 2] = 0;
        }
        psxprintf("PS-X Realtime Kernel OpenBios - build id %s.\nCopyright (C) 2019-2024 PCSX-Redux authors.\n",
                  buildIDstring);
    }
    POST = 6;
    muteSpu();
    s_configuration = g_defaultConfiguration;
    psxprintf("KERNEL SETUP!\n");
    syscall_kernInitheap(s_heap, HEAP_SIZE);
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

#ifndef OPENBIOS_BOOT_MODE_NO_CDROM
    POST = 8;
    IMASK = 0;
    IREG = 0;
    initCDRom();
    SETJMPFATAL(0x399);
    // See the note about hooks in main().
    runExp1PostHook();
    psxprintf("\nBOOTSTRAP LOADER\n");
    SETJMPFATAL(0x386);
    POST = 9;
    SETJMPFATAL(0x387);
    int fd = syscall_open(systemCnfPath, PSXF_READ);
    if (fd < 0) {
        SETJMPFATAL(0x391);
        *((uint32_t *)0x00000180) = 0;
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
            loadSystemCnf(g_readBuffer, &s_configuration, s_binaryPath);
        }
    }
    SETJMPFATAL(0x388);
    kernelSetup();
    psxprintf("boot file     : %s\n", s_binaryPath);
    SETJMPFATAL(0x389);
    zeroUserMemoryUntilStack();
    if (!loadExe(s_binaryPath, &s_binaryInfo)) fatal(0x38a);
    psxprintf("EXEC:PC0(%08x)  T_ADDR(%08x)  T_SIZE(%08x)\n", s_binaryInfo.pc, s_binaryInfo.text_addr,
              s_binaryInfo.text_size);
    psxprintf("boot address  : %08x %08x\nExecute !\n\n", s_binaryInfo.pc, s_configuration.stackBase);
    s_binaryInfo.stack_start = (uintptr_t)s_configuration.stackBase;
    s_binaryInfo.stack_size = 0;
    // the original format string says S_SIZE(%08), which is obviously wrong...
    psxprintf("                S_ADDR(%08x)  S_SIZE(%08x)\n", s_configuration.stackBase, 0);
    enterCriticalSection();
    SETJMPFATAL(0x38b);
    gameMainThunk(&s_binaryInfo, 1, NULL);
#endif

    psxprintf("End of Main\n");
    fatal(0x38c);
}

void setConfiguration(int eventsCount, int taskCount, void *stackBase) {
    s_configuration.taskCount = taskCount;
    s_configuration.eventsCount = eventsCount;
    s_configuration.stackBase = stackBase;
}

void getConfiguration(int *eventsCount, int *taskCount, void **stackBase) {
    *stackBase = s_configuration.stackBase;
    *eventsCount = s_configuration.eventsCount;
    *taskCount = s_configuration.taskCount;
}
