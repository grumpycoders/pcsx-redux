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

#include "openbios/kernel/threads.h"

#include <stddef.h>
#include <stdint.h>

#include "common/syscalls/syscalls.h"
#include "openbios/fileio/fileio.h"
#include "openbios/kernel/globals.h"

int initThreads(int processCount, int threadCount) {
    psxprintf("TCB\t0x%02x\n", threadCount);
    int processBlockSize = processCount * sizeof(struct Process);
    __globals.processBlockSize = processBlockSize;

    struct Process *process = syscall_kmalloc(processBlockSize);
    if (!process) return 0;

    int threadBlockSize = threadCount * sizeof(struct Thread);
    __globals.threadBlockSize = threadBlockSize;

    struct Thread *threads = syscall_kmalloc(threadBlockSize);
    if (!threads) return 0;

    for (int i = 0; i < processCount; i++) {
        process[i].thread = 0;
    }

    for (int i = 0; i < threadCount; i++) {
        threads[i].flags = 0x1000;
    }
    threads[0].flags = 0x4000;
    process[0].thread = &threads[0];

    __globals.processes = process;
    __globals.threads = threads;

    return processBlockSize + threadBlockSize;
}

int getFreeTCBslot() {
    int maxThreadCount = __globals.threadBlockSize / sizeof(struct Thread);
    for (int i = 0; i < maxThreadCount; i++) {
        struct Thread *tcb = &__globals.threads[i];
        if (tcb->flags == 0x1000) {
            return i;
        }
    }
    return -1;
}

int openThread(uint32_t pc, uint32_t sp, uint32_t gp) {
    int slot = getFreeTCBslot();
    if (slot == -1) {
        return -1;
    }

    struct Thread *thread = &__globals.threads[slot];
    thread->flags = 0x4000;
    thread->flags2 = 0x1000;
    thread->registers.GPR.n.sp = sp;
    thread->registers.GPR.n.fp = sp;
    thread->registers.returnPC = pc;
    thread->registers.GPR.n.gp = gp;

    return slot | 0xff000000;
}

int closeThread(int threadId) {
    struct Thread *thread = &__globals.threads[threadId & 0xffff];
    thread->flags = 0x1000;
    return 1;
}

int changeThread(int threadId) { return changeThreadSubFunction((uint32_t)&__globals.threads[threadId & 0xffff]); }
