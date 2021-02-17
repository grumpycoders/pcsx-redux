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

#include <stddef.h>

#include "common/psxlibc/handlers.h"
#include "common/syscalls/syscalls.h"
#include "openbios/handlers/handlers.h"
#include "openbios/kernel/events.h"
#include "openbios/kernel/globals.h"
#include "openbios/kernel/threads.h"

static __attribute__((section(".ramtext"))) int syscallVerifier() {
    struct Thread* currentThread = __globals.processes[0].thread;
    unsigned exCode = currentThread->registers.Cause & 0x3c;
    switch (exCode) {
        case 0x00:
            return 0;
            break;
        case 0x20:  // syscall
            currentThread->registers.returnPC = currentThread->registers.returnPC + 4;
            switch (currentThread->registers.GPR.n.a0) {
                case 0:
                    break;
                case 1:  // enterCriticalSection
                    currentThread->registers.GPR.n.v0 = (currentThread->registers.SR & 0x404) == 0x404;
                    currentThread->registers.SR &= ~0x404;
                    break;
                case 2:  // leaveCriticalSection
                    currentThread->registers.SR |= 0x404;
                    break;
                case 3:
                    __globals.processes[0].thread = (struct Thread*)currentThread->registers.GPR.n.a1;
                    currentThread->registers.GPR.n.v0 = 1;
                    break;
                default:
                    deliverEvent(0xf0000010, 0x4000);
                    break;
            }
            returnFromException();
            break;
    }
    deliverEvent(0xf0000010, 0x1000);
    return syscall_unresolvedException();
}

static struct HandlerInfo s_defaultSyscallInfo = {
    .next = NULL,
    .handler = NULL,
    .verifier = syscallVerifier,
    .padding = 0,
};

int __attribute__((section(".ramtext"))) enqueueSyscallHandler(int priority) {
    return sysEnqIntRP(priority, &s_defaultSyscallInfo);
}
