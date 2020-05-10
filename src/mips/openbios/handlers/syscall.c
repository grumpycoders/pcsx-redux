/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

#include <stddef.h>

#include "common/psxlibc/handlers.h"
#include "common/syscalls/syscalls.h"
#include "openbios/handlers/handlers.h"
#include "openbios/kernel/events.h"
#include "openbios/kernel/globals.h"
#include "openbios/kernel/threads.h"

static __attribute__((section(".ramtext"))) int syscallVerifier() {
    struct Thread ** blocks = __globals.blocks;
    struct Thread * currentThread = blocks[0];
    unsigned exCode = currentThread->registers.Cause & 0x3c;
    switch (exCode) {
        case 0x00:
            return 0;
            break;
        case 0x20: // syscall
            currentThread->registers.returnPC = currentThread->registers.returnPC + 4;
            switch (currentThread->registers.GPR.n.a0) {
                case 0:
                    break;
                case 1: // enterCriticalSection
                    currentThread->registers.GPR.n.v0 = (currentThread->registers.SR & 0x404) == 0x404;
                    currentThread->registers.SR &= ~0x404;
                    break;
                case 2: // leaveCriticalSection
                    currentThread->registers.SR |= 0x404;
                    break;
                case 3:
                    blocks[0] = (struct Thread *) currentThread->registers.GPR.n.a1;
                    currentThread->registers.GPR.n.v0 = 1;
                    break;
                default:
                    deliverEvent(0xf0000010,0x4000);
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
