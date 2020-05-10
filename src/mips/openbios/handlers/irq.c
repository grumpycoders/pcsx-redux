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

#include <memory.h>
#include <stdint.h>

#include "common/hardware/hwregs.h"
#include "common/psxlibc/handlers.h"
#include "common/psxlibc/string.h"
#include "openbios/handlers/handlers.h"
#include "openbios/kernel/events.h"

static int s_IRQsAutoAck[11];

static __attribute__((section(".ramtext"))) int IRQVerifier(void) {
    // The original code does read IMASK and IREG for every if,
    // and recompute that same mask for every of them, which is
    // a big waste of cycles. Since IMASK and IREG are volatiles,
    // they can't be cached by the compiler, if this is what the
    // original author was thinking.
    uint32_t mask = IMASK & IREG;
    if ((mask & 0x004) != 0) deliverEvent(0xf0000003, 0x1000);
    if ((mask & 0x200) != 0) deliverEvent(0xf0000009, 0x1000);
    if ((mask & 0x002) != 0) deliverEvent(0xf0000002, 0x1000);
    if ((mask & 0x400) != 0) deliverEvent(0xf000000a, 0x1000);
    if ((mask & 0x100) != 0) deliverEvent(0xf000000b, 0x1000);
    if ((mask & 0x001) != 0) deliverEvent(0xf0000001, 0x1000);
    if ((mask & 0x010) != 0) deliverEvent(0xf0000005, 0x1000);
    if ((mask & 0x020) != 0) deliverEvent(0xf0000006, 0x1000); // Yes that's a copy-paste mistake from the BIOS code directly.
    if ((mask & 0x040) != 0) deliverEvent(0xf0000006, 0x1000); // Keeping it this way to avoid breaking stuff.
    if ((mask & 0x080) != 0) deliverEvent(0xf0000008, 0x1000);
    if ((mask & 0x008) != 0) deliverEvent(0xf0000004, 0x1000);
    uint32_t ackMask = 0;
    int * ptr = s_IRQsAutoAck;
    for (int IRQ = 0; IRQ < 11; IRQ++, ptr++) {
        if (*ptr) ackMask |= 1 << (IRQ & 0x1f);
    }
    IREG = ~ackMask;
    return 0;
}

static struct HandlerInfo s_IRQHandlerInfo = {
    .next = NULL,
    .handler = NULL,
    .verifier = IRQVerifier,
    .padding = 0,
};

int __attribute__((section(".ramtext"))) enqueueIrqHandler(int priority) {
    // this is technically memset, but I can't deal with the far jumps now.
    safeMemZero(s_IRQsAutoAck, sizeof(s_IRQsAutoAck));

    return sysEnqIntRP(priority, &s_IRQHandlerInfo);
}

static int s_timersAutoAck[4];

static __attribute__((section(".ramtext"))) int T0verifier() {
    if (((IMASK & 0x10) == 0) || ((IREG & 0x10) == 0)) return 0;
    deliverEvent(0xf2000000, 2);
    return 1;
}
static __attribute__((section(".ramtext"))) void T0handler(int v) {
    if (!s_timersAutoAck[0]) return;
    IREG = ~0x10;
    returnFromException();
}
static __attribute__((section(".ramtext"))) int T1verifier() {
    if (((IMASK & 0x20) == 0) || ((IREG & 0x20) == 0)) return 0;
    deliverEvent(0xf2000001, 2);
    return 1;

}
static __attribute__((section(".ramtext"))) void T1handler(int v) {
    if (!s_timersAutoAck[1]) return;
    IREG = ~0x20;
    returnFromException();
}
static __attribute__((section(".ramtext"))) int T2verifier() {
    if (((IMASK & 0x40) == 0) || ((IREG & 0x40) == 0)) return 0;
    deliverEvent(0xf2000002, 2);
    return 1;

}
static __attribute__((section(".ramtext"))) void T2handler(int v) {
    if (!s_timersAutoAck[2]) return;
    IREG = ~0x40;
    returnFromException();
}
static __attribute__((section(".ramtext"))) int T3verifier() {
    if (((IMASK & 0x80) == 0) || ((IREG & 0x80) == 0)) return 0;
    deliverEvent(0xf2000003, 2);
    return 1;
}
static __attribute__((section(".ramtext"))) void T3handler(int v) {
    if (!s_timersAutoAck[3]) return;
    IREG = ~0x80;
    returnFromException();
}

static struct HandlerInfo s_rcntHandlers[4] = {
    {
        .next = NULL,
        .handler = T0handler,
        .verifier = T0verifier,
        .padding = 0,
    },
    {
        .next = NULL,
        .handler = T1handler,
        .verifier = T1verifier,
        .padding = 0,
    },
    {
        .next = NULL,
        .handler = T2handler,
        .verifier = T2verifier,
        .padding = 0,
    },
    {
        .next = NULL,
        .handler = T3handler,
        .verifier = T3verifier,
        .padding = 0,
    },
};

int __attribute__((section(".ramtext"))) enqueueRCntIrqs(int priority) {
    int ret, i;

    IMASK &= ~0x71;
    for (i = 0; i < 4; i++) {
        s_timersAutoAck[i] = 1;
        ret = sysEnqIntRP(priority, &s_rcntHandlers[i]);
    }
    for (i = 0; i < 4; i++) {
        COUNTERS[i].mode = 0;
        COUNTERS[i].target = 0;
        COUNTERS[i].value = 0;
    }
    return ret;
}

int __attribute__((section(".ramtext"))) setTimerAutoAck(int timer, int value) {
    int old = s_timersAutoAck[timer];
    s_timersAutoAck[timer] = value;
    return old;
}
