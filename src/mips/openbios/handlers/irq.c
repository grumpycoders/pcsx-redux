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

#include <memory.h>

#include "common/compiler/stdint.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/irq.h"
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
    if ((mask & IRQ_CDROM) != 0)      deliverEvent(EVENT_CDROM, 0x1000);
    if ((mask & IRQ_SPU) != 0)        deliverEvent(EVENT_SPU, 0x1000);
    if ((mask & IRQ_GPU) != 0)        deliverEvent(EVENT_GPU, 0x1000);
    if ((mask & IRQ_PIO) != 0)        deliverEvent(EVENT_PIO, 0x1000);
    if ((mask & IRQ_SIO) != 0)        deliverEvent(EVENT_SIO, 0x1000);
    if ((mask & IRQ_VBLANK) != 0)     deliverEvent(EVENT_VBLANK, 0x1000);
    if ((mask & IRQ_TIMER0) != 0)     deliverEvent(EVENT_RTC0, 0x1000);
    if ((mask & IRQ_TIMER1) != 0)     deliverEvent(EVENT_RTC1, 0x1000); // Yes that's a copy-paste mistake from the BIOS code directly.
    if ((mask & IRQ_TIMER2) != 0)     deliverEvent(EVENT_RTC1, 0x1000); // Keeping it this way to avoid breaking stuff.
    if ((mask & IRQ_CONTROLLER) != 0) deliverEvent(EVENT_CONTROLLER, 0x1000);
    if ((mask & IRQ_DMA) != 0)        deliverEvent(EVENT_DMA, 0x1000);
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
    if (((IMASK & IRQ_TIMER0) == 0) || ((IREG & IRQ_TIMER0) == 0)) return 0;
    deliverEvent(0xf2000000, 2);
    return 1;
}
static __attribute__((section(".ramtext"))) void T0handler(int v) {
    if (!s_timersAutoAck[0]) return;
    IREG = ~IRQ_TIMER0;
    returnFromException();
}
static __attribute__((section(".ramtext"))) int T1verifier() {
    if (((IMASK & IRQ_TIMER1) == 0) || ((IREG & IRQ_TIMER1) == 0)) return 0;
    deliverEvent(0xf2000001, 2);
    return 1;

}
static __attribute__((section(".ramtext"))) void T1handler(int v) {
    if (!s_timersAutoAck[1]) return;
    IREG = ~IRQ_TIMER1;
    returnFromException();
}
static __attribute__((section(".ramtext"))) int T2verifier() {
    if (((IMASK & IRQ_TIMER2) == 0) || ((IREG & IRQ_TIMER2) == 0)) return 0;
    deliverEvent(0xf2000002, 2);
    return 1;
}
static __attribute__((section(".ramtext"))) void T2handler(int v) {
    if (!s_timersAutoAck[2]) return;
    IREG = ~IRQ_TIMER2;
    returnFromException();
}
static __attribute__((section(".ramtext"))) int T3verifier() {
    if (((IMASK & IRQ_VBLANK) == 0) || ((IREG & IRQ_VBLANK) == 0)) return 0;
    deliverEvent(0xf2000003, 2);
    return 1;
}
static __attribute__((section(".ramtext"))) void T3handler(int v) {
    if (!s_timersAutoAck[3]) return;
    IREG = ~IRQ_VBLANK;
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

    IMASK &= ~(IRQ_VBLANK | IRQ_TIMER0 | IRQ_TIMER1 | IRQ_TIMER2);
    for (i = 0; i < 4; i++) {
        s_timersAutoAck[i] = 1;
        ret = sysEnqIntRP(priority, &s_rcntHandlers[i]);
    }
    for (i = 0; i < 3; i++) {
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
