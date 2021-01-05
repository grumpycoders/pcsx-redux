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

#include "common/psxlibc/string.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/irq.h"
#include "common/syscalls/syscalls.h"
#include "openbios/handlers/handlers.h"
#include "openbios/sio0/pad.h"

static int s_remove_ChgclrPAD = 0;
static int s_disable_slotChangeOnAbort = 0;
static int s_send_pad = 0;
void patch_remove_ChgclrPAD() { s_remove_ChgclrPAD = 1; }
void patch_disable_slotChangeOnAbort() { s_disable_slotChangeOnAbort = 1; }
void patch_send_pad() { s_send_pad = 1; }

static int s_padStarted;

void patch_startPad() { s_padStarted = 1; }
void patch_stopPad() { s_padStarted = 0; }

// this is the first time in this code I see a variable that
// requires static initialization.
static int s_cardStarted = 0;

static uint8_t * s_padBufferPtrs[2];
static size_t s_padBufferSizes[2];

struct HandlerInfo g_sio0HandlerInfo;

static int s_padAutoAck;

int __attribute__((section(".ramtext"))) setSIO0AutoAck(int value) {
    int ret = s_padAutoAck;
    s_padAutoAck = value;
    return ret;
}

void busyloop(int count);

/* A lot of the code in the readPad function is horrifyingly nonsensical.
   There's constructs that I can hypothetically reproduce in plain-C,
   but the compiler will throw tentrums at me. This code keeps dereferring
   pointers before verifying they are null or not. Also does
   complex pointer arithmetics to compute simple booleans that are
   readily available. So the end result is that this looks a bit
   different than the original, mainly because modern compilers
   won't allow me to do otherwise, with good reasons. */

/* The following is effectively unused anyway, always set to NULL,
   which will actively result in NULL pointer dereferences all around
   in the retail code. Ugh. */
static uint8_t * s_padOutputBuffers[2];
static size_t s_padOutputSizes[2];
void __attribute__((section(".ramtext"))) patch_setPadOutputData(uint8_t * pad1OutputBuffer, size_t pad1OutputSize, uint8_t * pad2OutputBuffer, size_t pad2OutputSize) {
    s_padOutputBuffers[0] = pad1OutputBuffer;
    s_padOutputBuffers[1] = pad2OutputBuffer;
    s_padOutputSizes[0] = pad1OutputSize;
    s_padOutputSizes[1] = pad2OutputSize;
}

static uint32_t s_padMask;

static void __attribute__((section(".ramtext"))) padAbort(int pad) {
    uint8_t ** padBufferPtr = &s_padBufferPtrs[pad];
    uint8_t * padBuffer = *padBufferPtr;
    padBuffer[0] = 0xff;

    if (s_disable_slotChangeOnAbort) {
        SIOS[0].ctrl = pad ? 0x2002 : 0x0002;
        busyloop(10);
    }
    SIOS[0].ctrl = 0;
}

static uint32_t __attribute__((section(".ramtext"))) readPad(int pad) {
    uint8_t ** padBufferPtr = &s_padBufferPtrs[pad];
    uint8_t * padBuffer = *padBufferPtr;
    padBuffer[0] = 0xff;
    uint16_t mask = pad == 0 ? 0x0000 : 0x2000;
    SIOS[0].ctrl = mask | 2;
    uint8_t * padOutputBuffer = s_padOutputBuffers[pad]; // always NULL
    // this test is reversed in retail; first dereference, then test for NULL
    int doPadOutput = padOutputBuffer && *padOutputBuffer ? -1 : 0;
    SIOS[0].fifo; // throw away
    busyloop(40);
    SIOS[0].ctrl = mask | 0x1003;
    while (!(SIOS[0].stat & 1));
    s_padMask = mask;
    SIOS[0].fifo = 1;
    busyloop(20);
    SIOS[0].ctrl |= 0x10;
    IREG = ~IRQ_CONTROLLER;
    while (!(SIOS[0].stat & 2));
    SIOS[0].fifo; // throw away
    busyloop(40);

    int cyclesWaited = 0;
    while (!(IREG & IRQ_CONTROLLER)) {
        if (cyclesWaited++ > 0x50) {
            padAbort(pad);
            return 0xffff; // is this return actually a int16_t maybe?
        }
    }

    SIOS[0].fifo = 0x42;
    busyloop(25);
    SIOS[0].ctrl |= 0x10;
    IREG = ~IRQ_CONTROLLER;

    while (!(SIOS[0].stat & 2));
    uint32_t fifoBytes = SIOS[0].fifo;
    padBuffer[1] = fifoBytes & 0xff;
    fifoBytes &= 0x0f;
    if (!fifoBytes) fifoBytes = 0x10;

    cyclesWaited = 0;
    while (!(IREG & IRQ_CONTROLLER)) {
        if (cyclesWaited++ > 0x50) {
            padAbort(pad);
            return 0xffff;
        }
    }

    SIOS[0].fifo = 0;
    busyloop(20);

    SIOS[0].ctrl |= 0x10;
    IREG = ~IRQ_CONTROLLER;

    while (!(SIOS[0].stat & 2));

    if (SIOS[0].fifo != 0x5a) {
        padAbort(pad);
        return 0xffff;
    }

    while (fifoBytes--) {
        cyclesWaited = 0;
        while (!(IREG & IRQ_CONTROLLER)) {
            if (cyclesWaited++ > 0x50) {
                padAbort(pad);
                return 0xffff;
            }
        }

        // Test is reversed in retail, resulting in reading pointer 0x0001 + 2 * n
        SIOS[0].fifo = s_send_pad ? doPadOutput & padOutputBuffer[1] : doPadOutput && padOutputBuffer[1];
        padOutputBuffer += 2;
        busyloop(10);
        SIOS[0].ctrl |= 0x10;
        IREG = ~IRQ_CONTROLLER;

        cyclesWaited = 0;
        while (!(SIOS[0].stat & 2)) {
            if (!(IREG & IRQ_CONTROLLER)) continue;
            while (!(SIOS[0].stat & 2));
            padAbort(pad);
            return 0xffff;
        }

        padBuffer[2] = SIOS[0].fifo;

        cyclesWaited = 0;
        while (!(IREG & IRQ_CONTROLLER)) {
            if (cyclesWaited++ > 0x50) {
                padAbort(pad);
                return 0xffff;
            }
        }

        // Test is reversed in retail, resulting in reading pointer 0x0002 + 2 * n
        SIOS[0].fifo = s_send_pad ? doPadOutput & padOutputBuffer[0] : doPadOutput && padOutputBuffer[0];
        busyloop(10);

        SIOS[0].ctrl |= 0x10;
        IREG = ~IRQ_CONTROLLER;

        while (!(SIOS[0].stat & 2));

        padBuffer[3] = SIOS[0].fifo;
        padBuffer += 2;
    }

    **padBufferPtr = 0;
    SIOS[0].ctrl = 0;

    return 0;
}

static void __attribute__((section(".ramtext"))) readCard() {}

static int __attribute__((section(".ramtext"))) sio0Verifier() {
    if (((IMASK & IRQ_VBLANK) == 0) || ((IREG & IRQ_VBLANK) == 0)) return 0;
    return 1;
}

static void __attribute__((section(".ramtext"))) sio0Handler(int v) {
    if (s_padStarted) {
        readPad(0);
        readPad(1);
        if (g_userPadBuffer) readPadHighLevel();
    }
    if (!s_remove_ChgclrPAD && s_padAutoAck) IREG = ~IRQ_VBLANK;
    if (s_cardStarted) readCard();
}

static void __attribute__((section(".ramtext"))) setupBasicSio0Handler() {
    g_sio0HandlerInfo.next = NULL;
    g_sio0HandlerInfo.handler = sio0Handler;
    g_sio0HandlerInfo.verifier = sio0Verifier;
    g_sio0HandlerInfo.padding = 0;
}

int __attribute__((section(".ramtext"))) initPad(uint8_t * pad1Buffer, size_t pad1BufferSize, uint8_t * pad2Buffer, size_t pad2BufferSize) {
    // *sigh*
    ramsyscall_printf("%s\n", "PS-X Control PAD Driver");
    g_userPadBuffer = NULL;
    s_padStarted = 0;
    patch_setPadOutputData(NULL, 0, NULL, 0);
    s_padBufferPtrs[0] = pad1Buffer;
    s_padBufferPtrs[1] = pad2Buffer;
    s_padBufferSizes[0] = pad1BufferSize;
    s_padBufferSizes[1] = pad2BufferSize;
    safeMemZero(pad1Buffer, pad1BufferSize);
    safeMemZero(pad2Buffer, pad2BufferSize);
    setupBasicSio0Handler();
    s_padStarted = 1;
    return 1;
}

static int s_sio0State;

static void __attribute__((section(".ramtext"))) setupSIO0() {
    SIOS[0].ctrl = 0x40;
    SIOS[0].baudRate = 0x88;
    SIOS[0].mode = 13;
    SIOS[0].ctrl = 0;
    busyloop(10);
    SIOS[0].ctrl = 2;
    busyloop(10);
    SIOS[0].ctrl = 0x2002;
    busyloop(10);
    SIOS[0].ctrl = 0;
    s_sio0State = 0;
}

int __attribute__((section(".ramtext"))) startPad() {
    setupSIO0();
    enterCriticalSection();
    sysDeqIntRP(2, &g_sio0HandlerInfo);
    sysEnqIntRP(2, &g_sio0HandlerInfo);
    IREG = ~IRQ_VBLANK;
    IMASK |= IRQ_VBLANK;
    setSIO0AutoAck(1);
    setTimerAutoAck(3, 0);
    leaveCriticalSection();
}

void __attribute__((section(".ramtext"))) stopPad() {
    enterCriticalSection();
    setTimerAutoAck(3, 1);
    sysDeqIntRP(2, &g_sio0HandlerInfo);
    leaveCriticalSection();
}
