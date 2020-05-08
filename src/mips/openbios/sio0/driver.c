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

#include "common/psxlibc/string.h"
#include "common/hardware/hwregs.h"
#include "common/syscalls/syscalls.h"
#include "openbios/handlers/handlers.h"
#include "openbios/sio0/pad.h"

static int s_padStarted;
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

static void __attribute__((section(".ramtext"))) readPad(int pad) {}

static void __attribute__((section(".ramtext"))) readCard() {}

static int __attribute__((section(".ramtext"))) sio0Verifier() {
    if (((IMASK & 0x01) == 0) || ((IREG & 0x01) == 0)) return 0;
    return 1;
}

static void __attribute__((section(".ramtext"))) sio0Handler(int v) {
    if (s_padStarted) {
        readPad(0);
        readPad(1);
        if (g_userPadBuffer) readPadHighLevel();
    }
    if (s_padAutoAck) IREG = ~1;
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
    // 4 words to 0...?
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

void busyloop(int count);

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
    IREG = ~1;
    IMASK |= 1;
    setSIO0AutoAck(1);
    setTimerAutoAck(3, 0);
    leaveCriticalSection();
}
