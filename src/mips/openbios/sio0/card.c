/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

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

#include "openbios/sio0/card.h"

#include "common/hardware/hwregs.h"
#include "common/hardware/irq.h"
#include "common/kernel/events.h"
#include "common/syscalls/syscalls.h"
#include "openbios/kernel/events.h"
#include "openbios/sio0/sio0.h"

int g_mcOverallSuccess;
int g_mcErrors[4];
static uint8_t s_mcCommand[2];
static uint8_t s_mcFlagByte[2];

void mcResetStatus() {
    g_mcOverallSuccess = 0;
    g_mcErrors[0] = 0;
    g_mcErrors[1] = 0;
    g_mcErrors[2] = 0;
    g_mcErrors[3] = 0;

    syscall_undeliverEvent(EVENT_VBLANK, 0x0004);
    syscall_undeliverEvent(EVENT_VBLANK, 0x8000);
    syscall_undeliverEvent(EVENT_VBLANK, 0x2000);
    syscall_undeliverEvent(EVENT_VBLANK, 0x0100);
}

int mcWaitForStatus() {
    while (1) {
        if (g_mcOverallSuccess) {
            mcResetStatus();
            return 1;
        }
        for (unsigned i = 0; i < 4; i++) {
            if (g_mcErrors[i]) {
                mcResetStatus();
                return 0;
            }
        }
    }
}

int mcWaitForStatusAndReturnIndex() {
    while (1) {
        if (g_mcOverallSuccess) {
            mcResetStatus();
            return 0;
        }
        for (unsigned i = 0; i < 4; i++) {
            if (g_mcErrors[i]) {
                mcResetStatus();
                return i + 1;
            }
        }
    }
}

int __attribute__((section(".ramtext"))) mcReadHandler() {
    int port = g_mcPortFlipping;
    int sector = g_mcSector[port];
    uint8_t* buffer = g_mcUserBuffers[port];

    uint8_t b;

    switch (g_mcOperation) {
        case 1:
            g_sio0Mask = port == 0 ? 0x0000 : 0x2000;
            SIOS[0].ctrl = g_sio0Mask | 0x1003;
            SIOS[0].fifo = (g_mcDeviceId[port] & 0x0f) + 0x81;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            g_mcActionInProgress = 1;
            break;
        case 2:
            SIOS[0].fifo = 'R';
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            break;
        case 3:
            b = SIOS[0].fifo;
            SIOS[0].fifo = 0;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            if (g_skipErrorOnNewCard) return 0;
            if ((b & 0x08) == 0) return 0;
            g_skipErrorOnNewCard = 0;  // durr?
            g_mcFlags[port] = 1;
            g_mcLastPort = g_mcPortFlipping;
            syscall_buLowLevelOpError3();
            deliverEvent(EVENT_CARD, 0x2000);
            g_mcGotError = 1;
            return -1;
            break;
        case 4:
            b = SIOS[0].fifo;
            SIOS[0].fifo = 0;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            if (b != 0x5a) return -1;
            break;
        case 5:
            b = SIOS[0].fifo;
            SIOS[0].fifo = sector >> 8;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            if (b != 0x5d) return -1;
            break;
        case 6:
            SIOS[0].fifo = sector;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            break;
        case 7:
            SIOS[0].fifo = 0;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            break;
        case 8:
            b = SIOS[0].fifo;
            SIOS[0].fifo = 0;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            if (b != 0x5c) return -1;
            break;
        case 9:
            b = SIOS[0].fifo;
            SIOS[0].fifo = 0;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            if (b != 0x5d) return -1;
            break;
        case 10:
            b = SIOS[0].fifo;
            SIOS[0].fifo = 0;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            if (b != (sector >> 8)) return -1;
            g_mcChecksum[port] = (sector ^ (sector >> 8)) & 0xff;
            s_mcCommand[port] = 0;
            break;
        case 11:
            b = SIOS[0].fifo;
            SIOS[0].fifo = s_mcCommand[port];
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            if (b != (sector & 0xff)) return -1;
            g_mcFastTrackActive = 1;
            break;
        case 12:
            b = SIOS[0].fifo;
            SIOS[0].fifo = 0;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            buffer[0x7f] = b;
            g_mcChecksum[port] ^= b;
            break;
        case 13:
            b = SIOS[0].fifo;
            SIOS[0].fifo = 0;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            if (b != g_mcChecksum[port]) return -1;
            while ((SIOS[0].stat & 2) == 0)
                ;
            return SIOS[0].fifo == 0x47 ? 1 : -1;
        default:
            return -1;
    }
    return 0;
}

int __attribute__((section(".ramtext"))) mcWriteHandler() {
    int port = g_mcPortFlipping;
    int sector = g_mcSector[port];
    uint8_t* buffer = g_mcUserBuffers[port];

    uint8_t b;

    switch (g_mcOperation) {
        case 1:
            g_sio0Mask = port == 0 ? 0x0000 : 0x2000;
            SIOS[0].ctrl = g_sio0Mask | 0x1003;
            SIOS[0].fifo = (g_mcDeviceId[port] & 0x0f) + 0x81;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            g_mcActionInProgress = 1;
            break;
        case 2:
            SIOS[0].fifo = 'W';
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            break;
        case 3:
            b = SIOS[0].fifo;
            SIOS[0].fifo = 0;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            s_mcFlagByte[port] = b;
            if (g_skipErrorOnNewCard) return 0;
            if ((b & 0x08) == 0) return 0;
            g_skipErrorOnNewCard = 0;  // durr?
            g_mcFlags[port] = 1;
            g_mcLastPort = g_mcPortFlipping;
            syscall_buLowLevelOpError3();
            deliverEvent(EVENT_CARD, 0x2000);
            g_mcGotError = 1;
            return -1;
            break;
        case 4:
            b = SIOS[0].fifo;
            SIOS[0].fifo = 0;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            if (b != 0x5a) return -1;
            break;
        case 5:
            b = SIOS[0].fifo;
            SIOS[0].fifo = sector >> 8;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            if (b != 0x5d) return -1;
            break;
        case 6:
            SIOS[0].fifo = sector & 0xff;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            g_mcChecksum[port] ^= sector & 0xff;
            g_mcFastTrackActive = 1;
            break;
        case 7:
            SIOS[0].fifo = g_mcChecksum[port];
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            break;
        case 8:
            SIOS[0].fifo = 0;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            break;
        case 9:
            b = SIOS[0].fifo;
            SIOS[0].fifo = 0;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            if (b != 0x5c) return -1;
            break;
        case 10:
            b = SIOS[0].fifo;
            SIOS[0].fifo = 0;
            SIOS[0].ctrl |= 0x0010;
            IREG = ~IRQ_CONTROLLER;
            if (b != 0x5d) return -1;
            while ((SIOS[0].stat & 2) == 0)
                ;
            if (!g_skipErrorOnNewCard && ((s_mcFlagByte[port] & 4) != 0)) {
                g_mcLastPort = g_mcPortFlipping;
                g_skipErrorOnNewCard = 0; // whyyyy
                g_mcFlags[g_mcPortFlipping] = 1;
                syscall_buLowLevelOpError3();
                deliverEvent(EVENT_CARD, 0x8001);
                g_mcGotError = 1;
            }
            return SIOS[0].fifo == 0x47 ? 1 : -1;
        default:
            return -1;
    }
    return 0;
}

int __attribute__((section(".ramtext"))) mcInfoHandler() {
    int port;
    uint8_t b;

    port = g_mcPortFlipping;
    switch (g_mcOperation) {
        case 1:
            g_sio0Mask = port == 0 ? 0x0000 : 0x2000;
            SIOS[0].ctrl = g_sio0Mask | 0x1003;
            SIOS[0].fifo = (g_mcDeviceId[port] & 0x0f) + 0x81;
            SIOS[0].ctrl = SIOS[0].ctrl | 0x0010;
            IREG = ~IRQ_CONTROLLER;
            g_mcActionInProgress = 1;
            break;
        case 2:
            SIOS[0].fifo = 0x52;
            SIOS[0].ctrl = SIOS[0].ctrl | 0x0010;
            IREG = ~IRQ_CONTROLLER;
            break;
        case 3:
            b = SIOS[0].fifo;
            SIOS[0].fifo = 0;
            SIOS[0].ctrl = SIOS[0].ctrl | 0x0010;
            IREG = ~IRQ_CONTROLLER;
            if (g_skipErrorOnNewCard) return 0;
            if ((b & 0x0c) == 0) break;

            g_skipErrorOnNewCard = 0;
            g_mcFlags[port] = 1;
            g_mcLastPort = g_mcPortFlipping;
            if ((b & 0x04) != 0) {
                syscall_buLowLevelOpError1();
                deliverEvent(EVENT_CARD, 0x8000);
            } else {
                syscall_buLowLevelOpError3();
                deliverEvent(EVENT_CARD, 0x2000);
            }
            g_mcGotError = 1;
            return -1;
        case 4:
            b = SIOS[0].fifo;
            SIOS[0].fifo = 0;
            SIOS[0].ctrl = SIOS[0].ctrl | 0x0010;
            IREG = ~IRQ_CONTROLLER;
            return (b == 0x5a) ? 1 : -1;
        default:
            return -1;
    }
    return 0;
}
