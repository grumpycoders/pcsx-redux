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
#include "openbios/handlers/handlers.h"
#include "openbios/kernel/events.h"

static int s_IRQsAutoAck[11];

static __attribute__((section(".data"))) int IRQVerifier(void) {
    if ((IMASK & IREG & 0x004) != 0) deliverEvent(0xf0000003,0x1000);
    if ((IMASK & IREG & 0x200) != 0) deliverEvent(0xf0000009,0x1000);
    if ((IMASK & IREG & 0x002) != 0) deliverEvent(0xf0000002,0x1000);
    if ((IMASK & IREG & 0x400) != 0) deliverEvent(0xf000000a,0x1000);
    if ((IMASK & IREG & 0x100) != 0) deliverEvent(0xf000000b,0x1000);
    if ((IMASK & IREG & 0x001) != 0) deliverEvent(0xf0000001,0x1000);
    if ((IMASK & IREG & 0x010) != 0) deliverEvent(0xf0000005,0x1000);
    if ((IMASK & IREG & 0x020) != 0) deliverEvent(0xf0000006,0x1000);
    if ((IMASK & IREG & 0x040) != 0) deliverEvent(0xf0000006,0x1000);
    if ((IMASK & IREG & 0x080) != 0) deliverEvent(0xf0000008,0x1000);
    if ((IMASK & IREG & 0x008) != 0) deliverEvent(0xf0000004,0x1000);
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

int enqueueIrqHandler(int priority) {
    memset(s_IRQsAutoAck, 0, sizeof(s_IRQsAutoAck));

    return sysEnqIntRP(priority, &s_IRQHandlerInfo);
}
