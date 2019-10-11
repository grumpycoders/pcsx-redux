/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include "osdebug.h"

#include "common/compiler/stdint.h"
#include "openbios/kernel/handlers.h"

void unimplemented();
void breakVector();
void interruptVector();
void A0Vector();
void B0Vector();
void C0Vector();

__attribute__((section(".a0table"))) uint32_t A0table[0xc0] = {
    unimplemented, unimplemented, unimplemented, unimplemented, // 00
    unimplemented, unimplemented, unimplemented, unimplemented, // 04
    unimplemented, unimplemented, unimplemented, unimplemented, // 08
    unimplemented, unimplemented, unimplemented, unimplemented, // 0c
    unimplemented, unimplemented, unimplemented, unimplemented, // 10
    unimplemented, unimplemented, unimplemented, unimplemented, // 14
    unimplemented, unimplemented, unimplemented, unimplemented, // 18
    unimplemented, unimplemented, unimplemented, unimplemented, // 1c
    unimplemented, unimplemented, unimplemented, unimplemented, // 20
    unimplemented, unimplemented, unimplemented, unimplemented, // 24
    unimplemented, unimplemented, unimplemented, unimplemented, // 28
    unimplemented, unimplemented, unimplemented, unimplemented, // 2c
    unimplemented, unimplemented, unimplemented, unimplemented, // 30
    unimplemented, unimplemented, unimplemented, unimplemented, // 34
    unimplemented, unimplemented, unimplemented, unimplemented, // 38
    unimplemented, unimplemented, unimplemented, unimplemented, // 3c
    unimplemented, unimplemented, unimplemented, unimplemented, // 40
    unimplemented, unimplemented, unimplemented, unimplemented, // 44
    unimplemented, unimplemented, unimplemented, unimplemented, // 48
    unimplemented, unimplemented, unimplemented, unimplemented, // 4c
    unimplemented, unimplemented, unimplemented, unimplemented, // 50
    unimplemented, unimplemented, unimplemented, unimplemented, // 54
    unimplemented, unimplemented, unimplemented, unimplemented, // 58
    unimplemented, unimplemented, unimplemented, unimplemented, // 5c
    unimplemented, unimplemented, unimplemented, unimplemented, // 60
    unimplemented, unimplemented, unimplemented, unimplemented, // 64
    unimplemented, unimplemented, unimplemented, unimplemented, // 68
    unimplemented, unimplemented, unimplemented, unimplemented, // 6c
    unimplemented, unimplemented, unimplemented, unimplemented, // 70
    unimplemented, unimplemented, unimplemented, unimplemented, // 74
    unimplemented, unimplemented, unimplemented, unimplemented, // 78
    unimplemented, unimplemented, unimplemented, unimplemented, // 7c
    unimplemented, unimplemented, unimplemented, unimplemented, // 80
    unimplemented, unimplemented, unimplemented, unimplemented, // 84
    unimplemented, unimplemented, unimplemented, unimplemented, // 88
    unimplemented, unimplemented, unimplemented, unimplemented, // 8c
    unimplemented, unimplemented, unimplemented, unimplemented, // 90
    unimplemented, unimplemented, unimplemented, unimplemented, // 94
    unimplemented, unimplemented, unimplemented, unimplemented, // 98
    unimplemented, unimplemented, unimplemented, unimplemented, // 9c
    unimplemented, unimplemented, unimplemented, unimplemented, // a0
    unimplemented, unimplemented, unimplemented, unimplemented, // a4
    unimplemented, unimplemented, unimplemented, unimplemented, // a8
    unimplemented, unimplemented, unimplemented, unimplemented, // ac
    unimplemented, unimplemented, unimplemented, unimplemented, // b0
    unimplemented, unimplemented, unimplemented, unimplemented, // b4
    unimplemented, unimplemented, unimplemented, unimplemented, // b8
    unimplemented, unimplemented, unimplemented, unimplemented, // bc
};

uint32_t B0table[0x60] = {
    unimplemented, unimplemented, unimplemented, unimplemented, // 00
    unimplemented, unimplemented, unimplemented, unimplemented, // 04
    unimplemented, unimplemented, unimplemented, unimplemented, // 08
    unimplemented, unimplemented, unimplemented, unimplemented, // 0c
    unimplemented, unimplemented, unimplemented, unimplemented, // 10
    unimplemented, unimplemented, unimplemented, unimplemented, // 14
    unimplemented, unimplemented, unimplemented, unimplemented, // 18
    unimplemented, unimplemented, unimplemented, unimplemented, // 1c
    unimplemented, unimplemented, unimplemented, unimplemented, // 20
    unimplemented, unimplemented, unimplemented, unimplemented, // 24
    unimplemented, unimplemented, unimplemented, unimplemented, // 28
    unimplemented, unimplemented, unimplemented, unimplemented, // 2c
    unimplemented, unimplemented, unimplemented, unimplemented, // 30
    unimplemented, unimplemented, unimplemented, unimplemented, // 34
    unimplemented, unimplemented, unimplemented, unimplemented, // 38
    unimplemented, unimplemented, unimplemented, unimplemented, // 3c
    unimplemented, unimplemented, unimplemented, unimplemented, // 40
    unimplemented, unimplemented, unimplemented, unimplemented, // 44
    unimplemented, unimplemented, unimplemented, unimplemented, // 48
    unimplemented, unimplemented, unimplemented, unimplemented, // 4c
    unimplemented, unimplemented, unimplemented, unimplemented, // 50
    unimplemented, unimplemented, unimplemented, unimplemented, // 54
    unimplemented, unimplemented, unimplemented, unimplemented, // 58
    unimplemented, unimplemented, unimplemented, unimplemented, // 5c
};

uint32_t C0table[0x20] = {
    unimplemented, unimplemented, unimplemented, unimplemented, // 00
    unimplemented, unimplemented, unimplemented, unimplemented, // 04
    unimplemented, unimplemented, unimplemented, unimplemented, // 08
    unimplemented, unimplemented, unimplemented, unimplemented, // 0c
    unimplemented, unimplemented, unimplemented, unimplemented, // 10
    unimplemented, unimplemented, unimplemented, unimplemented, // 14
    unimplemented, unimplemented, unimplemented, unimplemented, // 18
    unimplemented, unimplemented, unimplemented, unimplemented, // 1c
};

static void installHandler(const uint32_t * src, uint32_t * dst) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
}

void installKernelHandlers() {
    installHandler(breakVector, (uint32_t *) 0x40);
    installHandler(interruptVector, (uint32_t *) 0x80);
    installHandler(A0Vector, (uint32_t *) 0xa0);
    installHandler(B0Vector, (uint32_t *) 0xb0);
    installHandler(C0Vector, (uint32_t *) 0xc0);
}

typedef struct {
    union {
        struct {
            uint32_t r0, at, v0, v1, a0, a1, a2, a3;
            uint32_t t0, t1, t2, t3, t4, t5, t6, t7;
            uint32_t s0, s1, s2, s3, s4, s5, s6, s7;
            uint32_t t8, t9, k0, k1, gp, sp, s8, ra;
            uint32_t lo, hi;
        } n;
        uint32_t r[34]; /* Lo, Hi in r[32] and r[33] */
    } GPR;
    uint32_t SR;
    uint32_t Cause;
    uint32_t EPC;
} InterruptData;

static void printInterruptData(InterruptData* data) {
    osDbgPrintf("epc = %p - status = %p - cause = %p\r\n", data->EPC, data->SR, data->Cause);
    osDbgPrintf("r0 = %p - at = %p - v0 = %p - v1 = %p\r\n", data->GPR.r[ 0], data->GPR.r[ 1], data->GPR.r[ 2], data->GPR.r[ 3]);
    osDbgPrintf("a0 = %p - a1 = %p - a2 = %p - a3 = %p\r\n", data->GPR.r[ 4], data->GPR.r[ 5], data->GPR.r[ 6], data->GPR.r[ 7]);
    osDbgPrintf("t0 = %p - t1 = %p - t2 = %p - t3 = %p\r\n", data->GPR.r[ 8], data->GPR.r[ 9], data->GPR.r[10], data->GPR.r[11]);
    osDbgPrintf("t4 = %p - t5 = %p - t6 = %p - t7 = %p\r\n", data->GPR.r[12], data->GPR.r[13], data->GPR.r[14], data->GPR.r[15]);
    osDbgPrintf("s0 = %p - s1 = %p - s2 = %p - s3 = %p\r\n", data->GPR.r[16], data->GPR.r[17], data->GPR.r[18], data->GPR.r[19]);
    osDbgPrintf("s4 = %p - s5 = %p - s6 = %p - s7 = %p\r\n", data->GPR.r[20], data->GPR.r[21], data->GPR.r[22], data->GPR.r[23]);
    osDbgPrintf("t8 = %p - t9 = %p - k0 = %p - k1 = %p\r\n", data->GPR.r[24], data->GPR.r[25], data->GPR.r[26], data->GPR.r[27]);
    osDbgPrintf("gp = %p - sp = %p - s8 = %p - ra = %p\r\n", data->GPR.r[28], data->GPR.r[29], data->GPR.r[30], data->GPR.r[31]);
    osDbgPrintf("hi = %p - lo = %p\r\n", data->GPR.r[32], data->GPR.r[33]);
}

void breakHandler(InterruptData* data) {
}

void interruptHandler(InterruptData* data) {
    osDbgPrintf("***Exception***\r\n");
    printInterruptData(data);
}
