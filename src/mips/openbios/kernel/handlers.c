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

#include "openbios/kernel/handlers.h"
#include "common/compiler/stdint.h"

void unimplemented();
void breakVector();
void interruptVector();
void A0Vector();
void B0Vector();
void C0Vector();

__attribute__((section(".a0table"))) void* A0table[0xc0] = {
    unimplemented, unimplemented, unimplemented, unimplemented,  // 00
    unimplemented, unimplemented, unimplemented, unimplemented,  // 04
    unimplemented, unimplemented, unimplemented, unimplemented,  // 08
    unimplemented, unimplemented, unimplemented, unimplemented,  // 0c
    unimplemented, unimplemented, unimplemented, unimplemented,  // 10
    unimplemented, unimplemented, unimplemented, unimplemented,  // 14
    unimplemented, unimplemented, unimplemented, unimplemented,  // 18
    unimplemented, unimplemented, unimplemented, unimplemented,  // 1c
    unimplemented, unimplemented, unimplemented, unimplemented,  // 20
    unimplemented, unimplemented, unimplemented, unimplemented,  // 24
    unimplemented, unimplemented, unimplemented, unimplemented,  // 28
    unimplemented, unimplemented, unimplemented, unimplemented,  // 2c
    unimplemented, unimplemented, unimplemented, unimplemented,  // 30
    unimplemented, unimplemented, unimplemented, unimplemented,  // 34
    unimplemented, unimplemented, unimplemented, unimplemented,  // 38
    unimplemented, unimplemented, unimplemented, unimplemented,  // 3c
    unimplemented, unimplemented, unimplemented, unimplemented,  // 40
    unimplemented, unimplemented, unimplemented, unimplemented,  // 44
    unimplemented, unimplemented, unimplemented, unimplemented,  // 48
    unimplemented, unimplemented, unimplemented, unimplemented,  // 4c
    unimplemented, unimplemented, unimplemented, unimplemented,  // 50
    unimplemented, unimplemented, unimplemented, unimplemented,  // 54
    unimplemented, unimplemented, unimplemented, unimplemented,  // 58
    unimplemented, unimplemented, unimplemented, unimplemented,  // 5c
    unimplemented, unimplemented, unimplemented, unimplemented,  // 60
    unimplemented, unimplemented, unimplemented, unimplemented,  // 64
    unimplemented, unimplemented, unimplemented, unimplemented,  // 68
    unimplemented, unimplemented, unimplemented, unimplemented,  // 6c
    unimplemented, unimplemented, unimplemented, unimplemented,  // 70
    unimplemented, unimplemented, unimplemented, unimplemented,  // 74
    unimplemented, unimplemented, unimplemented, unimplemented,  // 78
    unimplemented, unimplemented, unimplemented, unimplemented,  // 7c
    unimplemented, unimplemented, unimplemented, unimplemented,  // 80
    unimplemented, unimplemented, unimplemented, unimplemented,  // 84
    unimplemented, unimplemented, unimplemented, unimplemented,  // 88
    unimplemented, unimplemented, unimplemented, unimplemented,  // 8c
    unimplemented, unimplemented, unimplemented, unimplemented,  // 90
    unimplemented, unimplemented, unimplemented, unimplemented,  // 94
    unimplemented, unimplemented, unimplemented, unimplemented,  // 98
    unimplemented, unimplemented, unimplemented, unimplemented,  // 9c
    unimplemented, unimplemented, unimplemented, unimplemented,  // a0
    unimplemented, unimplemented, unimplemented, unimplemented,  // a4
    unimplemented, unimplemented, unimplemented, unimplemented,  // a8
    unimplemented, unimplemented, unimplemented, unimplemented,  // ac
    unimplemented, unimplemented, unimplemented, unimplemented,  // b0
    unimplemented, unimplemented, unimplemented, unimplemented,  // b4
    unimplemented, unimplemented, unimplemented, unimplemented,  // b8
    unimplemented, unimplemented, unimplemented, unimplemented,  // bc
};

void* B0table[0x60] = {
    unimplemented, unimplemented, unimplemented, unimplemented,  // 00
    unimplemented, unimplemented, unimplemented, unimplemented,  // 04
    unimplemented, unimplemented, unimplemented, unimplemented,  // 08
    unimplemented, unimplemented, unimplemented, unimplemented,  // 0c
    unimplemented, unimplemented, unimplemented, unimplemented,  // 10
    unimplemented, unimplemented, unimplemented, unimplemented,  // 14
    unimplemented, unimplemented, unimplemented, unimplemented,  // 18
    unimplemented, unimplemented, unimplemented, unimplemented,  // 1c
    unimplemented, unimplemented, unimplemented, unimplemented,  // 20
    unimplemented, unimplemented, unimplemented, unimplemented,  // 24
    unimplemented, unimplemented, unimplemented, unimplemented,  // 28
    unimplemented, unimplemented, unimplemented, unimplemented,  // 2c
    unimplemented, unimplemented, unimplemented, unimplemented,  // 30
    unimplemented, unimplemented, unimplemented, unimplemented,  // 34
    unimplemented, unimplemented, unimplemented, unimplemented,  // 38
    unimplemented, unimplemented, unimplemented, unimplemented,  // 3c
    unimplemented, unimplemented, unimplemented, unimplemented,  // 40
    unimplemented, unimplemented, unimplemented, unimplemented,  // 44
    unimplemented, unimplemented, unimplemented, unimplemented,  // 48
    unimplemented, unimplemented, unimplemented, unimplemented,  // 4c
    unimplemented, unimplemented, unimplemented, unimplemented,  // 50
    unimplemented, unimplemented, unimplemented, unimplemented,  // 54
    unimplemented, unimplemented, unimplemented, unimplemented,  // 58
    unimplemented, unimplemented, unimplemented, unimplemented,  // 5c
};

void* C0table[0x20] = {
    unimplemented, unimplemented, unimplemented, unimplemented,  // 00
    unimplemented, unimplemented, unimplemented, unimplemented,  // 04
    unimplemented, unimplemented, unimplemented, unimplemented,  // 08
    unimplemented, unimplemented, unimplemented, unimplemented,  // 0c
    unimplemented, unimplemented, unimplemented, unimplemented,  // 10
    unimplemented, unimplemented, unimplemented, unimplemented,  // 14
    unimplemented, unimplemented, unimplemented, unimplemented,  // 18
    unimplemented, unimplemented, unimplemented, unimplemented,  // 1c
};

static void installHandler(const void* src, void* dst) {
    ((uint32_t*)dst)[0] = ((uint32_t*)src)[0];
    ((uint32_t*)dst)[1] = ((uint32_t*)src)[1];
    ((uint32_t*)dst)[2] = ((uint32_t*)src)[2];
    ((uint32_t*)dst)[3] = ((uint32_t*)src)[3];
}

void installKernelHandlers() {
    installHandler(breakVector, (uint32_t*)0x40);
    installHandler(interruptVector, (uint32_t*)0x80);
    installHandler(A0Vector, (uint32_t*)0xa0);
    installHandler(B0Vector, (uint32_t*)0xb0);
    installHandler(C0Vector, (uint32_t*)0xc0);
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

void breakHandler(InterruptData* data) {}

void interruptHandler(InterruptData* data) {}
