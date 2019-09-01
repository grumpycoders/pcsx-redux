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

#include "common/compiler/stdint.h"
#include "openbios/kernel/handlers.h"

static int nullFunction() { return 0; }

__attribute__((section(".a0table"))) uint32_t A0table[0xc0] = {
    nullFunction, nullFunction, nullFunction, nullFunction, // 00
    nullFunction, nullFunction, nullFunction, nullFunction, // 04
    nullFunction, nullFunction, nullFunction, nullFunction, // 08
    nullFunction, nullFunction, nullFunction, nullFunction, // 0c
    nullFunction, nullFunction, nullFunction, nullFunction, // 10
    nullFunction, nullFunction, nullFunction, nullFunction, // 14
    nullFunction, nullFunction, nullFunction, nullFunction, // 18
    nullFunction, nullFunction, nullFunction, nullFunction, // 1c
    nullFunction, nullFunction, nullFunction, nullFunction, // 20
    nullFunction, nullFunction, nullFunction, nullFunction, // 24
    nullFunction, nullFunction, nullFunction, nullFunction, // 28
    nullFunction, nullFunction, nullFunction, nullFunction, // 2c
    nullFunction, nullFunction, nullFunction, nullFunction, // 30
    nullFunction, nullFunction, nullFunction, nullFunction, // 34
    nullFunction, nullFunction, nullFunction, nullFunction, // 38
    nullFunction, nullFunction, nullFunction, nullFunction, // 3c
    nullFunction, nullFunction, nullFunction, nullFunction, // 40
    nullFunction, nullFunction, nullFunction, nullFunction, // 44
    nullFunction, nullFunction, nullFunction, nullFunction, // 48
    nullFunction, nullFunction, nullFunction, nullFunction, // 4c
    nullFunction, nullFunction, nullFunction, nullFunction, // 50
    nullFunction, nullFunction, nullFunction, nullFunction, // 54
    nullFunction, nullFunction, nullFunction, nullFunction, // 58
    nullFunction, nullFunction, nullFunction, nullFunction, // 5c
    nullFunction, nullFunction, nullFunction, nullFunction, // 60
    nullFunction, nullFunction, nullFunction, nullFunction, // 64
    nullFunction, nullFunction, nullFunction, nullFunction, // 68
    nullFunction, nullFunction, nullFunction, nullFunction, // 6c
    nullFunction, nullFunction, nullFunction, nullFunction, // 70
    nullFunction, nullFunction, nullFunction, nullFunction, // 74
    nullFunction, nullFunction, nullFunction, nullFunction, // 78
    nullFunction, nullFunction, nullFunction, nullFunction, // 7c
    nullFunction, nullFunction, nullFunction, nullFunction, // 80
    nullFunction, nullFunction, nullFunction, nullFunction, // 84
    nullFunction, nullFunction, nullFunction, nullFunction, // 88
    nullFunction, nullFunction, nullFunction, nullFunction, // 8c
    nullFunction, nullFunction, nullFunction, nullFunction, // 90
    nullFunction, nullFunction, nullFunction, nullFunction, // 94
    nullFunction, nullFunction, nullFunction, nullFunction, // 98
    nullFunction, nullFunction, nullFunction, nullFunction, // 9c
    nullFunction, nullFunction, nullFunction, nullFunction, // a0
    nullFunction, nullFunction, nullFunction, nullFunction, // a4
    nullFunction, nullFunction, nullFunction, nullFunction, // a8
    nullFunction, nullFunction, nullFunction, nullFunction, // ac
    nullFunction, nullFunction, nullFunction, nullFunction, // b0
    nullFunction, nullFunction, nullFunction, nullFunction, // b4
    nullFunction, nullFunction, nullFunction, nullFunction, // b8
    nullFunction, nullFunction, nullFunction, nullFunction, // bc
};

uint32_t B0table[0x60] = {
    nullFunction, nullFunction, nullFunction, nullFunction, // 00
    nullFunction, nullFunction, nullFunction, nullFunction, // 04
    nullFunction, nullFunction, nullFunction, nullFunction, // 08
    nullFunction, nullFunction, nullFunction, nullFunction, // 0c
    nullFunction, nullFunction, nullFunction, nullFunction, // 10
    nullFunction, nullFunction, nullFunction, nullFunction, // 14
    nullFunction, nullFunction, nullFunction, nullFunction, // 18
    nullFunction, nullFunction, nullFunction, nullFunction, // 1c
    nullFunction, nullFunction, nullFunction, nullFunction, // 20
    nullFunction, nullFunction, nullFunction, nullFunction, // 24
    nullFunction, nullFunction, nullFunction, nullFunction, // 28
    nullFunction, nullFunction, nullFunction, nullFunction, // 2c
    nullFunction, nullFunction, nullFunction, nullFunction, // 30
    nullFunction, nullFunction, nullFunction, nullFunction, // 34
    nullFunction, nullFunction, nullFunction, nullFunction, // 38
    nullFunction, nullFunction, nullFunction, nullFunction, // 3c
    nullFunction, nullFunction, nullFunction, nullFunction, // 40
    nullFunction, nullFunction, nullFunction, nullFunction, // 44
    nullFunction, nullFunction, nullFunction, nullFunction, // 48
    nullFunction, nullFunction, nullFunction, nullFunction, // 4c
    nullFunction, nullFunction, nullFunction, nullFunction, // 50
    nullFunction, nullFunction, nullFunction, nullFunction, // 54
    nullFunction, nullFunction, nullFunction, nullFunction, // 58
    nullFunction, nullFunction, nullFunction, nullFunction, // 5c
};

uint32_t C0table[0x20] = {
    nullFunction, nullFunction, nullFunction, nullFunction, // 00
    nullFunction, nullFunction, nullFunction, nullFunction, // 04
    nullFunction, nullFunction, nullFunction, nullFunction, // 08
    nullFunction, nullFunction, nullFunction, nullFunction, // 0c
    nullFunction, nullFunction, nullFunction, nullFunction, // 10
    nullFunction, nullFunction, nullFunction, nullFunction, // 14
    nullFunction, nullFunction, nullFunction, nullFunction, // 18
    nullFunction, nullFunction, nullFunction, nullFunction, // 1c
};

extern void A0Vector();
extern void B0Vector();
extern void C0Vector();

static void installHandler(const uint32_t * src, uint32_t * dst) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
}

void installKernelHandlers() {
    installHandler(A0Vector, (uint32_t *) 0xa0);
    installHandler(B0Vector, (uint32_t *) 0xb0);
    installHandler(C0Vector, (uint32_t *) 0xc0);
}
