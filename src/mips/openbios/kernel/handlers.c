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

#include <stdint.h>

#include "openbios/kernel/handlers.h"

__attribute__((section(".a0table"))) uint32_t A0table[192];
uint32_t B0table[192];
uint32_t C0table[192];

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
