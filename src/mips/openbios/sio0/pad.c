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

#include "openbios/sio0/pad.h"

#include "common/syscalls/syscalls.h"

static uint8_t s_padBuffer1[0x22];
static uint8_t s_padBuffer2[0x22];
uint8_t * g_userPadBuffer;

void * fastMemset(void * ptr, int value, size_t num);

int __attribute__((section(".ramtext"))) initPadHighLevel(uint32_t padType, uint8_t * buffer, int c, int d) {
    __asm__ volatile("sw %0, 4($sp)\nsw %1, 8($sp)\nsw %2, 12($sp)" : : "r"(buffer), "r"(c), "r"(d));
    switch (padType) {
        case 0x10000001:
            ramsyscall_printf("TYPE : Dual cross key  ->  not supported!\n");
            break;
        case 0x20000000:
        case 0x20000001:
            ramsyscall_printf("TYPE : 6 free button or flying-V form\n");
            // this is technically an inlined memset here, but I can't deal
            // with the far jumps in debug mode for now.
            fastMemset(s_padBuffer1, 0xff, 0x22);
            fastMemset(s_padBuffer2, 0xff, 0x22);
            initPad(s_padBuffer1, 0x22, s_padBuffer2, 0x22);
            g_userPadBuffer = buffer;
            startPad();
            return 2;
            break;
        default:
            ramsyscall_printf("TYPE : Unknown (%d)  ->  not supported!\n", padType);
            break;
    }

    return 0;
}

uint32_t __attribute__((section(".ramtext"))) readPadHighLevel() {

}