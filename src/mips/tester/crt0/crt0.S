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

#include <common/include/mipsregs.h>

.set push
.set noreorder
.set noat

    .section .start, "ax", @progbits
    .align 2
    .global main
    .global _start
    .type _start, @function
_start:
                la      t0, __bss_start
                la      t1, __bss_end
                addiu   t1, t1, 3
                srl     t1, t1, 2
                sll     t1, t1, 2
                beq     t0, t1, _zero_bss_done
                nop

_zero_bss:
				sw      zero, 0(t0)
                addiu   t0, t0, 4
                bne     t0, t1, _zero_bss
                nop

_zero_bss_done:
                li      a0, 0
                j       main
                li      a1, 0

                .extern __bss_start
                .extern __bss_end
                .extern _gp
                .extern main
                
.set pop
