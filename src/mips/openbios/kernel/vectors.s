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

    .set push
    .set noreorder
    .section .data, "ax", @progbits
    .align 2
    .global generalHandler
    .type generalHandler, @function

generalHandler:
    sw    $0, 0x100($0)
    .set push
    .set noat
    sw    $1, 0x104($0)
    .set pop
    sw    $2, 0x108($0)
    sw    $3, 0x10c($0)
    sw    $4, 0x110($0)
    sw    $5, 0x114($0)
    sw    $6, 0x118($0)
    sw    $7, 0x11c($0)
    sw    $8, 0x120($0)
    sw    $9, 0x124($0)
    sw    $10, 0x128($0)
    sw    $11, 0x12c($0)
    sw    $12, 0x130($0)
    sw    $13, 0x134($0)
    sw    $14, 0x138($0)
    sw    $15, 0x13c($0)
    sw    $16, 0x140($0)
    sw    $17, 0x144($0)
    sw    $18, 0x148($0)
    sw    $19, 0x14c($0)
    sw    $20, 0x150($0)
    sw    $21, 0x154($0)
    sw    $22, 0x158($0)
    sw    $23, 0x15c($0)
    sw    $24, 0x160($0)
    sw    $25, 0x164($0)
    sw    $0, 0x168($0)
    sw    $0, 0x16c($0)
    sw    $28, 0x170($0)
    sw    $29, 0x174($0)
    sw    $30, 0x178($0)
    sw    $31, 0x17c($0)

    mflo  $t0
    nop
    mfhi  $t1
    nop
    mfc0  $t2, $12
    nop
    mfc0  $t3, $13
    nop
    mfc0  $t4, $14
    nop

    sw    $t0, 0x180($0)
    sw    $t1, 0x184($0)
    sw    $t2, 0x188($0)
    sw    $t3, 0x18c($0)
    sw    $t4, 0x190($0)

    jalr  $k1
    li    $a0, 0x100

    move  $k1, $0

    lw    $t0, 0x180($0)
    lw    $t1, 0x184($0)
    lw    $t2, 0x188($0)
    lw    $t3, 0x18c($0)
    lw    $k0, 0x190($0)
    mtlo  $t0
    nop
    mthi  $t1
    nop
    mtc0  $t2, $12
    nop
    mtc0  $t3, $13
    nop
    .set push
    .set noat
    lw    $1, 0x104($0)
    .set pop
    lw    $2, 0x108($0)
    lw    $3, 0x10c($0)
    lw    $4, 0x110($0)
    lw    $5, 0x114($0)
    lw    $6, 0x118($0)
    lw    $7, 0x11c($0)
    lw    $8, 0x120($0)
    lw    $9, 0x124($0)
    lw    $10, 0x128($0)
    lw    $11, 0x12c($0)
    lw    $12, 0x130($0)
    lw    $13, 0x134($0)
    lw    $14, 0x138($0)
    lw    $15, 0x13c($0)
    lw    $16, 0x140($0)
    lw    $17, 0x144($0)
    lw    $18, 0x148($0)
    lw    $19, 0x14c($0)
    lw    $20, 0x150($0)
    lw    $21, 0x154($0)
    lw    $22, 0x158($0)
    lw    $23, 0x15c($0)
    lw    $24, 0x160($0)
    lw    $25, 0x164($0)
    lw    $28, 0x170($0)
    lw    $29, 0x174($0)
    lw    $30, 0x178($0)
    lw    $31, 0x17c($0)
    jr    $k0
    .word 0x42000010 /* rfe */

    .section .text, "ax", @progbits

    .align 2
    .global breakVector
    .global breakHandler
    .type breakVector, @function

breakVector:
    ori   $k0, $0, %lo(generalHandler)
    lui   $k1, %hi(breakHandler)
    jr    $k0
    ori   $k1, %lo(breakHandler)

    .align 2
    .global interruptVector
    .global interruptHandler
    .type interruptVector, @function

interruptVector:
    ori   $k0, $0, %lo(generalHandler)
    lui   $k1, %hi(interruptHandler)
    jr    $k0
    ori   $k1, %lo(interruptHandler)

    .align 2
    .global A0Vector
    .global A0Handler
    .type A0Vector, @function

A0Vector:
    la    $t0, A0Handler
    jr    $t0
    nop

    .align 2
    .global B0Vector
    .global B0Handler
    .type B0Vector, @function

B0Vector:
    la    $t0, B0Handler
    jr    $t0
    nop

    .align 2
    .global C0Vector
    .global C0Handler
    .type C0Vector, @function

C0Vector:
    la    $t0, C0Handler
    jr    $t0
    nop

    .section .text, "ax", @progbits
    .align 2
    .global A0table
    .type A0Handler, @function

A0Handler:
    la    $t0, A0table
    sll   $t2, $t1, 2
    add   $t2, $t0
    lw    $t2, 0($t2)
    li    $t0, 0xa0
    jr    $t2
    nop

    .align 2
    .global B0table
    .type B0Handler, @function

B0Handler:
    la    $t0, B0table
    sll   $t2, $t1, 2
    add   $t2, $t0
    lw    $t2, 0($t2)
    li    $t0, 0xb0
    jr    $t2
    nop

    .align 2
    .global C0table
    .type C0Handler, @function

C0Handler:
    la    $t0, C0table
    sll   $t2, $t1, 2
    add   $t2, $t0
    lw    $t2, 0($t2)
    li    $t0, 0xc0
    jr    $t2
    nop

    .align 2
    .global unimplemented
    .type unimplemented, @function

unimplemented:
    break
    nop
    jr    $ra
    nop

    .set pop
