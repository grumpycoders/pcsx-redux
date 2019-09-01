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

    .section .text, "ax", @progbits
    .set noreorder

    .align 2
    .global ExceptVector
    .type ExceptVector, @function

ExceptVector:

    .align 2
    .global InterruptVector
    .type InterruptVector, @function

InterruptVector:

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

    .align 2
    .global A0table
    .type A0Handler, @function

A0Handler:
    la    $t0, A0table
    sll   $t1, 1
    add   $t0, $t1
    lw    $t0, 0($t0)
    nop
    jr    $t0
    nop

    .align 2
    .global B0table
    .type B0Handler, @function

B0Handler:
    la    $t0, B0table
    sll   $t1, 1
    add   $t0, $t1
    lw    $t0, 0($t0)
    nop
    jr    $t0
    nop

    .align 2
    .global C0table
    .type C0Handler, @function

C0Handler:
    la    $t0, C0table
    sll   $t1, 1
    add   $t0, $t1
    lw    $t0, 0($t0)
    nop
    jr    $t0
    nop
