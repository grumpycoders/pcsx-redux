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

    .section .text, "ax", @progbits
    .align 2
    .global psxsetjmp
    .type psxsetjmp, @function

psxsetjmp:
    sw    $ra, 0($a0)
    sw    $sp, 4($a0)
    sw    $s8, 8($a0)
    sw    $s0, 12($a0)
    sw    $s1, 16($a0)
    sw    $s2, 20($a0)
    sw    $s3, 24($a0)
    sw    $s4, 28($a0)
    sw    $s5, 32($a0)
    sw    $s6, 36($a0)
    sw    $s7, 40($a0)
    sw    $gp, 44($a0)
    move  $v0, $0
    jr    $ra

    .section .text, "ax", @progbits
    .align 2
    .global psxlongjmp
    .type psxlongjmp, @function

psxlongjmp:
    lw    $ra, 0($a0)
    lw    $sp, 4($a0)
    lw    $s8, 8($a0)
    lw    $s0, 12($a0)
    lw    $s1, 16($a0)
    lw    $s2, 20($a0)
    lw    $s3, 24($a0)
    lw    $s4, 28($a0)
    lw    $s5, 32($a0)
    lw    $s6, 36($a0)
    lw    $s7, 40($a0)
    lw    $gp, 44($a0)
    move  $v0, $a1
    jr    $ra
