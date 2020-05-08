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

    .set noreorder
    .section .ramtext, "ax", @progbits
    .align 2
    .global busyloop
    .type busyloop, @function

/* The timing of this might be so sensitive, it could be
   requiring to be an exact replica of the existing code.
   
   The C version of this would be the following:
   
   void busyLoop(int count) {
       volatile int cycles = count;
       while (cycles--);
   }

   */
busyloop:
    sw    $a0, 0($sp)
    lw    $v0, 0($sp)
    lw    $v1, 0($sp)
    nop
    addiu $v1, -1
    beqz  $v0, earlyExit
    sw    $v1, 0($sp)

busyloopLoop:
    lw    $v0, 0($sp)
    lw    $v1, 0($sp)
    nop
    addiu $v1, -1
    bnez  $v0, busyloopLoop
    sw    $v1, 0($sp)

earlyExit:
    jr    $ra
    nop
