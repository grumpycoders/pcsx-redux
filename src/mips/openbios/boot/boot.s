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

.include "common/hardware/hwregs.inc"

    .section .boot, "ax", @progbits
    .align 2
    .global flushCache
    .global _reset
    .type _reset, @function

_reset:
    /* set bios memory bus width and speed. */
    li    $t0, (19 << 16) | 0x243f
    sw    $t0, SBUS_DEV2_CTRL

    nop

    /* set ram size */
    li    $t0, (5 << 9) | 0x188
    sw    $t0, RAM_SIZE

    /* this may be here to let the hardware pick up the new bus settings
       before moving on with the actual code. */
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

    /* jumping over the interrupt vector. */
    j     _boot


    .section .text, "ax", @progbits
    .align 2
    .global _boot
    .type _boot, @function

_boot:
    /* initializing all of the buses now */
    li    $t0, 0x31125
    sw    $t0, SBUS_COM_CTRL

    li    $t0, 0x1f000000
    sw    $t0, SBUS_DEV0_ADDR

    li    $t0, 0x1f802000
    sw    $t0, SBUS_DEV8_ADDR

    li    $t0, (19 << 16) | 0x243f
    sw    $t0, SBUS_DEV0_CTRL

    li    $t0, 0x200931e1
    sw    $t0, SBUS_DEV4_CTRL

    li    $t0, 0x20843
    sw    $t0, SBUS_DEV5_CTRL

    li    $t0, 0x3022
    sw    $t0, SBUS_DEV1_CTRL

    li    $t0, 0x70777
    sw    $t0, SBUS_DEV8_CTRL

    /* clearing out all registers */
    move  $1, $0
    move  $2, $0
    move  $3, $0
    move  $4, $0
    move  $5, $0
    move  $6, $0
    move  $7, $0
    move  $8, $0
    move  $9, $0
    move  $10, $0
    move  $11, $0
    move  $12, $0
    move  $13, $0
    move  $14, $0
    move  $15, $0
    move  $16, $0
    move  $17, $0
    move  $18, $0
    move  $19, $0
    move  $20, $0
    move  $21, $0
    move  $22, $0
    move  $23, $0
    move  $24, $0
    move  $25, $0
    move  $26, $0
    move  $27, $0
    move  $28, $0
    move  $29, $0
    move  $30, $0
    move  $31, $0

    jal  flushCache

    /* ensuring cop0 is fully reset */
    mtc0  $0, $7
    nop
    mtc0  $0, $3
    nop
    mtc0  $0, $5
    nop
    mtc0  $0, $6
    nop
    mtc0  $0, $9
    nop
    mtc0  $0, $11
    nop
    mtc0  $0, $12
    nop
    mtc0  $0, $13
    nop

    /* now we are ready for a typical crt0 */
    la    $t0, __data_start
    la    $t1, __data_end
    la    $t2, __rom_data_start

    beq   $t1, $t2, data_copy_skip

data_copy:
    lw    $t3, 0($t0)
    sw    $t3, 0($t2)
    addiu $t0, 4
    addiu $t2, 4
    bne   $t1, $t2, data_copy

data_copy_skip:
    la    $t0, __bss_start
    la    $t1, __bss_end

    beq   $t0, $t1, bss_init_skip

bss_init:
    sw    $0, 0($t0)
    addiu $t0, 4
    bne   $t0, $t1, bss_init

bss_init_skip:
    /* Displays the following:

      **********
      0123456789
      **********

    */
    li    $t3, 42
    lui   $t1, 0x1f00
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    li    $t0, 13
    sb    $t0, 0($t1)
    li    $t0, 10
    sb    $t0, 0($t1)
    li    $t0, '0'
    sb    $t0, 0($t1)
    addiu $t0, 1
    sb    $t0, 0($t1)
    addiu $t0, 1
    sb    $t0, 0($t1)
    addiu $t0, 1
    sb    $t0, 0($t1)
    addiu $t0, 1
    sb    $t0, 0($t1)
    addiu $t0, 1
    sb    $t0, 0($t1)
    addiu $t0, 1
    sb    $t0, 0($t1)
    addiu $t0, 1
    sb    $t0, 0($t1)
    addiu $t0, 1
    sb    $t0, 0($t1)
    addiu $t0, 1
    sb    $t0, 0($t1)
    li    $t0, 13
    sb    $t0, 0($t1)
    li    $t0, 10
    sb    $t0, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    sb    $t3, 0($t1)
    li    $t0, 13
    sb    $t0, 0($t1)
    li    $t0, 10
    sb    $t0, 0($t1)

    /* technically have to set $gp, but we are not using it, so, not */
    la    $sp, __sp
    move  $fp, $sp

    /* not sure it is needed a second time. */
    li    $t0, 0xb88
    sw    $t0, RAM_SIZE

    jal   _ucsdk_start

stop:
    b     stop
