/*

MIT License

Copyright (c) 2019 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

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

    /* psx.s configures the DRAM controller here, but we are going to do that
       after setting up DEV1/EXP3 as we have to probe a bit in there first. */
    nop
    nop
    nop
    nop

    /* this may be here to let the hardware pick up the new bus settings
       before moving on with the actual code. Also, some tools like IDA
       or even PCSX-Redux use it as a signature to detect this is a PS1
       BIOS file. */
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

.ascii "OpenBIOS"

    .section .text._boot, "ax", @progbits
    .align 2
    .global _boot
    .type _boot, @function

_boot:
    /* initializing all of the buses now */

    /* Floating time increased by 1 cycle from the default value in psx.s */
    li    $t0, 0x31225
    sw    $t0, SBUS_COM_CTRL

    li    $t0, 0x1f000000
    sw    $t0, SBUS_DEV0_ADDR

    li    $t0, 0x1f802000
    sw    $t0, SBUS_DEV8_ADDR

    /* 8 MB with a 16-bit bus, different value from the default one in psx.s */
    li    $t0, 0x1734ff
    sw    $t0, SBUS_DEV0_CTRL

    /* Read/write waitstates increased to 15 cycles from the default value in
       psx.s (for ZN-2, the ZN-1 BIOS uses the same configuration as psx.s) */
    li    $t0, 0x200931ff
    sw    $t0, SBUS_DEV4_CTRL

    /* 1 byte with an 8-bit bus, different value from the default one in psx.s
       (probably a failed attempt to set the CD-ROM region size to 0 bytes so
       that any access would have generated an exception) */
    li    $t0, 0x843
    sw    $t0, SBUS_DEV5_CTRL

    /* 2 MB with a 16-bit bus, different value from the default one in psx.s */
    li    $t0, 0x153410
    sw    $t0, SBUS_DEV1_CTRL

    /* 256 bytes with a 16-bit bus, different value from the default one in psx.s
       (the ZN-1/ZN-2 kernels actually use 0x71011/0x71077 respectively here, but
       it needs to be extended from 128 to 256 bytes in order for the writes to
       0x1f802080 not to crash on real hardware) */
    li    $t0, 0x81077
    sw    $t0, SBUS_DEV8_CTRL

    /* The ZN BIOS probes the board configuration register to determine the RAM
       layout and sets up both the DRAM controller and __globals60.ramsize
       accordingly. */
    lbu   $t1, ZN_BOARD_CONFIG
    la    $t0, _zn_ram_configs
    andi  $t1, 3
    sll   $t1, 1
    addu  $t0, $t1

    lhu   $t0, 0($t0)
    sw    $t0, RAM_SIZE

    /* clearing out all registers */
    .set push
    .set noat
    move  $1, $0
    .set pop
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

    /* Extra from OpenBIOS, not in the original BIOS:
       Enable cop2, as some games may rely on it being
       enabled as a side effect of the shell running,
       and our replacement shell does not enable it. */
    lui   $t0, 0x4000
    mtc0  $t0, $12
    nop

    /* Now we are ready for a typical crt0.
       The original bios does not do this, most likely
       for speed reasons. It would be more efficient to
       run these loops in RAM instead of the ROM. But
       we have enough code that would rely in all this
       to be set up already before starting, it would
       be a mistake to not do it here. */
    la    $t0, __data_start
    la    $t1, __data_end
    la    $t2, __rom_data_start

    beq   $t0, $t1, data_copy_skip

data_copy:
    lw    $t3, 0($t2)
    sw    $t3, 0($t0)
    addiu $t0, 4
    addiu $t2, 4
    bne   $t0, $t1, data_copy

data_copy_skip:
    la    $t0, __bss_start
    la    $t1, __bss_end

    beq   $t0, $t1, bss_init_skip

bss_init:
    sw    $0, 0($t0)
    addiu $t0, 4
    bne   $t0, $t1, bss_init

bss_init_skip:
    /* technically have to set $gp, but we are not using it, so, not */
    la    $sp, __sp
    move  $fp, $sp

    /* set __globals60.ramsize */
    lbu   $t1, ZN_BOARD_CONFIG
    la    $t0, _zn_ram_sizes
    andi  $t1, 3
    addu  $t0, $t1

    lbu   $t0, 0($t0)
    sw    $t0, 0x60($0)

    jal   _ucsdk_start

    li    $t0, 0x1f802080
    li    $t1, 10
    sb    $t1, 0($t0)
    sb    $t1, 1($t0)
stop:
    b     stop

    .section .rodata._zn_ram_configs, "a", @progbits
    .align 2
    .type _zn_ram_configs, @object

_zn_ram_configs:
    .hword 0xcbc /* 00: two 2 MB banks, bit 3 set */
    .hword 0xcb4 /* 01: two 2 MB banks */
    .hword 0xbb4 /* 10: single 8 MB bank */
    .hword 0xfa4 /* 11: two 8 MB banks */

    .section .rodata._zn_ram_sizes, "a", @progbits
    .align 1
    .type _zn_ram_sizes, @object

_zn_ram_sizes:
    .byte 4  /* 00: two 2 MB banks, bit 3 set */
    .byte 4  /* 01: two 2 MB banks */
    .byte 8  /* 10: single 8 MB bank */
    .byte 16 /* 11: two 8 MB banks */
