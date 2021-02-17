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

    .section .start, "ax", @progbits
    .set noreorder
    .align 2
    .global main
    .global _start
    .type _start, @function

_start:
    lw    $t2, SBUS_DEV8_CTRL
    lui   $t0, 8
    lui   $t1, 1
_check_dev8:
    bge   $t2, $t0, _store_dev8
    nop
    b     _check_dev8
    add   $t2, $t1
_store_dev8:
    sw    $t2, SBUS_DEV8_CTRL

    la    $t0, __bss_start
    la    $t1, __bss_end

    beq   $t0, $t1, _bss_init_skip
    nop

_bss_init:
    sw    $0, 0($t0)
    addiu $t0, 4
    bne   $t0, $t1, _bss_init
    nop

_bss_init_skip:

    la    $a1, _mainargv
    j     main
    li    $a0, 1

    .section .rodata, "a", @progbits
    .align 2
_mainargv:
    .word _progname
    .word 0
_progname:
    .string "PSX.EXE"
