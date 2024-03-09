/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

/* This version of the cache flush routine is designed to be used from
   the main ram, and is completely position-independent. This is inspired
   from a main-ram version of FlushCache found in the PAL game TOCA World
   Touring Cars, SLES-02572. The order of operations is important: the
   BIU_CONFIG register has to be modified *after* changing cop0 Status.
   Note that normally, nops are required after mutating cop0 Status or
   BIU_CONFIG, but since we are running from uncached ram, the pipeline
   stalls caused by accessing the SDRAM are enough. */

    .section .text.flushCache, "ax", @progbits
    .align 2
    .set noreorder
    .global flushCache
    .type flushCache, @function

flushCache:
    /* Saves $ra to $t6, and the current cop0 Status register to $t0, and ensure we
       are running from uncached ram. */
    li    $t1, 0xa0000000
    move  $t6, $ra
    bal   1f
    mfc0  $t0, $12
1:
    or    $t1, $ra, $t1
    addiu $t1, 4 * 4 /* Jumps to the next instruction after the delay slot. */
    jr    $t1

    /* First, disables interrupts. */
    mtc0  $0, $12

    /* Writes 0x0001e90c to the BIU_CONFIG register at 0xfffe0130.
       This will let us continue to run from uncached memory, while
       allowing us to access the i-cache. We keep the constant in
       $t2, so we can reuse it later when re-enabling the i-cache. */
    li    $t5, BIU_CONFIG
    li    $t2, 0x0001e90c
    sw    $t2, 0($t5)

    /* Isolates the cache, and disables interrupts. */
    li    $t1, 0x10000
    mtc0  $t1, $12

    /* Clears only the relevant parts of the i-cache. */
    li    $t3, 0
    li    $t4, 0x0f80

1:
    sw    $0, 0x00($t3)
    sw    $0, 0x10($t3)
    sw    $0, 0x20($t3)
    sw    $0, 0x30($t3)
    sw    $0, 0x40($t3)
    sw    $0, 0x50($t3)
    sw    $0, 0x60($t3)
    sw    $0, 0x70($t3)
    bne   $t3, $t4, 1b
    addiu $t3, 0x80

    /* First, un-isolate the cache. */
    mtc0  $0, $12
    /* Then, restore the BIU_CONFIG register to 0x0001e988. */
    addiu $t2, 0x7c
    sw    $t2, 0($t5)
    /* Finally, restore the cop0 Status register, and return. It
       might be unwise to do the mtc0 in the jr delay slot, in
       case we arrive back at a cop2 instruction, but further
       testing could be useful. */
    mtc0  $t0, $12
    jr    $t6
    nop
