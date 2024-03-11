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

/* This flushCache is a variant of the one found in the common/hardware/flushcache.s
   file. It is a bit more straightforward as there is no need to ensure that the
   code is run from the 0xbfc bios space, since the syscall will ensure that. */

    .section .text.flushCache, "ax", @progbits
    .align 2
    .set noreorder
    .global flushCache
    .type flushCache, @function

flushCache:
    /* Saves the cop0 Status register to $t0. */
    mfc0  $t0, $12
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
    jr    $ra
    nop

/* The code below is still kept as a reference, since it was directly reversed
   from the retail bios, but it is not used anymore. */

    .section .text.flushCacheOriginal, "ax", @progbits
    .align 2
    .set reorder
    .global flushCacheOriginal
    .type flushCacheOriginal, @function

flushCacheOriginal:
    mfc0  $t3, $12
    nop

    /* Around this location, the retail bios does a bal to the next instruction,
       in order to ensure this is run from the 0xbfc bios space, since the next
       few instructions are going to effectively unplug all other busses from
       the main CPU. Since flushCache can only be called from that space,
       thanks to the syscall, this should not be necessary here.

       A few other changes from the retail bios:
         - the cop0 status register is mutated BEFORE unplugging the busses.
         - the register k0 is left untouched.
     */

    li    $t1, 0x10000
    mtc0  $t1, $12
    nop
    nop

    /* The BIU_CONFIG register at 0xfffe0130 is a bit of a mystery at the moment.
       Further investigation is required here to properly understand what this
       code does exactly. Educated guesses are saying this is replacing the main
       ram with a direct access to the i-caches. There seems to be a way to remap
       the scratchpad into a d-cache also. But until the purpose of this register
       is better understood, this code will remain an almost exact copy of the
       retail code, as to not cause any problem. */

    li    $t0, 0x804
    sw    $t0, BIU_CONFIG

    move  $t0, $0
    li    $t2, 0x1000

cache_init_1:
    sw    $0, 0x00($t0)
    sw    $0, 0x10($t0)
    sw    $0, 0x20($t0)
    sw    $0, 0x30($t0)
    sw    $0, 0x40($t0)
    sw    $0, 0x50($t0)
    sw    $0, 0x60($t0)
    sw    $0, 0x70($t0)
    addi  $t0, 0x80
    bne   $t0, $t2, cache_init_1

    mtc0  $0, $12
    nop

    li    $t0, 0x800
    sw    $t0, BIU_CONFIG

    mtc0  $t1, $12
    nop
    nop

    move  $t0, $0
    li    $t2, 0x1000

cache_init_2:
    sw    $0, 0x00($t0)
    sw    $0, 0x04($t0)
    sw    $0, 0x08($t0)
    sw    $0, 0x0c($t0)
    sw    $0, 0x10($t0)
    sw    $0, 0x14($t0)
    sw    $0, 0x18($t0)
    sw    $0, 0x1c($t0)
    sw    $0, 0x20($t0)
    sw    $0, 0x24($t0)
    sw    $0, 0x28($t0)
    sw    $0, 0x2c($t0)
    sw    $0, 0x30($t0)
    sw    $0, 0x34($t0)
    sw    $0, 0x38($t0)
    sw    $0, 0x3c($t0)
    sw    $0, 0x40($t0)
    sw    $0, 0x44($t0)
    sw    $0, 0x48($t0)
    sw    $0, 0x4c($t0)
    sw    $0, 0x50($t0)
    sw    $0, 0x54($t0)
    sw    $0, 0x58($t0)
    sw    $0, 0x5c($t0)
    sw    $0, 0x60($t0)
    sw    $0, 0x64($t0)
    sw    $0, 0x68($t0)
    sw    $0, 0x6c($t0)
    sw    $0, 0x70($t0)
    sw    $0, 0x74($t0)
    sw    $0, 0x78($t0)
    sw    $0, 0x7c($t0)
    addi  $t0, 0x80
    bne   $t0, $t2, cache_init_2

    mtc0  $0, $12
    nop

    li    $t0, 0xa0000000
    lw    $t1, 0($t0)
    lw    $t1, 0($t0)
    lw    $t1, 0($t0)
    lw    $t1, 0($t0)
    lw    $t1, 0($t0)
    lw    $t1, 0($t0)
    lw    $t1, 0($t0)
    lw    $t1, 0($t0)
    nop

    li    $t0, 0x1e988
    sw    $t0, BIU_CONFIG

    mtc0  $t3, $12
    nop

    jr    $ra
