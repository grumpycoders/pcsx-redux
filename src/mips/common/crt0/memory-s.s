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

/* Optimized memcpy and memset for the R3000A, reached through the linker's
 * -Wl,-wrap,memcpy / -Wl,-wrap,memset toggles. The plain memcpy below, and the
 * routines in memory-c.c, are the small default.
 *
 * THE BLOCK SIZES ARE MEASURED. src/mips/tests/memops-unroll sweeps both of
 * them on hardware; re-run it before changing either.
 *
 *   memcpy uses a 32-byte block: eight words loaded before any is stored. What
 *   pays here is that batch depth, not the loop count, because an uncached load
 *   overlaps the following independent instructions and the shadow takes about
 *   four of them to saturate. RAM->RAM over 16 KiB, cyc/word: batch 2 is 12.80,
 *   batch 4 is 9.18, batch 8 is 8.72. Holding the batch at eight and doubling
 *   the LOOP instead moves nothing - 35697 ticks at eight words per iteration
 *   against 35698 at thirty-two, over the same 4096 words. Batch 16 was only
 *   measured on a 1 KiB buffer, where it sat inside the harness's own noise,
 *   and it costs eight callee-saved spills to reach. These are quoted at 16 KiB
 *   deliberately: at 1 KiB a single-digit percentage here is not
 *   distinguishable from where the code happened to land in a 4 KiB
 *   direct-mapped icache.
 *
 *   memset uses a 16-byte block: four words. Back-to-back stores into main RAM
 *   run at 2.15 cyc/store and are bandwidth bound, while a store with three or
 *   more independent instructions behind it is absorbed completely - so four
 *   stores per iteration is where the loop tail disappears underneath the
 *   drain. Measured cyc/word by depth: 4.05 at one word, 2.59 at two, then flat
 *   from four out to sixty-four (2.10 at both ends over 16 KiB). Nothing above
 *   four is left to win, and there is something to lose - the icache is 4 KiB,
 *   direct mapped, one word per line with no spatial prefetch, so a longer body
 *   is a longer fill on every cold call. Each kernel's own cold first call
 *   against its own warm minimum: +8% for this four-store body, +35% for a
 *   sixty-four store one.
 *
 * THE BLOCK LOOPS END ON "start + count with the remainder removed", and must.
 * Written as "end - blocksize" instead, the mask that follows has already
 * discarded the fact that a whole block is still owed, so a count that is an
 * exact multiple of the block size silently loses its last one. The unaligned
 * memcpy path carries the same trap one step further along: its end has to come
 * from the count BEFORE the mask, or it lands below the source pointer and the
 * loop runs exactly once whatever the length. src/mips/tests/{memcpy,memset}
 * sweep lengths rather than sampling them, which is what holds both.
 */

    .section .text___wrap_memcpy, "ax", @progbits
    .set noreorder
    .align 2
    .global __wrap_memcpy
    .type __wrap_memcpy, @function

__wrap_memcpy:
    /* Do we have less than 4 bytes to copy? */
    bltu   $a2, 4, .Lmemcpy_last4
    /* Setting return value to $a0 (destination), in the bltu delay slot */
    move   $v0, $a0

    /* Check if both source and destination are aligned to 4 bytes */
    xor    $t8, $a0, $a1
    andi   $t8, 3
    bnez   $t8, .Lmemcpy_unaligned

    /* Copy the first, potentially unaligned bytes */
    li     $t0, 4
    andi   $v1, $a0, 3
    subu   $t0, $v1

    subu   $a2, $t0
    lwr    $t8, 0($a1)
    addu   $a1, $t0
    swr    $t8, 0($a0)
    addu   $a0, $t0

    /* $a3 = source + the largest multiple of 32 that fits in the count. Derive
       it from the count BEFORE masking, then subtract the remainder; "end - 32"
       loses the final block on exact multiples of 32. */
    addu   $a3, $a1, $a2
    bltu   $a2, 32, .Lmemcpy_last32_aligned
    andi   $a2, 31
    subu   $a3, $a2

.Lmemcpy_loop32_aligned:
    lw     $t0, 0($a1)
    lw     $t1, 4($a1)
    lw     $t2, 8($a1)
    lw     $t3, 12($a1)
    lw     $t4, 16($a1)
    lw     $t5, 20($a1)
    lw     $t6, 24($a1)
    lw     $t7, 28($a1)
    addiu  $a1, 32
    sw     $t0, 0($a0)
    sw     $t1, 4($a0)
    sw     $t2, 8($a0)
    sw     $t3, 12($a0)
    sw     $t4, 16($a0)
    sw     $t5, 20($a0)
    sw     $t6, 24($a0)
    sw     $t7, 28($a0)
    bltu   $a1, $a3, .Lmemcpy_loop32_aligned
    addiu  $a0, 32

.Lmemcpy_last32_aligned:
    bltu   $a2, 4, .Lmemcpy_last4
    addu   $a3, $a1, $a2
    andi   $a2, 3
    subu   $a3, $a2

.Lmemcpy_loop4_aligned:
    lw     $t0, 0($a1)
    addiu  $a1, 4
    addiu  $a0, 4
    bltu   $a1, $a3, .Lmemcpy_loop4_aligned
    sw     $t0, -4($a0)

    b      .Lmemcpy_last4
    nop

.Lmemcpy_unaligned:
    /* Copy the first, potentially unaligned bytes,
    in order to bring the source to an aligned address */
    li     $t4, 4
    andi   $v1, $a1, 3
    subu   $t4, $v1
    sll    $v1, 2

    la     $t5, .Lmemcpy_read_first4
    addu   $t5, $v1
    jr     $t5
    subu   $a2, $t4
.Lmemcpy_read_first4:
    lbu    $t3, 3($a1)
    lbu    $t2, 2($a1)
    lbu    $t1, 1($a1)
    lbu    $t0, 0($a1)

    la     $t5, .Lmemcpy_write_first4
    addu   $t5, $v1
    jr     $t5
    addu   $a1, $t4
.Lmemcpy_write_first4:
    sb     $t3, 3($a0)
    sb     $t2, 2($a0)
    sb     $t1, 1($a0)
    sb     $t0, 0($a0)
    addu   $a0, $t4

    /* Same derivation as the aligned path, and the order is load bearing: mask
       the count first and $a3 comes out BELOW $a1, which makes this loop run
       exactly once whatever the length. */
    addu   $a3, $a1, $a2
    bltu   $a2, 32, .Lmemcpy_last32_unaligned
    andi   $a2, 31
    subu   $a3, $a2

.Lmemcpy_loop32_unaligned:
    lw     $t0, 0($a1)
    lw     $t1, 4($a1)
    lw     $t2, 8($a1)
    lw     $t3, 12($a1)
    lw     $t4, 16($a1)
    lw     $t5, 20($a1)
    lw     $t6, 24($a1)
    lw     $t7, 28($a1)
    addiu  $a1, 32
    swr    $t0, 0($a0)
    swl    $t0, 3($a0)
    swr    $t1, 4($a0)
    swl    $t1, 7($a0)
    swr    $t2, 8($a0)
    swl    $t2, 11($a0)
    swr    $t3, 12($a0)
    swl    $t3, 15($a0)
    swr    $t4, 16($a0)
    swl    $t4, 19($a0)
    swr    $t5, 20($a0)
    swl    $t5, 23($a0)
    swr    $t6, 24($a0)
    swl    $t6, 27($a0)
    swr    $t7, 28($a0)
    swl    $t7, 31($a0)
    bltu   $a1, $a3, .Lmemcpy_loop32_unaligned
    addiu  $a0, 32

.Lmemcpy_last32_unaligned:
    bltu   $a2, 4, .Lmemcpy_last4
    addu   $a3, $a1, $a2
    andi   $a2, 3
    subu   $a3, $a2

.Lmemcpy_loop4_unaligned:
    lw     $t0, 0($a1)
    addiu  $a1, 4
    addiu  $a0, 4
    swr    $t0, -4($a0)
    bltu   $a1, $a3, .Lmemcpy_loop4_unaligned
    swl    $t0, -1($a0)

.Lmemcpy_last4:
    beqz   $a2, .Lmemcpy_done
    nop

    /* Copy the last few bytes */
.Lmemcpy_loop1:
    addiu  $a2, -1
    lb     $t0, 0($a1)
    addiu  $a1, 1
    sb     $t0, 0($a0)
    bnez   $a2, .Lmemcpy_loop1
    addiu  $a0, 1

.Lmemcpy_done:
    jr     $ra
    nop

    .size __wrap_memcpy, .-__wrap_memcpy

    .section .text_memcpy, "ax", @progbits
    .align 2
    .global memcpy
    .weak memcpy
    .type memcpy, @function
memcpy:
    beqz   $a2, 2f
    move   $v0, $a0
    addu   $a3, $a1, $a2

1:
    lbu    $v1, 0($a1)
    addiu  $a1, 1
    sb     $v1, 0($a0)
    bne    $a1, $a3, 1b
    addiu  $a0, 1

2:
    jr     $ra
    nop

    .size memcpy, .-memcpy

    .section .text___wrap_memset, "ax", @progbits
    .align 2
    .global __wrap_memset
    .type __wrap_memset, @function
__wrap_memset:
    bltu   $a2, 4, .Lmemset_last4
    move   $v0, $a0

    andi   $a1, 255
    sll    $v1, $a1, 8
    or     $a1, $v1
    sll    $v1, $a1, 16
    or     $a1, $v1

    /* Align the destination with a single unaligned store. swr on an already
       aligned address writes the whole word, so the aligned case costs four
       bytes of the count and no branch. */
    li     $t0, 4
    andi   $v1, $a0, 3
    subu   $t0, $v1

    subu   $a2, $t0
    swr    $a1, 0($a0)
    addu   $a0, $t0

    /* $a3 = destination + the largest multiple of 16 that fits in the count. */
    addu   $a3, $a0, $a2
    bltu   $a2, 16, .Lmemset_last16
    andi   $a2, 15
    subu   $a3, $a2

.Lmemset_loop16:
    addiu  $a0, 16
    sw     $a1, -16($a0)
    sw     $a1, -12($a0)
    sw     $a1, -8($a0)
    bltu   $a0, $a3, .Lmemset_loop16
    sw     $a1, -4($a0)

.Lmemset_last16:
    bltu   $a2, 4, .Lmemset_last4
    addu   $a3, $a0, $a2
    andi   $a2, 3
    subu   $a3, $a2

.Lmemset_loop4:
    addiu  $a0, 4
    bltu   $a0, $a3, .Lmemset_loop4
    sw     $a1, -4($a0)

.Lmemset_last4:
    beqz   $a2, .Lmemset_done
    nop

.Lmemset_loop1:
    addiu  $a2, -1
    sb     $a1, 0($a0)
    bnez   $a2, .Lmemset_loop1
    addiu  $a0, 1

.Lmemset_done:
    jr     $ra
    nop

    .size __wrap_memset, .-__wrap_memset
