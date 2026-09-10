/*

MIT License

Copyright (c) 2020 PCSX-Redux authors

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

/* void * fastMemset(void * ptr, int value, size_t num); */
/* http://man7.org/linux/man-pages/man3/memset.3.html */

/* Deliberately parallel to __wrap_memset in common/crt0/memory-s.s, and
 * deliberately a separate copy: openbios links this file and does not link
 * memory-s.s, and this one has to live in .ramtext.
 *
 * Four-word block, for the reasons set out in memory-s.s and measured by
 * src/mips/tests/memops-unroll. Main RAM drains at 2.10 cyc/word, four stores
 * per iteration already hides the loop tail underneath that, and anything
 * deeper is icache fill paid on every cold call for no gain per word. That
 * weighs more here than it does for the wrapped memset: sio0/pad.c calls this
 * on 0x22 bytes, a length that never reaches the block loop at all and would
 * still pay to pull the whole body in.
 *
 * The head is a single swr rather than a jumptable of byte stores. swr on an
 * already aligned address writes the whole word, so one instruction covers all
 * four alignments, and there is no separate count adjustment that can fall out
 * of step with the number of bytes actually stored.
 */

    .section .ramtext, "ax", @progbits
    .align 2
    .global fastMemset
    .type fastMemset, @function
    .set noreorder

fastMemset:
    beqz    $a2, .Lfast_done
    move    $v0, $a0

    bltu    $a2, 4, .Lfast_bytes
    andi    $a1, 255

    sll     $v1, $a1, 8
    or      $a1, $v1
    sll     $v1, $a1, 16
    or      $a1, $v1

    /* Align the destination with one unaligned store. swr on an already
       aligned address writes the whole word, so this costs four bytes of the
       count in the aligned case and needs no branch. */
    li      $t0, 4
    andi    $v1, $a0, 3
    subu    $t0, $v1
    subu    $a2, $t0
    swr     $a1, 0($a0)
    addu    $a0, $t0

    /* $a3 = destination + the largest multiple of 16 that fits in the count.
       Derived from the count BEFORE the mask, so an exact multiple of 16 does
       not lose its final block. */
    addu    $a3, $a0, $a2
    bltu    $a2, 16, .Lfast_words
    andi    $a2, 15
    subu    $a3, $a2

.Lfast_loop16:
    addiu   $a0, 16
    sw      $a1, -16($a0)
    sw      $a1, -12($a0)
    sw      $a1, -8($a0)
    bltu    $a0, $a3, .Lfast_loop16
    sw      $a1, -4($a0)

.Lfast_words:
    bltu    $a2, 4, .Lfast_bytes
    addu    $a3, $a0, $a2
    andi    $a2, 3
    subu    $a3, $a2

.Lfast_loop4:
    addiu   $a0, 4
    bltu    $a0, $a3, .Lfast_loop4
    sw      $a1, -4($a0)

.Lfast_bytes:
    beqz    $a2, .Lfast_done
    nop

.Lfast_loop1:
    addiu   $a2, -1
    sb      $a1, 0($a0)
    bnez    $a2, .Lfast_loop1
    addiu   $a0, 1

.Lfast_done:
    jr      $ra
    nop

    .size fastMemset, .-fastMemset
