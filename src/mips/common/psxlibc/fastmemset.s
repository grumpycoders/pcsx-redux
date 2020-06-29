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

    .section .ramtext, "ax", @progbits
    .align 2
    .global fastMemset
    .type fastMemset, @function
    .set noreorder

/* void * fastMemset(void * ptr, int value, size_t num); */
/* http://man7.org/linux/man-pages/man3/memset.3.html */

fastMemset:
    beqz    $a2, out
    move    $v0, $a0

    sltiu   $v1, $a2, 32
    beqz    $v1, large_enough
    move    $t0, $a1

    addu    $a2, $a0
    addiu   $a2, -1
small_memset_loop:
    sb		$a1, 0($a0)
    bne     $a0, $a2, small_memset_loop
    addiu   $a0, 1
    jr      $ra

large_enough:
    sll     $t0, 8
    or      $t0, $a1
    move    $a1, $t0
    sll     $t0, 16
    or      $a1, $t0

    andi    $v1, $a0, 3
    la      $t1, jumptable1
    sll     $t2, $v1, 2
    subu    $a2, $v1
    addu    $t2, $t1
    lw      $t1, 0($t2)
    srl     $t0, $a2, 8
    jr      $t1
    andi    $t1, $a2, 0xff

jumptable1:
    .word   sb0
    .word   sb3
    .word   sb2
    .word   sb1

sb3:
    sb      $t0, 0($a0)
    addiu   $a0, 1
sb2:
    sb      $t0, 0($a0)
    addiu   $a0, 1
sb1:
    sb      $t0, 0($a0)
    addiu   $a0, 1
sb0:

/* At this point, we have:
v0 - our return value
a0 - current, aligned pointer
a1 - our word to store
t0 - our big loop counter
t1 - the remainder counter to store
*/

    beqz    $t0, skip_big_loop

big_loop:
    addiu   $t0, -1
    sw		$a1, 0x0000($a0)
    sw		$a1, 0x0004($a0)
    sw		$a1, 0x0008($a0)
    sw		$a1, 0x000c($a0)
    sw		$a1, 0x0010($a0)
    sw		$a1, 0x0014($a0)
    sw		$a1, 0x0018($a0)
    sw		$a1, 0x001c($a0)
    sw		$a1, 0x0020($a0)
    sw		$a1, 0x0024($a0)
    sw		$a1, 0x0028($a0)
    sw		$a1, 0x002c($a0)
    sw		$a1, 0x0030($a0)
    sw		$a1, 0x0034($a0)
    sw		$a1, 0x0038($a0)
    sw		$a1, 0x003c($a0)
    sw		$a1, 0x0040($a0)
    sw		$a1, 0x0044($a0)
    sw		$a1, 0x0048($a0)
    sw		$a1, 0x004c($a0)
    sw		$a1, 0x0050($a0)
    sw		$a1, 0x0054($a0)
    sw		$a1, 0x0058($a0)
    sw		$a1, 0x005c($a0)
    sw		$a1, 0x0060($a0)
    sw		$a1, 0x0064($a0)
    sw		$a1, 0x0068($a0)
    sw		$a1, 0x006c($a0)
    sw		$a1, 0x0070($a0)
    sw		$a1, 0x0074($a0)
    sw		$a1, 0x0078($a0)
    sw		$a1, 0x007c($a0)
    sw		$a1, 0x0080($a0)
    sw		$a1, 0x0084($a0)
    sw		$a1, 0x0088($a0)
    sw		$a1, 0x008c($a0)
    sw		$a1, 0x0090($a0)
    sw		$a1, 0x0094($a0)
    sw		$a1, 0x0098($a0)
    sw		$a1, 0x009c($a0)
    sw		$a1, 0x00a0($a0)
    sw		$a1, 0x00a4($a0)
    sw		$a1, 0x00a8($a0)
    sw		$a1, 0x00ac($a0)
    sw		$a1, 0x00b0($a0)
    sw		$a1, 0x00b4($a0)
    sw		$a1, 0x00b8($a0)
    sw		$a1, 0x00bc($a0)
    sw		$a1, 0x00c0($a0)
    sw		$a1, 0x00c4($a0)
    sw		$a1, 0x00c8($a0)
    sw		$a1, 0x00cc($a0)
    sw		$a1, 0x00d0($a0)
    sw		$a1, 0x00d4($a0)
    sw		$a1, 0x00d8($a0)
    sw		$a1, 0x00dc($a0)
    sw		$a1, 0x00e0($a0)
    sw		$a1, 0x00e4($a0)
    sw		$a1, 0x00e8($a0)
    sw		$a1, 0x00ec($a0)
    sw		$a1, 0x00f0($a0)
    sw		$a1, 0x00f4($a0)
    sw		$a1, 0x00f8($a0)
    sw		$a1, 0x00fc($a0)
    bnez    $t0, big_loop
    addiu   $a0, 0x0100

skip_big_loop:
    beqz    $t1, out

    addu    $a2, $t1, $a0
    b       small_memset_loop
    addiu   $a2, -1

out:
    jr      $ra
    nop
