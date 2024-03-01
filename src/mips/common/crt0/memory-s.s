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

    /* $a3 = end of source - 32 */
    addu   $a3, $a1, $a2
    addiu  $a3, -32

    /* Copy the rest of the data, 32 bytes at a time */
    bltu   $a2, 32, .Lmemcpy_last32_aligned
    andi   $a2, 31

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
    addiu  $a3, -4

.Lmemcpy_loop4_aligned:
    lw     $t0, 0($a1)
    addiu  $a1, 4
    sw     $t0, 0($a0)
    addiu  $a0, 4
    bltu   $a1, $a3, .Lmemcpy_loop4_aligned
    addiu  $a2, -4

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

    bltu   $a2, 32, .Lmemcpy_last32_unaligned
    andi   $a2, 31

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
    addiu  $a3, -4

.Lmemcpy_loop4_unaligned:
    lw     $t0, 0($a1)
    addiu  $a1, 4
    swr    $t0, 0($a0)
    swl    $t0, 3($a0)
    addiu  $a0, 4
    bltu   $a1, $a3, .Lmemcpy_loop4_unaligned
    addiu  $a2, -4

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

    li     $t0, 4
    andi   $v1, $a0, 3
    subu   $t0, $v1

    subu   $a2, $t0
    swr    $a1, 0($a0)
    addu   $a0, $t0

    addu   $a3, $a0, $a2
    addiu  $a3, -32

    bltu   $a2, 32, .Lmemset_last32
    andi   $a2, 31

.Lmemset_loop32:
    addiu  $a0, 32
    sw     $a1, -32($a0)
    sw     $a1, -28($a0)
    sw     $a1, -24($a0)
    sw     $a1, -20($a0)
    sw     $a1, -16($a0)
    sw     $a1, -12($a0)
    sw     $a1, -8($a0)
    bltu   $a0, $a3, .Lmemset_loop32
    sw     $a1, -4($a0)

.Lmemset_last32:
    bltu   $a2, 4, .Lmemset_last4
    addu   $a3, $a0, $a2
    addiu  $a3, -4

.Lmemset_loop4:
    sw     $a1, 0($a0)
    addiu  $a0, 4
    bltu   $a0, $a3, .Lmemset_loop4
    addiu  $a2, -4

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
