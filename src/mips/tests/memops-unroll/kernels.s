/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

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

/* GENERATED - see gen.py. Copy and set kernels at varying unroll depth (U words
   per loop iteration) and batch depth (B words loaded before any is stored).
   Every kernel moves exactly `words` words; `words` is assumed a multiple of U. */

    .section .text, "ax", @progbits
    .set noreorder
    .align 2

    .global copy_b2_u2
    .type copy_b2_u2, @function
copy_b2_u2:
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a1, 8
    addiu  $a0, 8
    lw     $t0, -8($a1)
    lw     $t1, -4($a1)
    sw     $t0, -8($a0)
    bltu   $a0, $a3, 1b
    sw     $t1, -4($a0)
    jr     $ra
    nop
    .size copy_b2_u2, .-copy_b2_u2

    .global copy_b4_u4
    .type copy_b4_u4, @function
copy_b4_u4:
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a1, 16
    addiu  $a0, 16
    lw     $t0, -16($a1)
    lw     $t1, -12($a1)
    lw     $t2, -8($a1)
    lw     $t3, -4($a1)
    sw     $t0, -16($a0)
    sw     $t1, -12($a0)
    sw     $t2, -8($a0)
    bltu   $a0, $a3, 1b
    sw     $t3, -4($a0)
    jr     $ra
    nop
    .size copy_b4_u4, .-copy_b4_u4

    .global copy_b8_u8
    .type copy_b8_u8, @function
copy_b8_u8:
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a1, 32
    addiu  $a0, 32
    lw     $t0, -32($a1)
    lw     $t1, -28($a1)
    lw     $t2, -24($a1)
    lw     $t3, -20($a1)
    lw     $t4, -16($a1)
    lw     $t5, -12($a1)
    lw     $t6, -8($a1)
    lw     $t7, -4($a1)
    sw     $t0, -32($a0)
    sw     $t1, -28($a0)
    sw     $t2, -24($a0)
    sw     $t3, -20($a0)
    sw     $t4, -16($a0)
    sw     $t5, -12($a0)
    sw     $t6, -8($a0)
    bltu   $a0, $a3, 1b
    sw     $t7, -4($a0)
    jr     $ra
    nop
    .size copy_b8_u8, .-copy_b8_u8

    .global copy_b8_u16
    .type copy_b8_u16, @function
copy_b8_u16:
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a1, 64
    addiu  $a0, 64
    lw     $t0, -64($a1)
    lw     $t1, -60($a1)
    lw     $t2, -56($a1)
    lw     $t3, -52($a1)
    lw     $t4, -48($a1)
    lw     $t5, -44($a1)
    lw     $t6, -40($a1)
    lw     $t7, -36($a1)
    sw     $t0, -64($a0)
    sw     $t1, -60($a0)
    sw     $t2, -56($a0)
    sw     $t3, -52($a0)
    sw     $t4, -48($a0)
    sw     $t5, -44($a0)
    sw     $t6, -40($a0)
    sw     $t7, -36($a0)
    lw     $t0, -32($a1)
    lw     $t1, -28($a1)
    lw     $t2, -24($a1)
    lw     $t3, -20($a1)
    lw     $t4, -16($a1)
    lw     $t5, -12($a1)
    lw     $t6, -8($a1)
    lw     $t7, -4($a1)
    sw     $t0, -32($a0)
    sw     $t1, -28($a0)
    sw     $t2, -24($a0)
    sw     $t3, -20($a0)
    sw     $t4, -16($a0)
    sw     $t5, -12($a0)
    sw     $t6, -8($a0)
    bltu   $a0, $a3, 1b
    sw     $t7, -4($a0)
    jr     $ra
    nop
    .size copy_b8_u16, .-copy_b8_u16

    .global copy_b8_u32
    .type copy_b8_u32, @function
copy_b8_u32:
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a1, 128
    addiu  $a0, 128
    lw     $t0, -128($a1)
    lw     $t1, -124($a1)
    lw     $t2, -120($a1)
    lw     $t3, -116($a1)
    lw     $t4, -112($a1)
    lw     $t5, -108($a1)
    lw     $t6, -104($a1)
    lw     $t7, -100($a1)
    sw     $t0, -128($a0)
    sw     $t1, -124($a0)
    sw     $t2, -120($a0)
    sw     $t3, -116($a0)
    sw     $t4, -112($a0)
    sw     $t5, -108($a0)
    sw     $t6, -104($a0)
    sw     $t7, -100($a0)
    lw     $t0, -96($a1)
    lw     $t1, -92($a1)
    lw     $t2, -88($a1)
    lw     $t3, -84($a1)
    lw     $t4, -80($a1)
    lw     $t5, -76($a1)
    lw     $t6, -72($a1)
    lw     $t7, -68($a1)
    sw     $t0, -96($a0)
    sw     $t1, -92($a0)
    sw     $t2, -88($a0)
    sw     $t3, -84($a0)
    sw     $t4, -80($a0)
    sw     $t5, -76($a0)
    sw     $t6, -72($a0)
    sw     $t7, -68($a0)
    lw     $t0, -64($a1)
    lw     $t1, -60($a1)
    lw     $t2, -56($a1)
    lw     $t3, -52($a1)
    lw     $t4, -48($a1)
    lw     $t5, -44($a1)
    lw     $t6, -40($a1)
    lw     $t7, -36($a1)
    sw     $t0, -64($a0)
    sw     $t1, -60($a0)
    sw     $t2, -56($a0)
    sw     $t3, -52($a0)
    sw     $t4, -48($a0)
    sw     $t5, -44($a0)
    sw     $t6, -40($a0)
    sw     $t7, -36($a0)
    lw     $t0, -32($a1)
    lw     $t1, -28($a1)
    lw     $t2, -24($a1)
    lw     $t3, -20($a1)
    lw     $t4, -16($a1)
    lw     $t5, -12($a1)
    lw     $t6, -8($a1)
    lw     $t7, -4($a1)
    sw     $t0, -32($a0)
    sw     $t1, -28($a0)
    sw     $t2, -24($a0)
    sw     $t3, -20($a0)
    sw     $t4, -16($a0)
    sw     $t5, -12($a0)
    sw     $t6, -8($a0)
    bltu   $a0, $a3, 1b
    sw     $t7, -4($a0)
    jr     $ra
    nop
    .size copy_b8_u32, .-copy_b8_u32

    .global copy_b2_u32
    .type copy_b2_u32, @function
copy_b2_u32:
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a1, 128
    addiu  $a0, 128
    lw     $t0, -128($a1)
    lw     $t1, -124($a1)
    sw     $t0, -128($a0)
    sw     $t1, -124($a0)
    lw     $t0, -120($a1)
    lw     $t1, -116($a1)
    sw     $t0, -120($a0)
    sw     $t1, -116($a0)
    lw     $t0, -112($a1)
    lw     $t1, -108($a1)
    sw     $t0, -112($a0)
    sw     $t1, -108($a0)
    lw     $t0, -104($a1)
    lw     $t1, -100($a1)
    sw     $t0, -104($a0)
    sw     $t1, -100($a0)
    lw     $t0, -96($a1)
    lw     $t1, -92($a1)
    sw     $t0, -96($a0)
    sw     $t1, -92($a0)
    lw     $t0, -88($a1)
    lw     $t1, -84($a1)
    sw     $t0, -88($a0)
    sw     $t1, -84($a0)
    lw     $t0, -80($a1)
    lw     $t1, -76($a1)
    sw     $t0, -80($a0)
    sw     $t1, -76($a0)
    lw     $t0, -72($a1)
    lw     $t1, -68($a1)
    sw     $t0, -72($a0)
    sw     $t1, -68($a0)
    lw     $t0, -64($a1)
    lw     $t1, -60($a1)
    sw     $t0, -64($a0)
    sw     $t1, -60($a0)
    lw     $t0, -56($a1)
    lw     $t1, -52($a1)
    sw     $t0, -56($a0)
    sw     $t1, -52($a0)
    lw     $t0, -48($a1)
    lw     $t1, -44($a1)
    sw     $t0, -48($a0)
    sw     $t1, -44($a0)
    lw     $t0, -40($a1)
    lw     $t1, -36($a1)
    sw     $t0, -40($a0)
    sw     $t1, -36($a0)
    lw     $t0, -32($a1)
    lw     $t1, -28($a1)
    sw     $t0, -32($a0)
    sw     $t1, -28($a0)
    lw     $t0, -24($a1)
    lw     $t1, -20($a1)
    sw     $t0, -24($a0)
    sw     $t1, -20($a0)
    lw     $t0, -16($a1)
    lw     $t1, -12($a1)
    sw     $t0, -16($a0)
    sw     $t1, -12($a0)
    lw     $t0, -8($a1)
    lw     $t1, -4($a1)
    sw     $t0, -8($a0)
    bltu   $a0, $a3, 1b
    sw     $t1, -4($a0)
    jr     $ra
    nop
    .size copy_b2_u32, .-copy_b2_u32

    .global copy_b4_u32
    .type copy_b4_u32, @function
copy_b4_u32:
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a1, 128
    addiu  $a0, 128
    lw     $t0, -128($a1)
    lw     $t1, -124($a1)
    lw     $t2, -120($a1)
    lw     $t3, -116($a1)
    sw     $t0, -128($a0)
    sw     $t1, -124($a0)
    sw     $t2, -120($a0)
    sw     $t3, -116($a0)
    lw     $t0, -112($a1)
    lw     $t1, -108($a1)
    lw     $t2, -104($a1)
    lw     $t3, -100($a1)
    sw     $t0, -112($a0)
    sw     $t1, -108($a0)
    sw     $t2, -104($a0)
    sw     $t3, -100($a0)
    lw     $t0, -96($a1)
    lw     $t1, -92($a1)
    lw     $t2, -88($a1)
    lw     $t3, -84($a1)
    sw     $t0, -96($a0)
    sw     $t1, -92($a0)
    sw     $t2, -88($a0)
    sw     $t3, -84($a0)
    lw     $t0, -80($a1)
    lw     $t1, -76($a1)
    lw     $t2, -72($a1)
    lw     $t3, -68($a1)
    sw     $t0, -80($a0)
    sw     $t1, -76($a0)
    sw     $t2, -72($a0)
    sw     $t3, -68($a0)
    lw     $t0, -64($a1)
    lw     $t1, -60($a1)
    lw     $t2, -56($a1)
    lw     $t3, -52($a1)
    sw     $t0, -64($a0)
    sw     $t1, -60($a0)
    sw     $t2, -56($a0)
    sw     $t3, -52($a0)
    lw     $t0, -48($a1)
    lw     $t1, -44($a1)
    lw     $t2, -40($a1)
    lw     $t3, -36($a1)
    sw     $t0, -48($a0)
    sw     $t1, -44($a0)
    sw     $t2, -40($a0)
    sw     $t3, -36($a0)
    lw     $t0, -32($a1)
    lw     $t1, -28($a1)
    lw     $t2, -24($a1)
    lw     $t3, -20($a1)
    sw     $t0, -32($a0)
    sw     $t1, -28($a0)
    sw     $t2, -24($a0)
    sw     $t3, -20($a0)
    lw     $t0, -16($a1)
    lw     $t1, -12($a1)
    lw     $t2, -8($a1)
    lw     $t3, -4($a1)
    sw     $t0, -16($a0)
    sw     $t1, -12($a0)
    sw     $t2, -8($a0)
    bltu   $a0, $a3, 1b
    sw     $t3, -4($a0)
    jr     $ra
    nop
    .size copy_b4_u32, .-copy_b4_u32

    .global copy_b16_u16
    .type copy_b16_u16, @function
copy_b16_u16:
    addiu  $sp, -32
    sw     $s0, 0($sp)
    sw     $s1, 4($sp)
    sw     $s2, 8($sp)
    sw     $s3, 12($sp)
    sw     $s4, 16($sp)
    sw     $s5, 20($sp)
    sw     $s6, 24($sp)
    sw     $s7, 28($sp)
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a1, 64
    addiu  $a0, 64
    lw     $t0, -64($a1)
    lw     $t1, -60($a1)
    lw     $t2, -56($a1)
    lw     $t3, -52($a1)
    lw     $t4, -48($a1)
    lw     $t5, -44($a1)
    lw     $t6, -40($a1)
    lw     $t7, -36($a1)
    lw     $s0, -32($a1)
    lw     $s1, -28($a1)
    lw     $s2, -24($a1)
    lw     $s3, -20($a1)
    lw     $s4, -16($a1)
    lw     $s5, -12($a1)
    lw     $s6, -8($a1)
    lw     $s7, -4($a1)
    sw     $t0, -64($a0)
    sw     $t1, -60($a0)
    sw     $t2, -56($a0)
    sw     $t3, -52($a0)
    sw     $t4, -48($a0)
    sw     $t5, -44($a0)
    sw     $t6, -40($a0)
    sw     $t7, -36($a0)
    sw     $s0, -32($a0)
    sw     $s1, -28($a0)
    sw     $s2, -24($a0)
    sw     $s3, -20($a0)
    sw     $s4, -16($a0)
    sw     $s5, -12($a0)
    sw     $s6, -8($a0)
    bltu   $a0, $a3, 1b
    sw     $s7, -4($a0)
    lw     $s0, 0($sp)
    lw     $s1, 4($sp)
    lw     $s2, 8($sp)
    lw     $s3, 12($sp)
    lw     $s4, 16($sp)
    lw     $s5, 20($sp)
    lw     $s6, 24($sp)
    lw     $s7, 28($sp)
    jr     $ra
    addiu  $sp, 32
    .size copy_b16_u16, .-copy_b16_u16

    .global copy_b16_u32
    .type copy_b16_u32, @function
copy_b16_u32:
    addiu  $sp, -32
    sw     $s0, 0($sp)
    sw     $s1, 4($sp)
    sw     $s2, 8($sp)
    sw     $s3, 12($sp)
    sw     $s4, 16($sp)
    sw     $s5, 20($sp)
    sw     $s6, 24($sp)
    sw     $s7, 28($sp)
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a1, 128
    addiu  $a0, 128
    lw     $t0, -128($a1)
    lw     $t1, -124($a1)
    lw     $t2, -120($a1)
    lw     $t3, -116($a1)
    lw     $t4, -112($a1)
    lw     $t5, -108($a1)
    lw     $t6, -104($a1)
    lw     $t7, -100($a1)
    lw     $s0, -96($a1)
    lw     $s1, -92($a1)
    lw     $s2, -88($a1)
    lw     $s3, -84($a1)
    lw     $s4, -80($a1)
    lw     $s5, -76($a1)
    lw     $s6, -72($a1)
    lw     $s7, -68($a1)
    sw     $t0, -128($a0)
    sw     $t1, -124($a0)
    sw     $t2, -120($a0)
    sw     $t3, -116($a0)
    sw     $t4, -112($a0)
    sw     $t5, -108($a0)
    sw     $t6, -104($a0)
    sw     $t7, -100($a0)
    sw     $s0, -96($a0)
    sw     $s1, -92($a0)
    sw     $s2, -88($a0)
    sw     $s3, -84($a0)
    sw     $s4, -80($a0)
    sw     $s5, -76($a0)
    sw     $s6, -72($a0)
    sw     $s7, -68($a0)
    lw     $t0, -64($a1)
    lw     $t1, -60($a1)
    lw     $t2, -56($a1)
    lw     $t3, -52($a1)
    lw     $t4, -48($a1)
    lw     $t5, -44($a1)
    lw     $t6, -40($a1)
    lw     $t7, -36($a1)
    lw     $s0, -32($a1)
    lw     $s1, -28($a1)
    lw     $s2, -24($a1)
    lw     $s3, -20($a1)
    lw     $s4, -16($a1)
    lw     $s5, -12($a1)
    lw     $s6, -8($a1)
    lw     $s7, -4($a1)
    sw     $t0, -64($a0)
    sw     $t1, -60($a0)
    sw     $t2, -56($a0)
    sw     $t3, -52($a0)
    sw     $t4, -48($a0)
    sw     $t5, -44($a0)
    sw     $t6, -40($a0)
    sw     $t7, -36($a0)
    sw     $s0, -32($a0)
    sw     $s1, -28($a0)
    sw     $s2, -24($a0)
    sw     $s3, -20($a0)
    sw     $s4, -16($a0)
    sw     $s5, -12($a0)
    sw     $s6, -8($a0)
    bltu   $a0, $a3, 1b
    sw     $s7, -4($a0)
    lw     $s0, 0($sp)
    lw     $s1, 4($sp)
    lw     $s2, 8($sp)
    lw     $s3, 12($sp)
    lw     $s4, 16($sp)
    lw     $s5, 20($sp)
    lw     $s6, 24($sp)
    lw     $s7, 28($sp)
    jr     $ra
    addiu  $sp, 32
    .size copy_b16_u32, .-copy_b16_u32

    .global set_u1
    .type set_u1, @function
set_u1:
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a0, 4
    bltu   $a0, $a3, 1b
    sw     $a1, -4($a0)
    jr     $ra
    nop
    .size set_u1, .-set_u1

    .global set_u2
    .type set_u2, @function
set_u2:
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a0, 8
    sw     $a1, -8($a0)
    bltu   $a0, $a3, 1b
    sw     $a1, -4($a0)
    jr     $ra
    nop
    .size set_u2, .-set_u2

    .global set_u4
    .type set_u4, @function
set_u4:
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a0, 16
    sw     $a1, -16($a0)
    sw     $a1, -12($a0)
    sw     $a1, -8($a0)
    bltu   $a0, $a3, 1b
    sw     $a1, -4($a0)
    jr     $ra
    nop
    .size set_u4, .-set_u4

    .global set_u8
    .type set_u8, @function
set_u8:
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a0, 32
    sw     $a1, -32($a0)
    sw     $a1, -28($a0)
    sw     $a1, -24($a0)
    sw     $a1, -20($a0)
    sw     $a1, -16($a0)
    sw     $a1, -12($a0)
    sw     $a1, -8($a0)
    bltu   $a0, $a3, 1b
    sw     $a1, -4($a0)
    jr     $ra
    nop
    .size set_u8, .-set_u8

    .global set_u16
    .type set_u16, @function
set_u16:
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a0, 64
    sw     $a1, -64($a0)
    sw     $a1, -60($a0)
    sw     $a1, -56($a0)
    sw     $a1, -52($a0)
    sw     $a1, -48($a0)
    sw     $a1, -44($a0)
    sw     $a1, -40($a0)
    sw     $a1, -36($a0)
    sw     $a1, -32($a0)
    sw     $a1, -28($a0)
    sw     $a1, -24($a0)
    sw     $a1, -20($a0)
    sw     $a1, -16($a0)
    sw     $a1, -12($a0)
    sw     $a1, -8($a0)
    bltu   $a0, $a3, 1b
    sw     $a1, -4($a0)
    jr     $ra
    nop
    .size set_u16, .-set_u16

    .global set_u32
    .type set_u32, @function
set_u32:
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a0, 128
    sw     $a1, -128($a0)
    sw     $a1, -124($a0)
    sw     $a1, -120($a0)
    sw     $a1, -116($a0)
    sw     $a1, -112($a0)
    sw     $a1, -108($a0)
    sw     $a1, -104($a0)
    sw     $a1, -100($a0)
    sw     $a1, -96($a0)
    sw     $a1, -92($a0)
    sw     $a1, -88($a0)
    sw     $a1, -84($a0)
    sw     $a1, -80($a0)
    sw     $a1, -76($a0)
    sw     $a1, -72($a0)
    sw     $a1, -68($a0)
    sw     $a1, -64($a0)
    sw     $a1, -60($a0)
    sw     $a1, -56($a0)
    sw     $a1, -52($a0)
    sw     $a1, -48($a0)
    sw     $a1, -44($a0)
    sw     $a1, -40($a0)
    sw     $a1, -36($a0)
    sw     $a1, -32($a0)
    sw     $a1, -28($a0)
    sw     $a1, -24($a0)
    sw     $a1, -20($a0)
    sw     $a1, -16($a0)
    sw     $a1, -12($a0)
    sw     $a1, -8($a0)
    bltu   $a0, $a3, 1b
    sw     $a1, -4($a0)
    jr     $ra
    nop
    .size set_u32, .-set_u32

    .global set_u64
    .type set_u64, @function
set_u64:
    sll    $a2, 2
    addu   $a3, $a0, $a2
1:
    addiu  $a0, 256
    sw     $a1, -256($a0)
    sw     $a1, -252($a0)
    sw     $a1, -248($a0)
    sw     $a1, -244($a0)
    sw     $a1, -240($a0)
    sw     $a1, -236($a0)
    sw     $a1, -232($a0)
    sw     $a1, -228($a0)
    sw     $a1, -224($a0)
    sw     $a1, -220($a0)
    sw     $a1, -216($a0)
    sw     $a1, -212($a0)
    sw     $a1, -208($a0)
    sw     $a1, -204($a0)
    sw     $a1, -200($a0)
    sw     $a1, -196($a0)
    sw     $a1, -192($a0)
    sw     $a1, -188($a0)
    sw     $a1, -184($a0)
    sw     $a1, -180($a0)
    sw     $a1, -176($a0)
    sw     $a1, -172($a0)
    sw     $a1, -168($a0)
    sw     $a1, -164($a0)
    sw     $a1, -160($a0)
    sw     $a1, -156($a0)
    sw     $a1, -152($a0)
    sw     $a1, -148($a0)
    sw     $a1, -144($a0)
    sw     $a1, -140($a0)
    sw     $a1, -136($a0)
    sw     $a1, -132($a0)
    sw     $a1, -128($a0)
    sw     $a1, -124($a0)
    sw     $a1, -120($a0)
    sw     $a1, -116($a0)
    sw     $a1, -112($a0)
    sw     $a1, -108($a0)
    sw     $a1, -104($a0)
    sw     $a1, -100($a0)
    sw     $a1, -96($a0)
    sw     $a1, -92($a0)
    sw     $a1, -88($a0)
    sw     $a1, -84($a0)
    sw     $a1, -80($a0)
    sw     $a1, -76($a0)
    sw     $a1, -72($a0)
    sw     $a1, -68($a0)
    sw     $a1, -64($a0)
    sw     $a1, -60($a0)
    sw     $a1, -56($a0)
    sw     $a1, -52($a0)
    sw     $a1, -48($a0)
    sw     $a1, -44($a0)
    sw     $a1, -40($a0)
    sw     $a1, -36($a0)
    sw     $a1, -32($a0)
    sw     $a1, -28($a0)
    sw     $a1, -24($a0)
    sw     $a1, -20($a0)
    sw     $a1, -16($a0)
    sw     $a1, -12($a0)
    sw     $a1, -8($a0)
    bltu   $a0, $a3, 1b
    sw     $a1, -4($a0)
    jr     $ra
    nop
    .size set_u64, .-set_u64
