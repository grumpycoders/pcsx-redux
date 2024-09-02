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

    .section .text.exceptionHandler, "ax", @progbits
    .set push
    .set noreorder
    .set noat
    .align 2
    .global psyqoAssemblyExceptionHandler
    .global psyqoExceptionHandler
    .global psyqoExceptionHandlerAdjustFrameCount
    .type psyqoAssemblyExceptionHandler, @function

psyqoAssemblyExceptionHandler:
    sw    $at, 0x100($0)
    sw    $v0, 0x104($0)
    sw    $v1, 0x108($0)
    sw    $a0, 0x10c($0)

    mfc0  $v0, $13         /* $v0 = Cause */
    mfc0  $k1, $14         /* $k1 = EPC */
    lui   $k0, 0x1f80      /* $k0 = hardware registers base */
    lw    $v1, 0($k1)      /* $v1 = instruction that caused the exception */
    andi  $v0, 0x7c        /* Test for what kind of exception */
.Lstop:                    /* psyqo will only support IRQs, aka 0 */
    bnez  $v0, .Lstop      /* Anything else and we just stop - $v0 available again */
    srl   $v1, 24          /* \                                      */
    andi  $v1, 0xfe        /*  | Test if we were in a cop2 operation */
    li    $at, 0x4a        /* /                                      */
    lw    $a0, 0x1070($k0) /* $a0 = IREG */
    bne   $v1, $at, .LnoCOP2adjustmentNeeded
    nop
    addiu $k1, 4           /* If we were in cop2, we need to adjust the EPC */
.LnoCOP2adjustmentNeeded:
    andi  $v1, $a0, 1      /* Is it VBlank ? */
    beqz  $v1, .LnotVBlank
    andi  $v1, $a0, 0xfffe
    sw    $v1, 0x1070($k0) /* ACK VBlank IRQ, $k0 not needed anymore */
psyqoExceptionHandlerAdjustFrameCount:
    lui   $k0, 0
    lw    $v0, 0($k0)      /* $v0 = m_frameCount */
    lw    $at, 0x100($0)   /* Load the old at */
    addiu $v0, 1           /* Increment m_frameCount */
    sw    $v0, 0($k0)      /* Store m_frameCount */
    lw    $v0, 0x104($0)   /* Load the old v0 */
    lw    $v1, 0x108($0)   /* Load the old v1 */
    lw    $a0, 0x10c($0)   /* Load the old a0 */
    jr    $k1              /* Exit the exception handler */
    rfe

.LnotVBlank:
    /* We want to call into C++ now, so we need to save the rest of the registers */
    sw    $a1, 0x110($0)
    sw    $a2, 0x114($0)
    sw    $a3, 0x118($0)
    sw    $t0, 0x11c($0)
    sw    $t1, 0x120($0)
    sw    $t2, 0x124($0)
    sw    $t3, 0x128($0)
    sw    $t4, 0x12c($0)
    sw    $t5, 0x130($0)
    sw    $t6, 0x134($0)
    sw    $t7, 0x138($0)
    sw    $s0, 0x13c($0)
    sw    $s1, 0x140($0)
    sw    $s2, 0x144($0)
    sw    $s3, 0x148($0)
    sw    $s4, 0x14c($0)
    sw    $s5, 0x150($0)
    sw    $s6, 0x154($0)
    sw    $s7, 0x158($0)
    sw    $t8, 0x15c($0)
    sw    $t9, 0x160($0)
    sw    $gp, 0x164($0)
    sw    $sp, 0x168($0)
    sw    $fp, 0x16c($0)
    sw    $ra, 0x170($0)

    /* Call the C++ exception handler while adjusting the stack */
    jal   psyqoExceptionHandler
    li    $sp, 0x1000 - 16

    /* Restore the registers and exit */
    lw    $a1, 0x110($0)
    lw    $a2, 0x114($0)
    lw    $a3, 0x118($0)
    lw    $t0, 0x11c($0)
    lw    $t1, 0x120($0)
    lw    $t2, 0x124($0)
    lw    $t3, 0x128($0)
    lw    $t4, 0x12c($0)
    lw    $t5, 0x130($0)
    lw    $t6, 0x134($0)
    lw    $t7, 0x138($0)
    lw    $s0, 0x13c($0)
    lw    $s1, 0x140($0)
    lw    $s2, 0x144($0)
    lw    $s3, 0x148($0)
    lw    $s4, 0x14c($0)
    lw    $s5, 0x150($0)
    lw    $s6, 0x154($0)
    lw    $s7, 0x158($0)
    lw    $t8, 0x15c($0)
    lw    $t9, 0x160($0)
    lw    $gp, 0x164($0)
    lw    $sp, 0x168($0)
    lw    $fp, 0x16c($0)
    lw    $ra, 0x170($0)
    jr    $k1
    rfe
