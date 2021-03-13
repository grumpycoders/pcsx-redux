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

    .set push
    .set noreorder
    .section .ramtext, "ax", @progbits

/* The exception handler seems to have some patching code
   here and there, using all these nops in the code, so it
   might be a good idea to keep it verbatim the same. 
   Maybe this can change later after understanding the
   patches a bit better. */

/* Why did they need to have this as a subfunction...? */
    .align 2
    .type getCop0CauseAndEPC, @function
getCop0CauseAndEPC:
    mfc0  $v0, $13
    mfc0  $v1, $14
    jr    $ra
    nop

    .align 2
    .global exceptionHandler
    .type exceptionHandler, @function
exceptionHandler:
    nop
    nop
    nop
    nop
    li    $k0, %lo(__globals)
    lw    $k0, 8($k0) /* ->processes[0] */
    nop
    lw    $k0, 0($k0) /* thread */
    nop
    addi  $k0, 8 /* &->Registers */
    /* From here on, $k0 is the pointer to the registers structure. */
    sw    $at, 0x04($k0)
    sw    $v0, 0x08($k0)
    sw    $v1, 0x0c($k0)
    sw    $ra, 0x7c($k0)
    jal   getCop0CauseAndEPC /* v0 = Cause, v1 = EPC */
    nop
    andi  $v0, 0x3c /* tests for excode 00 and 08, interrupt and syscall */
    bnez  $v0, noCOP2adjustmentNeeded
    nop
    lw    $v0, 0($v1) /* reads the opcode that caused the exception */
    nop
    srl   $v0, 24   /* were we in a cop2 operation ? */
    andi  $v0, 0xfe /* really weird way to compute this by the way */
    li    $at, 0x4a
    bne   $v0, $at, noCOP2adjustmentNeeded
    nop
    addi  $v1, 4    /* yup, we need to adjust our return PC
                       if we were in a cop2 operation, because
                       the silicon is bad. */
noCOP2adjustmentNeeded:
    sw    $v1, 0x80($k0)

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

    sw    $a0, 0x10($k0)
    sw    $a1, 0x14($k0)
    sw    $a2, 0x18($k0)
    sw    $a3, 0x1c($k0)

    mfc0  $a0, $12
    nop
    sw    $a0, 0x8c($k0)

    mfc0  $a1, $13
    nop
    sw    $a1, 0x90($k0)

    sw    $k1, 0x6c($k0)

    sw    $s0, 0x40($k0)
    sw    $s1, 0x44($k0)
    sw    $s2, 0x48($k0)
    sw    $s3, 0x4c($k0)
    sw    $s4, 0x50($k0)
    sw    $s5, 0x54($k0)
    sw    $s6, 0x58($k0)
    sw    $s7, 0x5c($k0)

    sw    $t0, 0x20($k0)
    sw    $t1, 0x24($k0)
    sw    $t2, 0x28($k0)
    sw    $t3, 0x2c($k0)
    sw    $t4, 0x30($k0)
    sw    $t5, 0x34($k0)
    sw    $t6, 0x38($k0)
    sw    $t7, 0x3c($k0)

    sw    $t8, 0x60($k0)
    sw    $t9, 0x64($k0)

    sw    $gp, 0x70($k0)
    sw    $sp, 0x74($k0)
    sw    $fp, 0x78($k0)

    mfhi  $a0
    nop
    sw    $a0, 0x84($k0)

    mflo  $a0
    nop
    sw    $a0, 0x88($k0)

    lui   $sp, %hi(g_exceptionStackPtr)
    li    $s3, %lo(__globals)
    lw    $sp, %lo(g_exceptionStackPtr)($sp)
    lw    $s3, 0($s3)

    lui   $gp, 0 /* None of the code actually uses $gp, */
    addiu $gp, 0 /* and I am not in the mood to set an area for it. */

    /* Even $fp is not used, but whatever. */
    move  $fp, $sp
    
    /* Now to call the handlers. I would rather do this in C, but
       it might break patches potentially. */
    addi  $s4, $s3, 0x20

priority_loop:
    lw    $s6, 0($s3)
    nop
    beqz  $s6, next_priority
    nop

handlers_loop:
    lw    $s1, 8($s6) /* ->verifier */
    lw    $s0, 4($s6) /* ->handler */
    beqz  $s1, next_handler
    nop
    jalr  $s1 /* call the verifier first */
    nop
    beqz  $v0, next_handler
    nop
    beqz  $s0, next_handler
    move  $a0, $v0
    jalr  $s0 /* then the handler */
    nop

next_handler:
    lw    $s6, 0($s6) /* ->next */
    nop
    bnez  $s6, handlers_loop
    nop

next_priority:
    addi  $s3, 8
    bne   $s4, $s3, priority_loop
    nop

    /* nobody took the call ? then longjmp into the unhandled exception buffer. */
    li    $k0, %lo(__globals) /* no idea why k0 is used again here... */
    lw    $k0, 8($k0) /* ->processes[0] */
    lui   $a0, %hi(g_exceptionJmpBufPtr)
    lw    $k0, 0($k0) /* thread */
    addiu $a0, %lo(g_exceptionJmpBufPtr)
    lw    $a0, 0($a0) /* such bad code... why... */
    li    $a1, 1 /* whyyyyy */
    addi  $k0, 8 /* whyyyyy */

    /* And process the longjmp now */
    lw    $ra, 0x00($a0)
    lw    $gp, 0x2c($a0)
    lw    $sp, 0x04($a0)
    lw    $fp, 0x08($a0)
    lw    $s0, 0x0c($a0)
    lw    $s1, 0x10($a0)
    lw    $s2, 0x14($a0)
    lw    $s3, 0x18($a0)
    lw    $s4, 0x1c($a0)
    lw    $s5, 0x20($a0)
    lw    $s6, 0x24($a0)
    lw    $s7, 0x28($a0)
    move  $v0, $a1 /* *sigh...* */
    jr    $ra
    nop

/* Not a verbatim copy, because there should not
   be patches onto it, hopefully. The original code
   has several layers of bad. */
    .align 2
    .global returnFromException
    .type returnFromException, @function
returnFromException:
    li    $k1, %lo(__globals)
    lw    $k1, 8($k1) /* ->TCBArrayPtr */
    nop
    lw    $k1, 0($k1) /* [0] */
    nop
    lw    $v0, 0x90($k1) /* lo */
    addiu $k1, 8
    mtlo  $v0
    lw    $v1, 0x84($k1) /* hi */
    lw    $k0, 0x80($k1) /* return PC */
    mthi  $v1
    lw    $a1, 0x8c($k1) /* Status */
    /* 00 is zero */
    lw    $at, 0x04($k1)
    mtc0  $a1, $12
    lw    $v0, 0x08($k1)
    lw    $v1, 0x0c($k1)
    lw    $a0, 0x10($k1)
    lw    $a1, 0x14($k1)
    lw    $a2, 0x18($k1)
    lw    $a3, 0x1c($k1)
    lw    $t0, 0x20($k1)
    lw    $t1, 0x24($k1)
    lw    $t2, 0x28($k1)
    lw    $t3, 0x2c($k1)
    lw    $t4, 0x30($k1)
    lw    $t5, 0x34($k1)
    lw    $t6, 0x38($k1)
    lw    $t7, 0x3c($k1)
    lw    $s0, 0x40($k1)
    lw    $s1, 0x44($k1)
    lw    $s2, 0x48($k1)
    lw    $s3, 0x4c($k1)
    lw    $s4, 0x50($k1)
    lw    $s5, 0x54($k1)
    lw    $s6, 0x58($k1)
    lw    $s7, 0x5c($k1)
    lw    $t8, 0x60($k1)
    lw    $t9, 0x64($k1)
    /* 68 is k0 */
    lw    $gp, 0x70($k1)
    lw    $sp, 0x74($k1)
    lw    $fp, 0x78($k1)
    lw    $ra, 0x7c($k1)
    /* Some games rely on $k1 to stay invariant at all times, even during
       interrupts. See for example Batman - Gotham City Racer NTSC (SLUS-01141)
       between addresses 8002c43c and 8002c4d4, which contains an obvious
       but horrible piece of inline assembly that has no regard for MIPS ABI. */
    lw    $k1, 0x6c($k1)
    jr    $k0
    rfe

    .section .text, "ax", @progbits
    .align 2
    .global exceptionVector
    .type exceptionVector, @function

exceptionVector:
    li    $k0, %lo(exceptionHandler)
    jr    $k0
    nop
    nop

    .align 2
    .global A0Vector
    .global A0Handler
    .type A0Vector, @function

A0Vector:
    li    $t0, %lo(A0Handler)
    jr    $t0
    nop
    nop

    .align 2
    .global B0Vector
    .global B0Handler
    .type B0Vector, @function

B0Vector:
    li    $t0, %lo(B0Handler)
    jr    $t0
    nop
    nop

    .align 2
    .global C0Vector
    .global C0Handler
    .type C0Vector, @function

C0Vector:
    li    $t0, %lo(C0Handler)
    jr    $t0
    nop
    nop

    .align 2
    .section .ramtext, "ax", @progbits
    .global __ramA0table
    .type A0Handler, @function

A0Handler:
    li    $t0, %lo(__ramA0table)
    sll   $t2, $t1, 2
    add   $t2, $t0
    lw    $t2, 0($t2)
    li    $t0, 0xa0
    jr    $t2
    nop

    .align 2
    .global B0table
    .type B0Handler, @function

B0Handler:
    li    $t0, %lo(B0table)
    sll   $t2, $t1, 2
    add   $t2, $t0
    lw    $t2, 0($t2)
    li    $t0, 0xb0
    jr    $t2
    nop

    .align 2
    .global C0table
    .type C0Handler, @function

C0Handler:
    li    $t0, %lo(C0table)
    sll   $t2, $t1, 2
    add   $t2, $t0
    lw    $t2, 0($t2)
    li    $t0, 0xc0
    jr    $t2
    nop

    .align 2
    .global unimplementedThunk
    .global unimplemented
    .type unimplementedThunk, @function

unimplementedThunk:
    la    $v0, unimplemented
    move  $a0, $t0
    move  $a1, $t1
    jr    $v0
    move  $a2, $ra

    .align 2
    .global ramsyscall_printf
    .type ramsyscall_printf, @function

ramsyscall_printf:
    li    $t2, 0xa0
    jr    $t2
    li    $t1, 0x3f

    .align 2
    .section .text, "ax", @progbits
    .global romsyscall_printf
    .type romsyscall_printf, @function

romsyscall_printf:
    li    $t2, 0xa0
    jr    $t2
    li    $t1, 0x3f

    .set pop
