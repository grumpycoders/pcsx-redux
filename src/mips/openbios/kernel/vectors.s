/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

    .set push
    .set noreorder
    .section .data, "ax", @progbits
    .align 2
    .global generalHandler
    .type generalHandler, @function

generalHandler:
    sw    $0, 0x400($0)
    .set push
    .set noat
    sw    $1, 0x404($0)
    .set pop
    sw    $2, 0x408($0)
    sw    $3, 0x40c($0)
    sw    $4, 0x410($0)
    sw    $5, 0x414($0)
    sw    $6, 0x418($0)
    sw    $7, 0x41c($0)
    sw    $8, 0x420($0)
    sw    $9, 0x424($0)
    sw    $10, 0x428($0)
    sw    $11, 0x42c($0)
    sw    $12, 0x430($0)
    sw    $13, 0x434($0)
    sw    $14, 0x438($0)
    sw    $15, 0x43c($0)
    sw    $16, 0x440($0)
    sw    $17, 0x444($0)
    sw    $18, 0x448($0)
    sw    $19, 0x44c($0)
    sw    $20, 0x450($0)
    sw    $21, 0x454($0)
    sw    $22, 0x458($0)
    sw    $23, 0x45c($0)
    sw    $24, 0x460($0)
    sw    $25, 0x464($0)
    sw    $0, 0x468($0)
    sw    $0, 0x46c($0)
    sw    $28, 0x470($0)
    sw    $29, 0x474($0)
    sw    $30, 0x478($0)
    sw    $31, 0x47c($0)

    mflo  $t0
    nop
    mfhi  $t1
    nop
    mfc0  $t2, $12
    nop
    mfc0  $t3, $13
    nop
    mfc0  $t4, $14
    nop

    sw    $t0, 0x480($0)
    sw    $t1, 0x484($0)
    sw    $t2, 0x488($0)
    sw    $t3, 0x48c($0)
    sw    $t4, 0x490($0)

    jalr  $k1
    li    $a0, 0x400

    move  $k1, $0

    lw    $t0, 0x480($0)
    lw    $t1, 0x484($0)
    lw    $t2, 0x488($0)
    lw    $t3, 0x48c($0)
    lw    $k0, 0x490($0)
    mtlo  $t0
    nop
    mthi  $t1
    nop
    mtc0  $t2, $12
    nop
    mtc0  $t3, $13
    nop
    .set push
    .set noat
    lw    $1, 0x404($0)
    .set pop
    lw    $2, 0x408($0)
    lw    $3, 0x40c($0)
    lw    $4, 0x410($0)
    lw    $5, 0x414($0)
    lw    $6, 0x418($0)
    lw    $7, 0x41c($0)
    lw    $8, 0x420($0)
    lw    $9, 0x424($0)
    lw    $10, 0x428($0)
    lw    $11, 0x42c($0)
    lw    $12, 0x430($0)
    lw    $13, 0x434($0)
    lw    $14, 0x438($0)
    lw    $15, 0x43c($0)
    lw    $16, 0x440($0)
    lw    $17, 0x444($0)
    lw    $18, 0x448($0)
    lw    $19, 0x44c($0)
    lw    $20, 0x450($0)
    lw    $21, 0x454($0)
    lw    $22, 0x458($0)
    lw    $23, 0x45c($0)
    lw    $24, 0x460($0)
    lw    $25, 0x464($0)
    lw    $28, 0x470($0)
    lw    $29, 0x474($0)
    lw    $30, 0x478($0)
    lw    $31, 0x47c($0)
    jr    $k0
    .word 0x42000010 /* rfe */

/* The exception handler seems to have some patching code
   here and there, using all these nops in the code, so it
   might be a good idea to keep it verbatim the same. 
   Maybe this can change later after understanding the
   patches a bit better. */

/* Why did they need to have this as a subfunction...? */
    .align 2
    .global getCop0CauseAndEPC
    .type getCop0CauseAndEPC, @function
getCop0CauseAndEPC:
    mfc0  $v0, $13
    mfc0  $v1, $14
    jr    $ra
    nop

    .align 2
    .global asmExceptionHandler
    .type asmExceptionHandler, @function
asmExceptionHandler:
    nop
    nop
    nop
    nop
    li    $k0, %lo(__globals)
    lw    $k0, 8($k0) /* ->TCBArrayPtr */
    nop
    lw    $k0, 0($k0) /* [0] */
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
    lw    $k0, 8($k0) /* ->TCBArrayPtr */
    lui   $a0, %hi(g_exceptionJmpBufPtr)
    lw    $k0, 0($k0) /* [0] */
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
    li    $k0, %lo(__globals)
    lw    $k0, 8($k0) /* ->TCBArrayPtr */
    nop
    lw    $k0, 0($k0) /* [0] */
    nop
    lw    $v0, 0x90($k0) /* lo */
    addiu $k0, 8
    mtlo  $v0
    lw    $v1, 0x84($k0) /* hi */
    lw    $k1, 0x80($k0) /* return PC */
    mthi  $v1
    lw    $a1, 0x8c($k0) /* Status */
    /* 00 is zero */
    lw    $at, 0x04($k0)
    mtc0  $a1, $12
    lw    $v0, 0x08($k0)
    lw    $v1, 0x0c($k0)
    lw    $a0, 0x10($k0)
    lw    $a1, 0x14($k0)
    lw    $a2, 0x18($k0)
    lw    $a3, 0x1c($k0)
    lw    $t0, 0x20($k0)
    lw    $t1, 0x24($k0)
    lw    $t2, 0x28($k0)
    lw    $t3, 0x2c($k0)
    lw    $t4, 0x30($k0)
    lw    $t5, 0x34($k0)
    lw    $t6, 0x38($k0)
    lw    $t7, 0x3c($k0)
    lw    $s0, 0x40($k0)
    lw    $s1, 0x44($k0)
    lw    $s2, 0x48($k0)
    lw    $s3, 0x4c($k0)
    lw    $s4, 0x50($k0)
    lw    $s5, 0x54($k0)
    lw    $s6, 0x58($k0)
    lw    $s7, 0x5c($k0)
    lw    $t8, 0x60($k0)
    lw    $t9, 0x64($k0)
    /* 68 and 6c are k0 and k1 */
    lw    $gp, 0x70($k0)
    lw    $sp, 0x74($k0)
    lw    $fp, 0x78($k0)
    lw    $ra, 0x7c($k0)
    jr    $k1
    .word 0x42000010 /* rfe */

    .align 2
    .section .text, "ax", @progbits
    .global breakVector
    .global breakHandler
    .type breakVector, @function

breakVector:
    ori   $k0, $0, %lo(generalHandler)
    lui   $k1, %hi(breakHandler)
    jr    $k0
    ori   $k1, %lo(breakHandler)

    .align 2
    .global exceptionVector
    .global exceptionHandler
    .type exceptionVector, @function

exceptionVector:
    ori   $k0, $0, %lo(generalHandler)
    lui   $k1, %hi(exceptionHandler)
    jr    $k0
    ori   $k1, %lo(exceptionHandler)

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
    .section .data, "ax", @progbits
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
    .global unimplemented
    .global unimplemented_end
    .type unimplemented, @function

unimplemented:
    break
    nop
    jr    $ra
    nop
unimplemented_end:

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
