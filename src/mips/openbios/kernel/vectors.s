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
    .global exceptionHandlerPatchSlot1
    .global exceptionHandlerPatchSlot2
    .global exceptionHandlerPatchSlot3
    .global exceptionHandlerPatchSlot4
    .type exceptionHandler, @function
exceptionHandler:
/* These 4 nops here are most likely for an injected very early handler */
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

/* These 4 blocs of 4 nops are each for an early exception handler slot.
   Only registers at, v0, v1, and ra are saved at this point. The first
   slot is used by the memory card driver. The second is used by the
   lightgun driver, and a custom handler from the game Point Blank.
   These are sometimes cleared out by patches. */

exceptionHandlerPatchSlot1:
    nop
    nop
    nop
    nop
exceptionHandlerPatchSlot2:
    nop
    nop
    nop
    nop
exceptionHandlerPatchSlot3:
    nop
    nop
    nop
    nop
exceptionHandlerPatchSlot4:
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
    /* At least one game (Armored Core: Master of Arena) is very wrongly
       using 0x80 as a parameter to CdControlF instead of a pointer to
       a structure that *contains* the 0x80 value:

      ::8001616c 0e  00  04  24    li         a0, 0xe
      ::80016170 cf  5f  00  0c    jal        CdControlF
      ::80016174 80  00  05  24    _li        a1, 0x80

      This results in the address 0x80 being wrongly dereferenced by
      CdControlF to read its parameters, and the retail bios will have
      enough zeroes here to make it work properly, tho it will be at
      1x speed instead of the intended 2x.

      Now, we cannot just use a nop here, even though it would be the
      simplest way to ensure a valid CdControlF call, because then,
      Batman - Gotham City Racer NTSC (SLUS-01141) replaces this
      code by reading the exception handler until a nop is found:

                             copyHandler                                     XREF[1]:     FUN_80016a34:80016a68 (c)   
        8002668c 80  00  04  24    li         src ,0x80
        80026690 02  80  02  3c    lui        v0,0x8002
        80026694 a8  67  42  24    addiu      dst ,dst ,0x67a8
                             LAB_80026698                                    XREF[1]:     800266a4 (j)   
        80026698 00  00  88  8c    lw         opcode ,0x0 (src )=>DAT_00000080
        8002669c 04  00  84  20    addi       src ,src ,0x4
        800266a0 00  00  48  ac    sw         opcode ,0x0 (dst )=>DAT_800267a8
        800266a4 fc  ff  00  15    bne        opcode ,zero ,LAB_80026698
        800266a8 04  00  42  20    _addi      dst ,dst ,0x4

      So if we want to keep the game working, we need to have a valid
      no-op instruction that is not a nop.

      Using lui $0, 0x80 will not only accomplish these goals, but also
      ensure that a CdControlF(0x80) actually sets the drive at 2x speed.

      However, Need for Speed - High Stakes will run this code to detect
      the presence of a debugger:

                             detectDevBIOS                                   XREF[1]:     FUN_800f4390:800f43bc (c)   
        8010769c 86  00  04  94    lhu        a0,0x86 (zero )
        801076a0 5a  37  02  24    li         v0,0x375a
        801076a4 05  00  82  10    beq        a0,v0,LAB_801076bc
        801076a8 5a  27  03  24    _li        v1,0x275a
        801076ac 04  00  83  10    beq        a0,v1,LAB_801076c0
        801076b0 21  10  00  00    _clear     ret
        801076b4 08  00  e0  03    jr         ra
        801076b8 ff  ff  02  24    _li        ret ,-0x1
                             LAB_801076bc                                    XREF[1]:     801076a4 (j)   
        801076bc 01  00  02  24    li         ret ,0x1
                             LAB_801076c0                                    XREF[1]:     801076ac (j)   
        801076c0 08  00  e0  03    jr         ra
        801076c4 00  00  00  00    _nop

      In other words, it will check if the 16-bits value at 0x86 is 0x275a
      for a retail bios, or 0x375a for a debugger. If it is neither, it
      will return the code -1, for an error. 0x375a corresponds to
      `ori $k0, $k0, xxx`, and 0x275a corresponds to `addiu $k0, $k0, xxx`.

      At this point, our only safe option is to use a `la`, which will
      expand into lui / addiu, with the low portion of the lui being
      0x0000, to satisfy all of our constraints.
      */

    la    $k0, exceptionHandler
    jr    $k0
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
    la    $t0, __ramA0table
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
    la    $t0, B0table
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
    la    $t0, C0table
    sll   $t2, $t1, 2
    add   $t2, $t0
    lw    $t2, 0($t2)
    li    $t0, 0xc0
    jr    $t2
    nop

    .align 2
    .global OBtable
    .global OBHandler
    .type OBHandler, @function

OBHandler:
    li    $t0, %lo(OBtable)
    sll   $t2, $t1, 2
    add   $t2, $t0
    lw    $t2, 0($t2)
    nop
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
