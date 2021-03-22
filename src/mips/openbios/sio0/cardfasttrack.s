/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

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

    .set noreorder
    .set noat

    .align 2
    .section .ramtext, "ax", @progbits
    .global g_mcFastTrackActive
    .global g_mcFastTrackOperationPtr
    .global g_mcFastTrackBuffer
    .global g_mcFastTrackChecksumPtr
    .global g_mcFastTrackCounter
    .global exceptionHandlerCardFastTrack
    .type exceptionHandlerCardFastTrack, @function

/* This code is called from the exception handler, after only at, v0, v1, and ra
   are saved, so it has to be written in assembly. k0 can also be used at this point,
   The equivalent C code roughly says the following:

    uint8_t b;
    if (g_mcFastTrackActive && (IREG & IRQ_CONTROLLER) && (IMASK & IRQ_CONTROLLER)) {
        switch(g_mcFastTrackOperationPtr) {
            case MC_FASTTRACK_WRITE: // 4
                SIOS[0].fifo;
                SIOS[0].fifo = b = *g_mcFastTrackBuffer++;
                SIOS[0].ctrl |= 0x0010;
                IREG = ~IRQ_CONTROLLER;
                *g_mcFastTrackChecksum ^= b;
                if (++g_mcFastTrackCount > 0x7f) g_mcFastTrackActive = 0;
                break;
            case MC_FASTTRACK_READ: // 2
                *g_mcFastTrackBuffer++ = b = SIOS[0].fifo;
                SIOS[0].fifo = 0;
                SIOS[0].ctrl |= 0x0010;
                IREG = ~IRQ_CONTROLLER;
                *g_mcFastTrackChecksum ^= b;
                if (++g_mcFastTrackCount > 0x7e) g_mcFastTrackActive = 0;
                break;
        }
    }
*/

exceptionHandlerCardFastTrack:
/* can only use $v0, $v1, and $at for this section */
    lw    $v0, g_mcFastTrackActive
    lui   $v1, 0x1f80
    beqz  $v0, mcFastTrackExit
    lw    $v0, 0x1070($v1)
    nop
    andi  $v0, 0x80
    beqz  $v0, mcFastTrackExit
    lw    $v0, 0x1074($v1)
    nop
    andi  $v0, 0x80
    beqz  $v0, mcFastTrackExit
/* from here, we can also use $k0 */
    lui   $v0, %hi(g_mcFastTrackOperationPtr)
    lw    $v0, %lo(g_mcFastTrackOperationPtr)($v0)
    li    $at, 2
    lbu   $v0, 0($v0)
    lui   $k0, %hi(g_mcFastTrackBuffer)
    beq   $v0, $at, mcFastTrackRead
    li    $at, 4
    bne   $v0, $at, mcFastTrackRFE
    nop

mcFastTrackWrite:
    lw    $k0, %lo(g_mcFastTrackBuffer)($k0)
    move  $at, $k0 /* trolololo */
    lbu   $v0, 0($k0)
    addiu $k0, 1
    sw    $k0, %lo(g_mcFastTrackBuffer)($at)
    lbu   $0, 0x1040($v1)
    sb    $v0, 0x1040($v1)
    lhu   $k0, 0x104a($v1)
    lui   $at, %hi(g_mcFastTrackChecksumPtr)
    ori   $k0, 0x0010
    sh    $k0, 0x104a($v1)
    lw    $k0, %lo(g_mcFastTrackChecksumPtr)($at)
    nop
    lw    $at, 0($k0)
    nop
    xor   $at, $v0
    sw    $at, 0($k0)
    li    $at, 0xffffff7f
    sw    $at, 0x1070($v1)
    lui   $at, %hi(g_mcFastTrackCounter)
    lw    $v0, %lo(g_mcFastTrackCounter)($at)
    nop
    addiu $v0, 1
    sw    $v0, %lo(g_mcFastTrackCounter)($at)
    sltiu $v0, 0x80
    bnez  $v0, mcFastTrackRFE
    lui   $v0, %hi(g_mcFastTrackActive)
    b     mcFastTrackRFE
    sw    $0, %lo(g_mcFastTrackActive)($v0)

mcFastTrackRead:
    lbu   $v0, 0x1040($v1)
    lw    $k0, %lo(g_mcFastTrackBuffer)($k0)
    move  $at, $k0 /* gotta break those bad emulators */
    sb    $v0, 0($k0)
    addiu $k0, 1
    sw    $k0, %lo(g_mcFastTrackBuffer)($at)
    sb    $0, 0x1040($v1)
    lhu   $k0, 0x104a($v1)
    lui   $at, %hi(g_mcFastTrackChecksumPtr)
    ori   $k0, 0x0010
    sh    $k0, 0x104a($v1)
    lw    $k0, %lo(g_mcFastTrackChecksumPtr)($at)
    nop
    lw    $at, 0($k0)
    nop
    xor   $at, $v0
    sw    $at, 0($k0)
    li    $at, 0xffffff7f
    sw    $at, 0x1070($v1)
    lui   $at, %hi(g_mcFastTrackCounter)
    lw    $v0, %lo(g_mcFastTrackCounter)($at)
    nop
    addiu $v0, 1
    sw    $v0, %lo(g_mcFastTrackCounter)($at)
    sltiu $v0, 0x7f
    bnez  $v0, mcFastTrackRFE
    lui   $v0, %hi(g_mcFastTrackActive)
    b     mcFastTrackRFE
    sw    $0, %lo(g_mcFastTrackActive)($v0)

mcFastTrackExit:
    jr    $ra
    nop

mcFastTrackRFE:
    li    $k0, %lo(__globals)
    lw    $k0, 8($k0)
    nop
    lw    $k0, 0($k0)
    nop
    lw    $at, 0x0c($k0)
    lw    $v0, 0x10($k0)
    lw    $v1, 0x14($k0)
    lw    $ra, 0x84($k0)
    lw    $k0, 0x88($k0)
    nop
    jr    $k0
    rfe

    .section .text, "ax", @progbits
    .align 2
    .global exceptionHandlerCardFastTrackPatch
exceptionHandlerCardFastTrackPatch:
    la    $v0, exceptionHandlerCardFastTrack
    jalr  $v0
    nop
