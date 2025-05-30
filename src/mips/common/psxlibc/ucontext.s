/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

.set RAPTR, 0
.set SPPTR, 4
.set S8PTR, 8
.set S0PTR, 12
.set S1PTR, 16
.set S2PTR, 20
.set S3PTR, 24
.set S4PTR, 28
.set S5PTR, 32
.set S6PTR, 36
.set S7PTR, 40
.set GPPTR, 44
.set FUNCPTR, 48
.set ARGPTR, 52
.set UNUSED1, 56
.set UNUSED2, 60
.set LINKPTR, 64
.set STACKPTR, 68
.set STACKSIZE, 72

    .section .text.getcontext, "ax", @progbits
    .align 2
    .global getcontext
    .type getcontext, @function

getcontext:
    sw    $ra, RAPTR($a0)
    sw    $sp, SPPTR($a0)
    sw    $s8, S8PTR($a0)
    sw    $s0, S0PTR($a0)
    sw    $s1, S1PTR($a0)
    sw    $s2, S2PTR($a0)
    sw    $s3, S3PTR($a0)
    sw    $s4, S4PTR($a0)
    sw    $s5, S5PTR($a0)
    sw    $s6, S6PTR($a0)
    sw    $s7, S7PTR($a0)
    sw    $gp, GPPTR($a0)
    move  $v0, $0
    jr    $ra

    .section .text.setcontext, "ax", @progbits
    .align 2
    .global setcontext
    .type setcontext, @function

setcontext:
    lw    $ra, RAPTR($a0)
    lw    $sp, SPPTR($a0)
    lw    $s8, S8PTR($a0)
    lw    $s0, S0PTR($a0)
    lw    $s1, S1PTR($a0)
    lw    $s2, S2PTR($a0)
    lw    $s3, S3PTR($a0)
    lw    $s4, S4PTR($a0)
    lw    $s5, S5PTR($a0)
    lw    $s6, S6PTR($a0)
    lw    $s7, S7PTR($a0)
    lw    $gp, GPPTR($a0)
    move  $v0, $0
    jr    $ra

    .section .text.makecontext, "ax", @progbits
    .align 2
    .global makecontext
    .type makecontext, @function
    .type contexttrampoline, @function

contexttrampoline:
    lw    $a0, ARGPTR($s0)
    lw    $a1, FUNCPTR($s0)
    lw    $sp, SPPTR($s0)
    lw    $s8, S8PTR($s0)
    lw    $gp, GPPTR($s0)
    jalr  $a1
    lw    $a0, LINKPTR($s0)
    j     setcontext

makecontext:
    lw    $v1, STACKPTR($a0)
    lw    $t0, STACKSIZE($a0)
    la    $v0, contexttrampoline
    sw    $v0, RAPTR($a0)
    sw    $a1, FUNCPTR($a0)
    sw    $a2, ARGPTR($a0)
    sw    $a0, S0PTR($a0)
    addiu $t0, -16
    addu  $v1, $t0
    sw    $v1, SPPTR($a0)
    jr    $ra

    .section .text.swapcontext, "ax", @progbits
    .align 2
    .global swapcontext
    .type swapcontext, @function

swapcontext:
    sw    $ra, RAPTR($a0)
    sw    $sp, SPPTR($a0)
    sw    $s8, S8PTR($a0)
    sw    $s0, S0PTR($a0)
    sw    $s1, S1PTR($a0)
    sw    $s2, S2PTR($a0)
    sw    $s3, S3PTR($a0)
    sw    $s4, S4PTR($a0)
    sw    $s5, S5PTR($a0)
    sw    $s6, S6PTR($a0)
    sw    $s7, S7PTR($a0)
    sw    $gp, GPPTR($a0)
    lw    $ra, RAPTR($a1)
    lw    $sp, SPPTR($a1)
    lw    $s8, S8PTR($a1)
    lw    $s0, S0PTR($a1)
    lw    $s1, S1PTR($a1)
    lw    $s2, S2PTR($a1)
    lw    $s3, S3PTR($a1)
    lw    $s4, S4PTR($a1)
    lw    $s5, S5PTR($a1)
    lw    $s6, S6PTR($a1)
    lw    $s7, S7PTR($a1)
    lw    $gp, GPPTR($a1)
    move  $v0, $0
    jr    $ra
