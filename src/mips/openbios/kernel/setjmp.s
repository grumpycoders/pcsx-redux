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

    .section .text, "ax", @progbits
    .align 2
    .global psxsetjmp
    .type psxsetjmp, @function

psxsetjmp:
    sw    $ra, 0($a0)
    sw    $sp, 4($a0)
    sw    $s8, 8($a0)
    sw    $s0, 12($a0)
    sw    $s1, 16($a0)
    sw    $s2, 20($a0)
    sw    $s3, 24($a0)
    sw    $s4, 28($a0)
    sw    $s5, 32($a0)
    sw    $s6, 36($a0)
    sw    $s7, 40($a0)
    sw    $gp, 44($a0)
    move  $v0, $0
    jr    $ra

    .section .text, "ax", @progbits
    .align 2
    .global psxlongjmp
    .type psxlongjmp, @function

psxlongjmp:
    lw    $ra, 0($a0)
    lw    $sp, 4($a0)
    lw    $s8, 8($a0)
    lw    $s0, 12($a0)
    lw    $s1, 16($a0)
    lw    $s2, 20($a0)
    lw    $s3, 24($a0)
    lw    $s4, 28($a0)
    lw    $s5, 32($a0)
    lw    $s6, 36($a0)
    lw    $s7, 40($a0)
    lw    $gp, 44($a0)
    move  $v0, $a1
    jr    $ra
