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

    .set push
    .set noreorder
    .section .ramtext, "ax", @progbits
    .align 2
    .global branchbranch1
    .type branchbranch1, @function

branchbranch1:
    li    $v0, 1     /* yes */
    b     t1branch1
    b     t1branch2
    ori   $v0, 2     /* no */
    jr    $ra
    ori   $v0, 4     /* no */
t1branch1:
    ori   $v0, 8     /* yes */
    jr    $ra
    ori   $v0, 16    /* no */
t1branch2:
    ori   $v0, 32    /* no */
    jr    $ra
    ori   $v0, 64    /* no */
    ori   $v0, 128   /* yes */
    jr    $ra
    ori   $v0, 256   /* yes */

    .align 2
    .global branchbranch2
    .type branchbranch2, @function

branchbranch2:
    li    $v0, 1
    b     t2branch1
    b     t2branch2
    addiu $v0, 3
    jr    $ra
    move  $v0, $0
t2branch1:
    addiu $v0, 1
    jr    $ra
    move  $v0, $0
t2branch2:
    sll   $v0, 3
    jr    $ra
    addiu $v0, 5
    sll   $v0, 2
    jr    $ra
    addiu $v0, 1

    .align 2
    .global jumpjump1
    .type jumpjump1, @function

/* 1 8 32 64 */
jumpjump1:
    li    $v0, 1     /* yes */
    j     t1jump1
    j     t1jump2
    ori   $v0, 2     /* no */
    jr    $ra
    ori   $v0, 4     /* no */
t1jump1:
    ori   $v0, 8     /* yes */
    jr    $ra
    ori   $v0, 16    /* no */
t1jump2:
    ori   $v0, 32    /* yes */
    jr    $ra
    ori   $v0, 64    /* yes */
    ori   $v0, 128   /* no */
    jr    $ra
    ori   $v0, 256   /* no */

    .align 2
    .global jumpjump2
    .type jumpjump2, @function

jumpjump2:
    li    $v0, 1
    j     t2jump1
    j     t2jump2
    addiu $v0, 3
    jr    $ra
    move  $v0, $0
t2jump1:
    addiu $v0, 1
    jr    $ra
    move  $v0, $0
t2jump2:
    sll   $v0, 3
    jr    $ra
    addiu $v0, 5
    sll   $v0, 2
    jr    $ra
    addiu $v0, 1
