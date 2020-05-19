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
    .set noreorder
    .align 2
    .global exec
    .type exec, @function

    /* is there a way to access a C-struct in assembly? */
exec:
    sw    $s0, 0x38($a0) /* header->savedS0 */
    sw    $ra, 0x34($a0) /* header->savedRA */
    sw    $sp, 0x28($a0) /* header->savedSP */
    sw    $s8, 0x2c($a0) /* header->savedS8 */
    sw    $gp, 0x30($a0) /* header->savedGP */

    lw    $t0, 0x1c($a0) /* t0 = header->bss_size */
    lw    $t3, 0x20($a0) /* t3 = stack_start */

    beqz  $t0, skipBSS   /* t0 = bss_size */
    move  $s0, $a0       /* s0 = header */

    lw    $t1, 0x18($a0) /* t1 = bss_start */

clearBSS:
    addi  $t0, -4
    sw    $0, 0($t1)
    bgtz  $t0, clearBSS
    addi  $t1, 4

skipBSS:
    beqz  $t3, noStack
    lw    $t2, 0x00($a0) /* t2 = pc */

    lw    $t1, 0x24($a0) /* t1 = stack_size */
    nop
    add   $sp, $t3, $t1
    move  $s8, $sp

noStack:
    lw    $gp, 0x04($a0)
    move  $a0, $a1       /* shifting argc */
    jalr  $t2
    move  $a1, $a2       /* shifting argv */

    lw    $ra, 0x34($s0) /* header->savedRA */
    lw    $sp, 0x28($s0) /* header->savedSP */
    lw    $s8, 0x2c($s0) /* header->savedS8 */
    lw    $gp, 0x30($s0) /* header->savedGP */
    lw    $s0, 0x38($s0) /* header->savedS0 */
    jr    $ra
    li    $v0, 1
