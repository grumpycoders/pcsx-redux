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
    .global cpu_LWR_LWL_half
    .type cpu_LWR_LWL_half, @function

cpu_LWR_LWL_half:
    lwl   $a1, 4($a0)
    jr    $ra
    move  $v0, $a1

    .align 2
    .global cpu_LWR_LWL_nodelay
    .type cpu_LWR_LWL_nodelay, @function

cpu_LWR_LWL_nodelay:
    lwl   $a1, 4($a0)
    lwr   $a1, 1($a0)
    move  $v0, $a1
    jr    $ra
    nop

    .align 2
    .global cpu_LWR_LWL_delayed
    .type cpu_LWR_LWL_delayed, @function

cpu_LWR_LWL_delayed:
    lwl   $a1, 4($a0)
    lwr   $a1, 1($a0)
    j     $ra
    move  $v0, $a1
