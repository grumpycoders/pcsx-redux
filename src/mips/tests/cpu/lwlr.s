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

/* While this usage is rare, it is technically valid and allowed. */
/* uint32_t cpu_LWR_LWL_half(uint32_t buff[], uint32_t initial); */
cpu_LWR_LWL_half:
    lwl   $a1, 4($a0)
    jr    $ra
    move  $v0, $a1

    .align 2
    .global cpu_LWR_LWL_nodelay
    .type cpu_LWR_LWL_nodelay, @function

/* This is technically invalid, and undefined behaviour. The result will be
   deterministic however on the r3000a PSX CPU. */
/* uint32_t cpu_LWR_LWL_delayed(uint32_t buff[], uint32_t initial); */
cpu_LWR_LWL_nodelay:
    lwl   $a1, 4($a0)
    lwr   $a1, 1($a0)
    move  $v0, $a1 /* This is run without waiting the proper delay. */
    jr    $ra
    nop

    .align 2
    .global cpu_LWR_LWL_delayed
    .type cpu_LWR_LWL_delayed, @function

/* This is the proper usage of lwl / lwr. */
/* uint32_t cpu_LWR_LWL_delayed(uint32_t buff[], uint32_t initial); */
cpu_LWR_LWL_delayed:
    lwl   $a1, 4($a0)
    lwr   $a1, 1($a0)
    j     $ra
    move  $v0, $a1

    .align 2
    .global cpu_LWR_LWL_load_different
    .type cpu_LWR_LWL_load_different, @function

/* uint32_t cpu_LWR_LWL_load_different(uint32_t buff[], uint32_t initial); */
cpu_LWR_LWL_load_different:
    lwl   $a1, 4($a0)
    lwr   $a1, 5($a0)
    j     $ra
    move  $v0, $a1

    .align 2
    .global cpu_LW_LWR
    .type cpu_LW_LWL, @function
/* uint32_t cpu_LW_LWR(uint32_t buff[], uint32_t initial); */
cpu_LW_LWR:
    lw    $a1, 8($a0)
    lwr   $a1, 1($a0)
    j     $ra
    move  $v0, $a1
