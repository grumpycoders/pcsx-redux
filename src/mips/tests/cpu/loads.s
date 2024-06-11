/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

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
    .global cpu_delayed_load
    .type cpu_delayed_load, @function

/* This can happen. */
/* uint32_t cpu_delayed_load(uint32_t buff[], uint32_t override); */
cpu_delayed_load:
    lw    $a1, 0($a0)
    move  $v0, $a1
    jr    $ra
    nop

    .align 2
    .global cpu_delayed_load_cancelled
    .type cpu_delayed_load_cancelled, @function

/* This happens even more frequently. */
/* uint32_t cpu_delayed_load_cancelled(uint32_t buff[], uint32_t override); */
cpu_delayed_load_cancelled:
    lw    $v0, 0($a0)
    move  $v0, $a1
    jr    $ra
    nop

    .align 2
    .global cpu_delayed_load_load
    .type cpu_delayed_load_load, @function

/* This is extremely infrequent */
/* uint64_t cpu_delayed_load_load(uint32_t buff[], uint32_t override); */
cpu_delayed_load_load:
    lw    $a1, 0($a0)
    lw    $a1, 4($a0)
    move  $v0, $a1
    move  $v1, $a1
    jr    $ra
    nop
