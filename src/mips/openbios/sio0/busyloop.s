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

    .set noreorder
    .section .ramtext, "ax", @progbits
    .align 2
    .global busyloop
    .type busyloop, @function

/* The timing of this might be so sensitive, it could be
   requiring to be an exact replica of the existing code.
   
   The C version of this would be the following:
   
   void busyLoop(int count) {
       volatile int cycles = count;
       while (cycles--);
   }

   */
busyloop:
    sw    $a0, 0($sp)
    lw    $v0, 0($sp)
    lw    $v1, 0($sp)
    nop
    addiu $v1, -1
    beqz  $v0, earlyExit
    sw    $v1, 0($sp)

busyloopLoop:
    lw    $v0, 0($sp)
    lw    $v1, 0($sp)
    nop
    addiu $v1, -1
    bnez  $v0, busyloopLoop
    sw    $v1, 0($sp)

earlyExit:
    jr    $ra
    nop
