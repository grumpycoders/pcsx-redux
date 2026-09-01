/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

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

/*
 * Trampolines that force the exact MIPS store instruction we want to test
 * against MMIO. Calling convention: $a0 = base address, $a1 = byte offset,
 * $a2 = source value. The compiler is not trusted to emit the right opcode
 * here - we want sb/sh/sw verbatim on a known-offset address.
 *
 * Using $v0 as the scratch effective-address register avoids touching $at
 * (the assembler reserves it).
 */

.set noreorder
.set noat

.global rw_sb
.type rw_sb, @function
rw_sb:
    addu  $v0, $a0, $a1
    sb    $a2, 0($v0)
    jr    $ra
    nop
.size rw_sb, . - rw_sb

.global rw_sh
.type rw_sh, @function
rw_sh:
    addu  $v0, $a0, $a1
    sh    $a2, 0($v0)
    jr    $ra
    nop
.size rw_sh, . - rw_sh

.global rw_sw
.type rw_sw, @function
rw_sw:
    addu  $v0, $a0, $a1
    sw    $a2, 0($v0)
    jr    $ra
    nop
.size rw_sw, . - rw_sw

.global rw_swl
.type rw_swl, @function
rw_swl:
    addu  $v0, $a0, $a1
    swl   $a2, 0($v0)
    jr    $ra
    nop
.size rw_swl, . - rw_swl

.global rw_swr
.type rw_swr, @function
rw_swr:
    addu  $v0, $a0, $a1
    swr   $a2, 0($v0)
    jr    $ra
    nop
.size rw_swr, . - rw_swr
