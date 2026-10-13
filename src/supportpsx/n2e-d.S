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

// Derived from n2e-d.S, originally written for ps2-packer by Nicolas Noble, who relicensed it here
// under the MIT license above.

// This is the source of the decompressor payload in the n2e-d.h file. It is only here for
// reference, as it is not part of the compilation process, to avoid requiring a mips compiler.

// n2e-d.h holds the .text of: mipsel-none-elf-gcc -march=r3000 -c n2e-d.S (without -DARGS_IN_S)

// NRV2E decompressor, same contract as the original n2e-d.S: valid streams only,
// decodes in place when the stream sits at the tail of the destination buffer.

.set noreorder
.global n2e_decompress
.ent n2e_decompress

#ifdef ARGS_IN_S
#define source     $s0
#define dest       $s1
#else
#define source     $a0
#define dest       $a1
#endif
#define bb         $t0
#define last_m_off $t2
#define acc        $t3                  // m_off while decoding the offset, then m_len
#define m_pos      $t5
#define bits_left  $t6
#define saved_ra   $t9

n2e_decompress:
    move    saved_ra, $ra
    move    bits_left, $0               // first getbit refills
    b       main_loop
    li      last_m_off, 1

m_off_loop:                             // acc == 1 on entry
    bal     getbit
    sll     acc, 1
    bal     getbit
    addu    acc, $v0                    // m_off = m_off * 2 + bit
    bnez    $v0, exit_m_off_loop
    addiu   acc, -1                     // m_off - 1, compensated below
    bal     getbit
    sll     acc, 1
    b       m_off_loop
    addu    acc, $v0                    // m_off = (m_off - 1) * 2 + bit

exit_m_off_loop:                        // acc holds the true m_off - 1
    addiu   $t1, acc, -1
    bnez    $t1, m_off_diff_2
    sll     acc, 8                      // (m_off - 1) * 256, unused on the repeat path
    bal     getbit                      // m_off == 2: repeat last_m_off, flag = getbit
    nop

len_decode:                             // bit 0 of $v0 = flag (m_len in the C code)
    bal     getbit                      // prefetch, used by both branches
    andi    $t1, $v0, 1
    bnez    $t1, exit_if
    addiu   acc, $v0, 3                 // m_len = 1 + bit  (+2 for the copy loop)
    bnez    $v0, len_3plus
    li      acc, 1
while_m_len:
    bal     getbit
    sll     acc, 1
    bal     getbit
    addu    acc, $v0                    // m_len = m_len * 2 + bit
    beqz    $v0, while_m_len
    nop
    b       exit_if
    addiu   acc, 5                      // m_len += 3  (+2)
len_3plus:
    bal     getbit
    nop
    addiu   acc, $v0, 5                 // m_len = 3 + bit  (+2)

exit_if:
    sltiu   $t1, last_m_off, 0x501      // m_len += (m_off > 0x500), as 2 - (m_off < 0x501)
    subu    acc, $t1
    subu    m_pos, dest, last_m_off

copy_loop:                              // seven instructions, so not an R5900 short loop
    lbu     $t1, 0(m_pos)
    addiu   m_pos, 1
    sb      $t1, 0(dest)
    nop
    addiu   acc, -1
    bnez    acc, copy_loop
    addiu   dest, 1

main_loop:
    bal     getbit
    li      acc, 1                      // m_off start, and the literal's copy count
    beqz    $v0, m_off_loop
    move    m_pos, source               // a literal is a one-byte copy from the stream
    b       copy_loop
    addiu   source, 1

end_of_stream:
    jr      saved_ra                    // delay slot: the pointer bump below, harmless here

m_off_diff_2:                           // acc = (true m_off - 1) * 256
    addiu   source, 1
    lbu     $t1, -1(source)
    addiu   acc, -511
    addu    $v0, acc, $t1               // C m_off + 1: zero at end of stream, bit 0 = flag
    beqz    $v0, end_of_stream
    addiu   $t1, $v0, 1                 // C m_off + 2
    b       len_decode
    srl     last_m_off, $t1, 1          // (C m_off >> 1) + 1

.end n2e_decompress

// $v0 = next bit. bb holds the pending bits MSB first, bits_left counts them; lwl drops the
// next stream byte straight into the top byte of bb.
.ent getbit
getbit:
    bnez    bits_left, 1f
    addiu   bits_left, -1
    lwl     bb, 0(source)               // also reads up to 3 bytes below source in the same aligned
                                        // word; they land in bb's low bits and are never consumed
    addiu   source, 1
    addiu   bits_left, 8                // -1 + 8: eight loaded, one consumed now
1:  srl     $v0, bb, 31
    jr      $ra
    sll     bb, 1
.end getbit
