/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

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

#include "common/compiler/stdint.h"
#include "openbios/sio0/pad.h"

/* Found in Suikoden 2:

TEXT:800E31C4                          # =============== S U B R O U T I N E =======================================
TEXT:800E31C4
TEXT:800E31C4                          # Attributes: library function
TEXT:800E31C4
TEXT:800E31C4                         _patch_pad:                              # CODE XREF: PAD_init+34↑p
TEXT:800E31C4                                                                  # TEXT:800E2F14↑p
TEXT:800E31C4 11 80 01 3C 80 9B 3F AC                 sw      $ra, dword_80109B80
TEXT:800E31CC 6F 52 03 0C                             jal     EnterCriticalSection
TEXT:800E31D0 00 00 00 00                             nop
TEXT:800E31D4 57 00 09 24                             li      $t1, 0x57
TEXT:800E31D8 B0 00 0A 24                             li      $t2, 0xB0
TEXT:800E31DC 09 F8 40 01                             jalr    $t2
TEXT:800E31E0 00 00 00 00                             nop
TEXT:800E31E4 6C 01 42 8C                             lw      $v0, 0x16C($v0)
TEXT:800E31E8 0B 00 09 24                             li      $t1, 0xB
TEXT:800E31EC 84 08 43 20                             addi    $v1, $v0, 0x884
TEXT:800E31F0 11 80 01 3C 88 9B 23 AC                 sw      $v1, dword_80109B88
TEXT:800E31F8 94 08 43 20                             addi    $v1, $v0, 0x894
TEXT:800E31FC 11 80 01 3C 8C 9B 23 AC                 sw      $v1, dword_80109B8C
TEXT:800E3204
TEXT:800E3204                         loc_800E3204:                            # CODE XREF: _patch_pad+4C↓j
TEXT:800E3204 94 05 40 AC                             sw      $zero, 0x594($v0)
TEXT:800E3208 04 00 42 24                             addiu   $v0, 4
TEXT:800E320C FF FF 29 25                             addiu   $t1, -1
TEXT:800E3210 FC FF 20 15                             bnez    $t1, loc_800E3204
TEXT:800E3214 00 00 00 00                             nop
TEXT:800E3218 53 7D 03 0C                             jal     FlushCache
TEXT:800E321C 00 00 00 00                             nop
TEXT:800E3220 11 80 1F 3C 80 9B FF 8F                 lw      $ra, dword_80109B80
TEXT:800E3228 00 00 00 00                             nop
TEXT:800E322C 08 00 E0 03                             jr      $ra
TEXT:800E3230 00 00 00 00                             nop
TEXT:800E3230                          # End of function _patch_pad

hash len = 16


 */

void patch_pad_execute(uint32_t* ra) { }
