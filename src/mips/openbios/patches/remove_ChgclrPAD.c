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

TEXT:800E330C                          # =============== S U B R O U T I N E =======================================
TEXT:800E330C
TEXT:800E330C                          # Attributes: library function
TEXT:800E330C
TEXT:800E330C                         _remove_ChgclrPAD:                       # CODE XREF: PAD_init+24↑p
TEXT:800E330C                                                                  # TEXT:800E2F04↑p
TEXT:800E330C 11 80 01 3C A0 9B 3F AC                 sw      $ra, dword_80109BA0
TEXT:800E3314 6F 52 03 0C                             jal     EnterCriticalSection
TEXT:800E3318 00 00 00 00                             nop
TEXT:800E331C 57 00 09 24                             li      $t1, 0x57
TEXT:800E3320 B0 00 0A 24                             li      $t2, 0xB0
TEXT:800E3324 09 F8 40 01                             jalr    $t2
TEXT:800E3328 00 00 00 00                             nop
TEXT:800E332C 09 00 0A 24                             li      $t2, 9
TEXT:800E3330 6C 01 42 8C                             lw      $v0, 0x16C($v0)
TEXT:800E3334 00 00 00 00                             nop
TEXT:800E3338 2C 06 43 20                             addi    $v1, $v0, 0x62C
TEXT:800E333C
TEXT:800E333C                         loc_800E333C:                            # CODE XREF: _remove_ChgclrPAD+3C↓j
TEXT:800E333C 00 00 60 AC                             sw      $zero, 0($v1)
TEXT:800E3340 04 00 63 24                             addiu   $v1, 4
TEXT:800E3344 FF FF 4A 25                             addiu   $t2, -1
TEXT:800E3348 FC FF 40 15                             bnez    $t2, loc_800E333C
TEXT:800E334C 00 00 00 00                             nop
TEXT:800E3350 53 7D 03 0C                             jal     FlushCache
TEXT:800E3354 00 00 00 00                             nop
TEXT:800E3358 73 52 03 0C                             jal     ExitCriticalSection
TEXT:800E335C 00 00 00 00                             nop
TEXT:800E3360 11 80 1F 3C A0 9B FF 8F                 lw      $ra, dword_80109BA0
TEXT:800E3368 00 00 00 00                             nop
TEXT:800E336C 08 00 E0 03                             jr      $ra
TEXT:800E3370 00 00 00 00                             nop
TEXT:800E3370                          # End of function _remove_ChgclrPAD

hash len = 16
hash mask = 00010100100010000000000000000000

  This patch nops out the code that changes pad on abort. We toggle a boolean
  for this instead if we detect this patch. See sio0/driver.c for more details.

 */

void remove_ChgclrPAD_execute(uint32_t* ra) { patch_remove_ChgclrPAD(); }
