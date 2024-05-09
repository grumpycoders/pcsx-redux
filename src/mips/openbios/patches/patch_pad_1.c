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

#include <stdint.h>

#include "openbios/patches/patches.h"
#include "openbios/sio0/pad.h"

// clang-format off

/* Found in Suikoden 2 NTSC (SLUS-00958):

                    *************************************************************
                    *                           FUNCTION
                    *************************************************************
                             undefined  _patch_pad ()
                               assume gp = 0x80109798
             undefined         v0:1           <RETURN>                                XREF[2]:     800e31dc (W),
                                                                                                   800e31e4 (W)
             dword * *         v0:4           B0table                                 XREF[1]:     800e31dc (W)
             undefined4        v0:4           ptr                                     XREF[1]:     800e31e4 (W)
             undefined4        t1:4           count                                   XREF[1]:     800e31e8 (W)
                             _patch_pad                                      XREF[2]:     PAD_init:800e2e7c (c),
                                                                                          InitPAD:800e2f14 (c)
        800e31c4 11 80 01 3c          lui             at,0x8011
             assume gp = <UNKNOWN>
        800e31c8 80 9b 3f ac          sw              ra,-0x6480 (at)=>DAT_80109b80                    = ??
        800e31cc 6f 52 03 0c          jal             EnterCriticalSection                             int EnterCriticalSection(void)
        800e31d0 00 00 00 00          _nop
        800e31d4 57 00 09 24          li              t1,0x57
        800e31d8 b0 00 0a 24          li              t2,0xb0
        800e31dc 09 f8 40 01          jalr            t2=>SUB_000000b0
        800e31e0 00 00 00 00          _nop
        800e31e4 6c 01 42 8c          lw              ptr,0x16c (ptr)
        800e31e8 0b 00 09 24          li              count ,0xb
        800e31ec 84 08 43 20          addi            v1,ptr,0x884
        800e31f0 11 80 01 3c          lui             at,0x8011
        800e31f4 88 9b 23 ac          sw              v1,-0x6478 (at)=>captured_startPad               = ??
        800e31f8 94 08 43 20          addi            v1,ptr,0x894
        800e31fc 11 80 01 3c          lui             at,0x8011
        800e3200 8c 9b 23 ac          sw              v1,-0x6474 (at)=>captured_stopPad                = ??

                             LAB_800e3204                                    XREF[1]:     800e3210 (j)
        800e3204 94 05 40 ac          sw              zero,0x594 (ptr)
        800e3208 04 00 42 24          addiu           ptr,ptr,0x4
        800e320c ff ff 29 25          addiu           count ,count ,-0x1
        800e3210 fc ff 20 15          bne             count ,zero,LAB_800e3204
        800e3214 00 00 00 00          _nop
        800e3218 53 7d 03 0c          jal             FlushCache                                       void FlushCache(void)
        800e321c 00 00 00 00          _nop
        800e3220 11 80 1f 3c          lui             ra,0x8011
        800e3224 80 9b ff 8f          lw              ra,-0x6480 (ra)=>DAT_80109b80                    = ??
        800e3228 00 00 00 00          nop
        800e322c 08 00 e0 03          jr              ra
        800e3230 00 00 00 00          _nop

    This patch nops out the code that automatically changes slot on pad abort,
    and grabs the pointer to the functions that enables and disables the handler.
    We toggle a boolean for this instead if we detect this patch, and we
    inject some functions for it in the pointers.

    See sio0/driver.c for more details.

 */

// clang-format on

#ifndef GENERATE_HASHES

enum patch_behavior patch_pad_1_execute(uint32_t *ra) {
    patch_disable_slotChangeOnAbort();
    uint32_t ptr;
    int16_t addend;

    ptr = ra[3] & 0xffff;
    ptr <<= 16;
    addend = ra[4] & 0xffff;
    ptr += addend;
    *((uint32_t *)ptr) = (uint32_t)patch_startPad;

    ptr = ra[6] & 0xffff;
    ptr <<= 16;
    addend = ra[7] & 0xffff;
    ptr += addend;
    *((uint32_t *)ptr) = (uint32_t)patch_stopPad;

    ra[2] = 11 | 0x10000000;
    ra[3] = 0;

    return PATCH_COUNTERPATCH;
}

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    0, 0, 0, 1,  // 00
    1, 0, 1, 1,  // 10
    0, 0, 0, 0,  // 20
    0, 2, 0, 1,  // 30
};

static const uint8_t bytes[] = {
    0x6c, 0x01, 0x42, 0x8c, 0x0b, 0x00, 0x09, 0x24, 0x84, 0x08, 0x43, 0x20, 0x00, 0x00, 0x01, 0x3c,  // 00
    0x00, 0x00, 0x23, 0xac, 0x94, 0x08, 0x43, 0x20, 0x00, 0x00, 0x01, 0x3c, 0x00, 0x00, 0x23, 0xac,  // 10
    0x94, 0x05, 0x40, 0xac, 0x04, 0x00, 0x42, 0x24, 0xff, 0xff, 0x29, 0x25, 0xfc, 0xff, 0x20, 0x15,  // 20
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x3c,  // 30
};

uint32_t generate_hash_patch_pad_1(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t *)bytes, (uint8_t *)&mask, len);
}

uint32_t generate_mask_patch_pad_1() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
