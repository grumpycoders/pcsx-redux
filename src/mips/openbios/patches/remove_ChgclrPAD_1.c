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

// clang-format off

/* Found in Suikoden 2 NTSC (SLUS-00958):

                    *************************************************************
                    *                           FUNCTION
                    *************************************************************
                             void  _remove_ChgclrPAD (void)
                               assume gp = 0x80109798
             void              <VOID>         <RETURN>
             dword * *         v0:4           B0table                                 XREF[1]:     800e3324 (W)
             undefined4        t2:4           count                                   XREF[1]:     800e332c (W)
             undefined4        v1:4           ptr                                     XREF[1]:     800e333c (W)
                             _remove_ChgclrPAD                               XREF[2]:     PAD_init:800e2e6c (c),
                                                                                          InitPAD:800e2f04 (c)
        800e330c 11 80 01 3c          lui             at,0x8011
             assume gp = <UNKNOWN>
        800e3310 a0 9b 3f ac          sw              ra,-0x6460 (at)=>DAT_80109ba0                    = ??
        800e3314 6f 52 03 0c          jal             EnterCriticalSection                             int EnterCriticalSection(void)
        800e3318 00 00 00 00          _nop
        800e331c 57 00 09 24          li              t1,0x57
        800e3320 b0 00 0a 24          li              t2,0xb0
        800e3324 09 f8 40 01          jalr            t2=>SUB_000000b0
        800e3328 00 00 00 00          _nop
        800e332c 09 00 0a 24          li              count ,0x9
        800e3330 6c 01 42 8c          lw              B0table ,0x16c (B0table )
        800e3334 00 00 00 00          nop
        800e3338 2c 06 43 20          addi            v1,B0table ,0x62c

                             LAB_800e333c                                    XREF[1]:     800e3348 (j)
        800e333c 00 00 60 ac          sw              zero,0x0(ptr)
        800e3340 04 00 63 24          addiu           ptr,ptr,0x4
        800e3344 ff ff 4a 25          addiu           count ,count ,-0x1
        800e3348 fc ff 40 15          bne             count ,zero,LAB_800e333c
        800e334c 00 00 00 00          _nop
        800e3350 53 7d 03 0c          jal             FlushCache                                       void FlushCache(void)
        800e3354 00 00 00 00          _nop
        800e3358 73 52 03 0c          jal             ExitCriticalSection                              void ExitCriticalSection(void)
        800e335c 00 00 00 00          _nop
        800e3360 11 80 1f 3c          lui             ra,0x8011
        800e3364 a0 9b ff 8f          lw              ra,-0x6460 (ra)=>DAT_80109ba0                    = ??
        800e3368 00 00 00 00          nop
        800e336c 08 00 e0 03          jr              ra
        800e3370 00 00 00 00          _nop

    This patch nops out the code that automatically ACK pad IRQ in the handler.
    We toggle a boolean for this instead if we detect this patch.

    See sio0/driver.c for more details.

 */

// clang-format on

#ifndef GENERATE_HASHES

int remove_ChgclrPAD_1_execute(uint32_t* ra) {
    patch_remove_ChgclrPAD();

    ra[2] = 7 | 0x10000000;
    ra[3] = 0;

    return 1;
}

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    0, 0, 0, 0,  // 00
    0, 0, 0, 0,  // 10
    0, 2, 0, 2,  // 20
    0, 1, 1, 0,  // 30
};

static const uint8_t bytes[] = {
    0x09, 0x00, 0x0a, 0x24, 0x6c, 0x01, 0x42, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x06, 0x43, 0x20,  // 00
    0x00, 0x00, 0x60, 0xac, 0x04, 0x00, 0x63, 0x24, 0xff, 0xff, 0x4a, 0x25, 0xfc, 0xff, 0x40, 0x15,  // 10
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c,  // 20
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x3c, 0x00, 0x00, 0xff, 0x8f, 0x00, 0x00, 0x00, 0x00,  // 30
};

uint32_t generate_hash_remove_ChgclrPAD_1(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t *)bytes, (uint8_t *)&mask, len);
}

uint32_t generate_mask_remove_ChgclrPAD_1() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
