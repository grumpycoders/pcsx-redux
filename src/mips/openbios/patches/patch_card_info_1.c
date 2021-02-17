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

// clang-format off

/* Found in Tales of Destiny Disc 2 (SLUS-01367):

                    *************************************************************
                    *                           FUNCTION
                    *************************************************************
                             undefined  _patch_card_info ()
                               assume gp = 0x800c5454
             undefined         v0:1           <RETURN>                                XREF[1]:     80078448 (W)
             dword * *         v0:4           B0table                                 XREF[1]:     80078448 (W)
                             _patch_card_info                                XREF[1]:     InitCARD:80077f38 (c)
        80078438 10 80 01 3c          lui             at,0x8010
             assume gp = <UNKNOWN>
        8007843c 90 37 3f ac          sw              ra,offset  DAT_80103790 (at)                      = ??
        80078440 57 00 09 24          li              t1,0x57
        80078444 b0 00 0a 24          li              t2,0xb0
        80078448 09 f8 40 01          jalr            t2=>SUB_000000b0
        8007844c 00 00 00 00          _nop
        80078450 09 00 0a 24          li              t2,0x9
        80078454 6c 01 42 8c          lw              B0table ,0x16c (B0table )
        80078458 00 00 00 00          nop
        8007845c 88 19 43 20          addi            v1,B0table ,0x1988
        80078460 e2 e0 01 0c          jal             FlushCache                                       void FlushCache(void)
        80078464 00 00 60 ac          _sw             zero,0x0(v1)
        80078468 10 80 1f 3c          lui             ra,0x8010
        8007846c 90 37 ff 8f          lw              ra,offset  DAT_80103790 (ra)                      = ??
        80078470 00 00 00 00          nop
        80078474 08 00 e0 03          jr              ra
        80078478 00 00 00 00          _nop

 */

// clang-format on

#ifndef GENERATE_HASHES

// not doing anything about it for now
int patch_card_info_1_execute(uint32_t* ra) {
    ra[2] = 0 | 0x10000000;
    ra[3] = 0;
    ra[5] = 0;
    return 1;
}

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    0, 0, 0, 0,  // 00
    2, 0, 1, 1,  // 10
    0, 0, 0, 3,  // 20
    3, 3, 3, 3,  // 30
};

static const uint8_t bytes[] = {
    0x09, 0x00, 0x0a, 0x24, 0x6c, 0x01, 0x42, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x88, 0x19, 0x43, 0x20,  // 00
    0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x60, 0xac, 0x00, 0x00, 0x1f, 0x3c, 0x00, 0x00, 0xff, 0x8f,  // 10
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0xe0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 20
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 30
};

uint32_t generate_hash_patch_card_info_1(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t *)bytes, (uint8_t *)&mask, len);
}

uint32_t generate_mask_patch_card_info_1() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
