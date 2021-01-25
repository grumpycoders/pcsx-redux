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
                             undefined  _patch_card2 ()
                               assume gp = 0x800c5454
             undefined         v0:1           <RETURN>                                XREF[2]:     800785c0 (W),
                                                                                                   800785c8 (W)
             dword * *         v0:4           B0table                                 XREF[1]:     800785c0 (W)
             undefined4        v0:4           dst                                     XREF[1]:     800785c8 (W)
             undefined4        t2:4           src                                     XREF[1]:     800785d8 (W)
                             _patch_card2                                    XREF[1]:     InitCARD:80077f30 (c)
        800785a8 10 80 01 3c          lui             at,0x8010
             assume gp = <UNKNOWN>
        800785ac 90 37 3f ac          sw              ra,offset  DAT_80103790 (at)                      = ??
        800785b0 f6 df 01 0c          jal             EnterCriticalSection                             undefined EnterCriticalSection()
        800785b4 00 00 00 00          _nop
        800785b8 57 00 09 24          li              t1,0x57
        800785bc b0 00 0a 24          li              t2,0xb0
        800785c0 09 f8 40 01          jalr            t2=>SUB_000000b0
        800785c4 00 00 00 00          _nop
        800785c8 6c 01 42 8c          lw              dst,0x16c (dst)
        800785cc 00 00 00 00          nop
        800785d0 c8 09 43 8c          lw              v1,0x9c8 (dst)
        800785d4 08 80 0a 3c          lui             t2,0x8008
        800785d8 00 85 4a 25          addiu           src,src,-0x7b00
        800785dc 08 80 09 3c          lui             t1,0x8008
        800785e0 14 85 29 25          addiu           t1,t1,-0x7aec
                             PATCH_OBJ_1AC                                   XREF[1]:     800785f4 (j)
        800785e4 00 00 48 8d          lw              t0,0x0(src)=>PATCH_OBJ_C8                        = 2508DF80h
                                                                                                       = 3C08A001h
        800785e8 00 00 00 00          nop
        800785ec c8 09 48 ac          sw              t0,DAT_000009c8 (dst)
        800785f0 04 00 4a 25          addiu           src,src,0x4
        800785f4 fb ff 49 15          bne             src,t1,PATCH_OBJ_1AC
        800785f8 04 00 42 24          _addiu          dst,dst,0x4
        800785fc e2 e0 01 0c          jal             FlushCache                                       void FlushCache(void)
        80078600 00 00 00 00          _nop
        80078604 10 80 1f 3c          lui             ra,0x8010
        80078608 90 37 ff 8f          lw              ra,offset  DAT_80103790 (ra)                      = ??
        8007860c 00 00 00 00          nop
        80078610 08 00 e0 03          jr              ra
        80078614 00 00 00 00          _nop

 */

// clang-format on

#ifndef GENERATE_HASHES

// not doing anything about it for now
int patch_card2_2_execute(uint32_t* ra) {
    ra[2] = 9 | 0x10000000;
    ra[3] = 0;
    return 1;
}

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    0, 0, 0, 1,  // 00
    1, 1, 1, 0,  // 10
    0, 0, 0, 0,  // 20
    0, 2, 0, 1,  // 30
};

static const uint8_t bytes[] = {
    0x6c, 0x01, 0x42, 0x8c, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x09, 0x43, 0x8c, 0x00, 0x00, 0x0a, 0x3c,  // 00
    0x00, 0x00, 0x4a, 0x25, 0x00, 0x00, 0x09, 0x3c, 0x00, 0x00, 0x29, 0x25, 0x00, 0x00, 0x48, 0x8d,  // 10
    0x00, 0x00, 0x00, 0x00, 0xc8, 0x09, 0x48, 0xac, 0x04, 0x00, 0x4a, 0x25, 0xfb, 0xff, 0x49, 0x15,  // 20
    0x04, 0x00, 0x42, 0x24, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x3c,  // 30
};

uint32_t generate_hash_patch_card2_2(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t *)bytes, (uint8_t *)&mask, len);
}

uint32_t generate_mask_patch_card2_2() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
