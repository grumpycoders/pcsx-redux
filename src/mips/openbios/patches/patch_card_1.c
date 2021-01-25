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

/* Found in Tomba! NTSC (SCUS-94236):

                    *************************************************************
                    *                           FUNCTION
                    *************************************************************
                             undefined  _patch_card ()
                               assume gp = 0x80097fa8
             undefined         v0:1           <RETURN>                                XREF[1]:     8005ce34 (W)
             dword * *         v0:4           C0Table                                 XREF[1]:     8005ce34 (W)
             dword *           t2:4           src                                     XREF[1]:     8005ce6c (W)
             dword *           v0:4           dst
             undefined4        v1:4           tmp                                     XREF[1]:     8005ce74 (W)
                             _patch_card                                     XREF[1]:     FUN_8005cccc:8005ccf4 (c)
        8005ce20 0a 80 01 3c          lui             at,0x800a
             assume gp = <UNKNOWN>
        8005ce24 b0 af 3f ac          sw              ra,-0x5050 (at)=>DAT_8009afb0                    = ??
        8005ce28 07 6d 01 0c          jal             EnterCriticalSection                             undefined EnterCriticalSection()
        8005ce2c 00 00 00 00          _nop
        8005ce30 b0 00 0a 24          li              t2,0xb0
        8005ce34 09 f8 40 01          jalr            t2=>SUB_000000b0
        8005ce38 56 00 09 24          _li             t1,0x56
        8005ce3c 18 00 42 8c          lw              C0Table ,0x18(C0Table )
        8005ce40 00 00 00 00          nop
        8005ce44 70 00 43 8c          lw              v1,0x70(C0Table )
        8005ce48 00 00 00 00          nop
        8005ce4c ff ff 69 30          andi            t1,v1,0xffff
        8005ce50 74 00 43 8c          lw              v1,0x74(C0Table )
        8005ce54 00 4c 09 00          sll             t1,t1,0x10
        8005ce58 ff ff 6a 30          andi            t2,v1,0xffff
        8005ce5c 21 18 2a 01          addu            v1,t1,t2
        8005ce60 06 80 0a 3c          lui             t2,0x8006
        8005ce64 06 80 09 3c          lui             t1,0x8006
        8005ce68 28 00 62 24          addiu           C0Table ,v1,0x28
        8005ce6c c8 cd 4a 25          addiu           src,src,-0x3238
        8005ce70 dc cd 29 25          addiu           t1,t1,-0x3224
                             PATCH_OBJ_AC                                    XREF[1]:     8005ce80 (j)
        8005ce74 00 00 43 8d          lw              tmp,0x0(src)=>PATCH_OBJ_0
        8005ce78 04 00 4a 25          addiu           src,src,0x4
        8005ce7c 04 00 42 24          addiu           dst,dst,0x4
        8005ce80 fc ff 49 15          bne             src,t1,PATCH_OBJ_AC
        8005ce84 fc ff 43 ac          _sw             tmp,-0x4(dst)
        8005ce88 0a 80 01 3c          lui             at,0x800a
        8005ce8c e3 6c 01 0c          jal             FlushCache                                       undefined FlushCache()
        8005ce90 b4 af 22 ac          _sw             dst,-0x504c (at)=>ptrnext                        = ??
        8005ce94 0a 80 1f 3c          lui             ra,0x800a
        8005ce98 b0 af ff 8f          lw              ra,-0x5050 (ra)=>DAT_8009afb0                    = ??
        8005ce9c 00 00 00 00          nop
        8005cea0 08 00 e0 03          jr              ra
        8005cea4 00 00 00 00          _nop

 */

// clang-format on

#ifndef GENERATE_HASHES

// not doing anything about it for now
int patch_card_1_execute(uint32_t* ra) {
    ra[2] = 16 | 0x10000000;
    ra[3] = 0;
    return 1;
}

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    0, 0, 0, 0,  // 00
    0, 0, 0, 0,  // 10
    0, 1, 1, 0,  // 20
    1, 1, 0, 0,  // 30
};

static const uint8_t bytes[] = {
    0x18, 0x00, 0x42, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x43, 0x8c, 0x00, 0x00, 0x00, 0x00,  // 00
    0xff, 0xff, 0x69, 0x30, 0x74, 0x00, 0x43, 0x8c, 0x00, 0x4c, 0x09, 0x00, 0xff, 0xff, 0x6a, 0x30,  // 10
    0x21, 0x18, 0x2a, 0x01, 0x00, 0x00, 0x0a, 0x3c, 0x00, 0x00, 0x09, 0x3c, 0x28, 0x00, 0x62, 0x24,  // 20
    0x00, 0x00, 0x4a, 0x25, 0x00, 0x00, 0x29, 0x25, 0x00, 0x00, 0x43, 0x8d, 0x04, 0x00, 0x4a, 0x25,  // 30
};

uint32_t generate_hash_patch_card_1(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t *)bytes, (uint8_t *)&mask, len);
}

uint32_t generate_mask_patch_card_1() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
