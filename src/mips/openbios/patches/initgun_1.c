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

/* Found in Gex (rev1.1) NTSC (SLUS-00042), file MAIN.EXE:

                    *************************************************************
                    *                           FUNCTION
                    *************************************************************
                             undefined  _InitGun ()
                               assume gp = 0x80048090
             undefined         v0:1           <RETURN>                                XREF[2]:     80034708 (W),
                                                                                                   80034724 (W)
             dword * *         v0:4           C0table                                 XREF[1]:     80034708 (W)
             undefined4        t2:4           src                                     XREF[1]:     8003471c (W)
             undefined4        v0:4           dst                                     XREF[1]:     80034724 (W)
             undefined4        v1:4           tmp
                             _InitGun                                        XREF[1]:     GUN_OBJ_7A4:800342bc (c)
        800346e8 05 80 01 3c          lui             at,0x8005
             assume gp = <UNKNOWN>
        800346ec 10 85 3f ac          sw              ra,-0x7af0 (at)=>DAT_80048510
        800346f0 05 80 01 3c          lui             at,0x8005
        800346f4 0c 85 24 ac          sw              a0,-0x7af4 (at)=>DAT_8004850c
        800346f8 05 80 01 3c          lui             at,0x8005
        800346fc 3a 7c 00 0c          jal             EnterCriticalSection                             undefined EnterCriticalSection()
        80034700 14 85 25 ac          _sw             a1,-0x7aec (at)=>DAT_80048514
        80034704 b0 00 0a 24          li              t2,0xb0
        80034708 09 f8 40 01          jalr            t2=>SUB_000000b0
        8003470c 56 00 09 24          _li             t1,0x56
        80034710 03 80 0a 3c          lui             t2,0x8003
        80034714 03 80 09 3c          lui             t1,0x8003
        80034718 18 00 42 8c          lw              C0table ,0x18(C0table )
        8003471c d8 47 4a 25          addiu           src,src,0x47d8
        80034720 e8 47 29 25          addiu           t1,t1,0x47e8
                             NEWGUN_OBJ_3C                                   XREF[1]:     80034730 (j)
        80034724 00 00 43 8d          lw              tmp,0x0(src)=>NEWGUN_OBJ_F0
        80034728 04 00 4a 25          addiu           src,src,0x4
        8003472c 04 00 42 24          addiu           dst,dst,0x4
        80034730 fc ff 49 15          bne             src,t1,NEWGUN_OBJ_3C
        80034734 7c 00 43 ac          _sw             tmp,0x7c(dst)
        80034738 16 94 00 0c          jal             FlushCache                                       void FlushCache(void)
        8003473c 00 00 00 00          _nop
        80034740 05 80 1f 3c          lui             ra,0x8005
        80034744 10 85 ff 8f          lw              ra,-0x7af0 (ra)=>DAT_80048510
        80034748 00 00 00 00          nop
        8003474c 08 00 e0 03          jr              ra
        80034750 00 00 00 00          _nop

    This patch adds a new early exception handler. We can allow it to go on, since it's
    not going to conflict with anything from our own handler.

 */

// clang-format on

#ifndef GENERATE_HASHES

// allowing it to run
int initgun_1_execute(uint32_t* ra) { return 2; }

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    1, 1, 0, 1,  // 00
    1, 0, 0, 0,  // 10
    0, 0, 2, 0,  // 20
    1, 1, 0, 0,  // 30
};

static const uint8_t bytes[] = {
    0x00, 0x00, 0x0a, 0x3c, 0x00, 0x00, 0x09, 0x3c, 0x18, 0x00, 0x42, 0x8c, 0x00, 0x00, 0x4a, 0x25,  // 00
    0x00, 0x00, 0x29, 0x25, 0x00, 0x00, 0x43, 0x8d, 0x04, 0x00, 0x4a, 0x25, 0x04, 0x00, 0x42, 0x24,  // 10
    0xfc, 0xff, 0x49, 0x15, 0x7c, 0x00, 0x43, 0xac, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,  // 20
    0x00, 0x00, 0x1f, 0x3c, 0x00, 0x00, 0xff, 0x8f, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0xe0, 0x03,  // 30
};

uint32_t generate_hash_initgun_1(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t *)bytes, (uint8_t *)&mask, len);
}

uint32_t generate_mask_initgun_1() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
