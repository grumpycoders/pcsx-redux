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

/* Found in Xenogears NTSC (SLUS-00664):

                    *************************************************************
                    *                           FUNCTION                          
                    *************************************************************
                             undefined  _remove_ChgclrPAD ()
                               assume gp = 0x0
             undefined         v0:1           <RETURN>                                XREF[1]:     80040c70 (W)  
             dword * *         v0:4           B0table                                 XREF[1]:     80040c70 (W)  
             undefined4        t2:4           count                                   XREF[1]:     80040c7c (W)  
             undefined4        v1:4           ptr                                     XREF[1]:     80040c84 (W)  
                             _remove_ChgclrPAD                               XREF[2]:     FUN_8004078c:800407b0 (c), 
                                                                                          FUN_80040828:8004084c (c)  
        80040c5c 06 80 01 3c          lui             at,0x8006
             assume gp = <UNKNOWN>
        80040c60 c4 93 3f ac          sw              ra,-0x6c3c (at)=>DAT_800593c4
        80040c64 35 01 01 0c          jal             EnterCriticalSection                             undefined EnterCriticalSection()
        80040c68 00 00 00 00          _nop
        80040c6c b0 00 0a 24          li              t2,0xb0
        80040c70 09 f8 40 01          jalr            t2=>SUB_000000b0
        80040c74 57 00 09 24          _li             t1,0x57
        80040c78 6c 01 42 8c          lw              B0table ,0x16c (B0table )
        80040c7c 09 00 0a 24          li              count ,0x9
        80040c80 2c 06 43 20          addi            v1,B0table ,0x62c

                             LAB_80040c84                                    XREF[1]:     80040c8c (j)  
        80040c84 ff ff 4a 25          addiu           count ,count ,-0x1
        80040c88 00 00 60 ac          sw              zero,0x0(ptr)
        80040c8c fd ff 40 15          bne             count ,zero,LAB_80040c84
        80040c90 04 00 63 24          _addiu          ptr,ptr,0x4
        80040c94 15 01 01 0c          jal             FlushCache                                       undefined FlushCache()
        80040c98 00 00 00 00          _nop
        80040c9c 39 01 01 0c          jal             ExitCriticalSection                              undefined ExitCriticalSection()
        80040ca0 00 00 00 00          _nop
        80040ca4 06 80 1f 3c          lui             ra,0x8006
        80040ca8 c4 93 ff 8f          lw              ra,-0x6c3c (ra)=>DAT_800593c4
        80040cac 00 00 00 00          nop
        80040cb0 08 00 e0 03          jr              ra
        80040cb4 00 00 00 00          _nop


    This patch nops out the code that automatically ACK pad IRQ in the handler.
    We toggle a boolean for this instead if we detect this patch.

    See sio0/driver.c for more details.

 */

// clang-format on

#ifndef GENERATE_HASHES

int remove_ChgclrPAD_2_execute(uint32_t* ra) {
    patch_remove_ChgclrPAD();

    ra[2] = 5 | 0x10000000;
    ra[3] = 0;

    return 1;
}

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    0, 0, 0, 0, // 00
    0, 0, 0, 2, // 10
    0, 2, 0, 1, // 20
    1, 0, 0, 0, // 30
};

static const uint8_t bytes[] = {
    0x6c, 0x01, 0x42, 0x8c, 0x09, 0x00, 0x0a, 0x24, 0x2c, 0x06, 0x43, 0x20, 0xff, 0xff, 0x4a, 0x25, // 00
    0x00, 0x00, 0x60, 0xac, 0xfd, 0xff, 0x40, 0x15, 0x04, 0x00, 0x63, 0x24, 0x00, 0x00, 0x00, 0x0c, // 10
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x3c, // 20
    0x00, 0x00, 0xff, 0x8f, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0xe0, 0x03, 0x00, 0x00, 0x00, 0x00, // 30
};

uint32_t generate_hash_remove_ChgclrPAD_2(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t*) bytes, (uint8_t *) &mask, len);
}

uint32_t generate_mask_remove_ChgclrPAD_2() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
