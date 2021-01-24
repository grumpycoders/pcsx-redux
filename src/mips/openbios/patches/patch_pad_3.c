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

/* Found in Pandemonium 2 PAL (SLES-00965):

                    *************************************************************
                    *                           FUNCTION                          
                    *************************************************************
                             undefined  _patch_pad ()
                               assume gp = 0x8008a600
             undefined         v0:1           <RETURN>                                XREF[2]:     80083c98 (W), 
                                                                                                   80083ca0 (W)  
             dword * *         v0:4           B0table                                 XREF[1]:     80083c98 (W)  
             undefined4        v0:4           dst                                     XREF[1]:     80083ca0 (W)  
             undefined4        t1:4           count                                   XREF[1]:     80083ca4 (W)  
                             _patch_pad                                      XREF[2]:     PAD_init:80083b80 (c), 
                                                                                          InitPAD:80083be8 (c)  
        80083c84 09 80 01 3c          lui             at,0x8009
             assume gp = <UNKNOWN>
        80083c88 28 a9 3f ac          sw              ra,-0x56d8 (at)=>DAT_8008a928
        80083c8c 69 0e 02 0c          jal             EnterCriticalSection                             undefined EnterCriticalSection()
        80083c90 00 00 00 00          _nop
        80083c94 b0 00 0a 24          li              t2,0xb0
        80083c98 09 f8 40 01          jalr            t2=>SUB_000000b0
        80083c9c 57 00 09 24          _li             t1,0x57
        80083ca0 6c 01 42 8c          lw              dst,0x16c (dst)
        80083ca4 0b 00 09 24          li              count ,0xb
                             PATCH_OBJ_24                                    XREF[1]:     80083cb0 (j)  
        80083ca8 ff ff 29 25          addiu           count ,count ,-0x1
        80083cac 94 05 40 ac          sw              zero,0x594 (dst)
        80083cb0 fd ff 20 15          bne             count ,zero,PATCH_OBJ_24
        80083cb4 04 00 42 24          _addiu          dst,dst,0x4
        80083cb8 2d 0e 02 0c          jal             FlushCache                                       undefined FlushCache()
        80083cbc 00 00 00 00          _nop
        80083cc0 09 80 1f 3c          lui             ra,0x8009
        80083cc4 28 a9 ff 8f          lw              ra,-0x56d8 (ra)=>DAT_8008a928
        80083cc8 00 00 00 00          nop
        80083ccc 08 00 e0 03          jr              ra
                             LAB_80083cd0                                    XREF[1]:     FUN_80017004:80017030 (R)  
        80083cd0 00 00 00 00          _nop


    This patch nops out the code that automatically changes slot on pad abort.
    We toggle a boolean for this instead if we detect this patch.

    See sio0/driver.c for more details.

 */

// clang-format on

#ifndef GENERATE_HASHES

int patch_pad_3_execute(uint32_t* ra) {
    patch_disable_slotChangeOnAbort();
    uint32_t ptr;
    int16_t addend;

    ra[2] = 2 | 0x10000000;
    ra[3] = 0;

    return 1;
}

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    0, 0, 0, 0, // 00
    0, 0, 2, 0, // 10
    1, 1, 0, 0, // 20
    0, 3, 3, 3, // 30
};

static const uint8_t bytes[] = {
    0x6c, 0x01, 0x42, 0x8c, 0x0b, 0x00, 0x09, 0x24, 0xff, 0xff, 0x29, 0x25, 0x94, 0x05, 0x40, 0xac, // 00
    0xfd, 0xff, 0x20, 0x15, 0x04, 0x00, 0x42, 0x24, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, // 10
    0x00, 0x00, 0x1f, 0x3c, 0x00, 0x00, 0xff, 0x8f, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0xe0, 0x03, // 20
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 30
};

uint32_t generate_hash_patch_pad_3(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t*) bytes, (uint8_t *) &mask, len);
}

uint32_t generate_mask_patch_pad_3() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
