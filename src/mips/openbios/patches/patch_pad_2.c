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
                             undefined  _patch_pad ()
                               assume gp = 0x0
             undefined         v0:1           <RETURN>                                XREF[2]:     80040b28 (W), 
                                                                                                   80040b30 (W)  
             dword * *         v0:4           B0table                                 XREF[1]:     80040b28 (W)  
             undefined4        v0:4           ptr                                     XREF[1]:     80040b30 (W)  
             undefined4        t1:4           count                                   XREF[1]:     80040b48 (W)  
                             _patch_pad                                      XREF[2]:     FUN_8004078c:800407c0 (c), 
                                                                                          FUN_80040828:8004085c (c)  
        80040b14 06 80 01 3c          lui             at,0x8006
             assume gp = <UNKNOWN>
        80040b18 a4 93 3f ac          sw              ra,-0x6c5c (at)=>DAT_800593a4
        80040b1c 35 01 01 0c          jal             EnterCriticalSection                             undefined EnterCriticalSection()
        80040b20 00 00 00 00          _nop
        80040b24 b0 00 0a 24          li              t2,0xb0
        80040b28 09 f8 40 01          jalr            t2=>SUB_000000b0
        80040b2c 57 00 09 24          _li             t1,0x57
        80040b30 6c 01 42 8c          lw              ptr,0x16c (ptr)
        80040b34 06 80 01 3c          lui             at,0x8006
        80040b38 84 08 43 20          addi            v1,ptr,0x884
        80040b3c ac 93 23 ac          sw              v1,-0x6c54 (at)=>capture_startPad
        80040b40 06 80 01 3c          lui             at,0x8006
        80040b44 94 08 43 20          addi            v1,ptr,0x894
        80040b48 0b 00 09 24          li              count ,0xb
        80040b4c b0 93 23 ac          sw              v1,-0x6c50 (at)=>capture_stopPad

                             LAB_80040b50                                    XREF[1]:     80040b58 (j)  
        80040b50 ff ff 29 25          addiu           count ,count ,-0x1
        80040b54 94 05 40 ac          sw              zero,0x594 (ptr)
        80040b58 fd ff 20 15          bne             count ,zero,LAB_80040b50
        80040b5c 04 00 42 24          _addiu          ptr,ptr,0x4
        80040b60 15 01 01 0c          jal             FlushCache                                       undefined FlushCache()
        80040b64 00 00 00 00          _nop
        80040b68 06 80 1f 3c          lui             ra,0x8006
        80040b6c a4 93 ff 8f          lw              ra,-0x6c5c (ra)=>DAT_800593a4
        80040b70 00 00 00 00          nop
        80040b74 08 00 e0 03          jr              ra
        80040b78 00 00 00 00          _nop


    This patch nops out the code that automatically changes slot on pad abort,
    and grabs the pointer to the functions that enables and disables the handler.
    We toggle a boolean for this instead if we detect this patch, and we
    inject some functions for it in the pointers.

    See sio0/driver.c for more details.

 */

// clang-format on

#ifndef GENERATE_HASHES

int patch_pad_2_execute(uint32_t* ra) {
    patch_disable_slotChangeOnAbort();
    uint32_t ptr;
    int16_t addend;

    ptr = ra[1] & 0xffff;
    ptr <<= 16;
    addend = ra[3] & 0xffff;
    ptr += addend;
    *((uint32_t *)ptr) = patch_startPad;

    ptr = ra[4] & 0xffff;
    ptr <<= 16;
    addend = ra[7] & 0xffff;
    ptr += addend;
    *((uint32_t *)ptr) = patch_stopPad;

    ra[2] = 10 | 0x10000000;
    ra[3] = 0;

    return 1;
}

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    0, 1, 0, 1, // 00
    1, 0, 0, 1, // 10
    0, 0, 0, 0, // 20
    2, 0, 1, 1, // 30
};

static const uint8_t bytes[] = {
    0x6c, 0x01, 0x42, 0x8c, 0x00, 0x00, 0x01, 0x3c, 0x84, 0x08, 0x43, 0x20, 0x00, 0x00, 0x23, 0xac, // 00
    0x00, 0x00, 0x01, 0x3c, 0x94, 0x08, 0x43, 0x20, 0x0b, 0x00, 0x09, 0x24, 0x00, 0x00, 0x23, 0xac, // 10
    0xff, 0xff, 0x29, 0x25, 0x94, 0x05, 0x40, 0xac, 0xfd, 0xff, 0x20, 0x15, 0x04, 0x00, 0x42, 0x24, // 20
    0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x3c, 0x00, 0x00, 0xff, 0x8f, // 30
};

uint32_t generate_hash_patch_pad_2(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t*) bytes, (uint8_t *) &mask, len);
}

uint32_t generate_mask_patch_pad_2() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
