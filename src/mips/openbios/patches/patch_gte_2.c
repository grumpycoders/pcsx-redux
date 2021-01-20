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

/* Found in Xenogears NTSC (SLUS-00664):

                    *************************************************************
                    *                           FUNCTION                          
                    *************************************************************
                             undefined  _patch_gte ()
                               assume gp = 0x0
             undefined         v0:1           <RETURN>                                XREF[1]:     8004b4c0 (W)  
             dword * *         v0:4           C0table                                 XREF[1]:     8004b4c0 (W)  
             undefined4        t2:4           src                                     XREF[1]:     8004b4d4 (W)  
             undefined4        v0:4           dst
             undefined4        v1:4           value                                   XREF[1]:     8004b4dc (W)  
                             _patch_gte                                      XREF[1]:     InitGeom:80048bcc (c)  
        8004b4ac 06 80 01 3c          lui             at,0x8006
             assume gp = <UNKNOWN>
        8004b4b0 d4 93 3f ac          sw              ra,-0x6c2c (at)=>DAT_800593d4
        8004b4b4 35 01 01 0c          jal             EnterCriticalSection                             undefined EnterCriticalSection()
        8004b4b8 00 00 00 00          _nop
        8004b4bc b0 00 0a 24          li              t2,0xb0
        8004b4c0 09 f8 40 01          jalr            t2=>SUB_000000b0
        8004b4c4 56 00 09 24          _li             t1,0x56
        8004b4c8 05 80 0a 3c          lui             t2,0x8005
        8004b4cc 05 80 09 3c          lui             t1,0x8005
        8004b4d0 18 00 42 8c          lw              C0table ,0x18(C0table )
        8004b4d4 14 b5 4a 25          addiu           src,src,-0x4aec
        8004b4d8 4c b5 29 25          addiu           t1,t1,-0x4ab4

                             LAB_8004b4dc                                    XREF[1]:     8004b4e8 (j)  
        8004b4dc 00 00 43 8d          lw              value ,0x0(src)=>new_eh_start
        8004b4e0 04 00 4a 25          addiu           src,src,0x4
        8004b4e4 04 00 42 24          addiu           dst,dst,0x4
        8004b4e8 fc ff 49 15          bne             src,t1,LAB_8004b4dc
        8004b4ec fc ff 43 ac          _sw             value ,-0x4(dst)
        8004b4f0 15 01 01 0c          jal             FlushCache                                       undefined FlushCache()
        8004b4f4 00 00 00 00          _nop
        8004b4f8 39 01 01 0c          jal             ExitCriticalSection                              undefined ExitCriticalSection()
        8004b4fc 00 00 00 00          _nop
        8004b500 06 80 1f 3c          lui             ra,0x8006
        8004b504 d4 93 ff 8f          lw              ra,-0x6c2c (ra)=>DAT_800593d4
        8004b508 00 00 00 00          nop
        8004b50c 08 00 e0 03          jr              ra
        8004b510 00 00 00 00          _nop

                             new_eh_start                                    XREF[1]:     _patch_gte:8004b4dc (R)  
        8004b514 00 00 00 00          nop

                             LAB_8004b518                                    XREF[1]:     _patch_gte:8004b4dc (R)  
        8004b518 00 00 00 00          nop
        8004b51c 00 01 1a 24          li              k0,0x100
        8004b520 08 00 5a 8f          lw              k0,offset  DAT_00000108 (k0)
        8004b524 00 00 00 00          nop
        8004b528 00 00 5a 8f          lw              k0,0x0(k0)
        8004b52c 00 00 00 00          nop
        8004b530 08 00 5a 23          addi            k0,k0,0x8
        8004b534 04 00 41 af          sw              at,0x4(k0)
        8004b538 08 00 42 af          sw              v0,0x8(k0)
        8004b53c 0c 00 43 af          sw              v1,0xc(k0)
        8004b540 7c 00 5f af          sw              ra,0x7c(k0)
        8004b544 00 68 02 40          mfc0            v0,Cause
        8004b548 00 00 00 00          nop


    This patch fixes older versions of the exception handler, which didn't
    take GTE instructions into account properly. Our exception handler is
    correct, so no patch nor behavior change is necessary.

 */

#ifndef GENERATE_HASHES

int patch_gte_2_execute(uint32_t* ra) {
    ra[2] = 8 | 0x10000000;
    ra[3] = 0;
    return 1;
}

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    1, 1, 0, 1, // 00
    1, 0, 0, 0, // 10
    0, 0, 2, 0, // 20
    2, 0, 1, 1, // 30
};

static const uint8_t bytes[] = {
    0x00, 0x00, 0x0a, 0x3c, 0x00, 0x00, 0x09, 0x3c, 0x18, 0x00, 0x42, 0x8c, 0x00, 0x00, 0x4a, 0x25, // 00
    0x00, 0x00, 0x29, 0x25, 0x00, 0x00, 0x43, 0x8d, 0x04, 0x00, 0x4a, 0x25, 0x04, 0x00, 0x42, 0x24, // 10
    0xfc, 0xff, 0x49, 0x15, 0xfc, 0xff, 0x43, 0xac, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, // 20
    0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x3c, 0x00, 0x00, 0xff, 0x8f, // 30
};

uint32_t generate_hash_patch_gte_2(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t*) bytes, (uint8_t *) &mask, len);
}

uint32_t generate_mask_patch_gte_2() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
