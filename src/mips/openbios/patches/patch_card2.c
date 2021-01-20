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

/* Found in Tomba! NTSC (SCUS-94236):

                    *************************************************************
                    *                           FUNCTION                          
                    *************************************************************
                             undefined  _patch_card2 ()
                               assume gp = 0x80097fa8
             undefined         v0:1           <RETURN>                                XREF[2]:     8005ceec (W), 
                                                                                                   8005cf0c (W)  
             dword * *         v0:4           B0table                                 XREF[1]:     8005ceec (W)  
             undefined4        v0:4           dst                                     XREF[1]:     8005cf0c (W)  
             undefined4        t2:4           src
             undefined4        t0:4           tmp                                     XREF[1]:     8005cf10 (W)  
             undefined4        t2:4           nextSrc                                 XREF[1]:     8005cf14 (W)  
                             _patch_card2                                    XREF[2]:     FUN_8005cccc:8005ccfc (c), 
                                                                                          FUN_8005cd58:8005cd68 (c)  
        8005ced8 0a 80 01 3c          lui             at,0x800a
             assume gp = <UNKNOWN>
        8005cedc b0 af 3f ac          sw              ra,-0x5050 (at)=>DAT_8009afb0                    = ??
        8005cee0 07 6d 01 0c          jal             EnterCriticalSection                             undefined EnterCriticalSection()
        8005cee4 00 00 00 00          _nop
        8005cee8 b0 00 0a 24          li              t2,0xb0
        8005ceec 09 f8 40 01          jalr            t2=>SUB_000000b0
        8005cef0 57 00 09 24          _li             t1,0x57
        8005cef4 6c 01 42 8c          lw              B0table ,0x16c (B0table )
        8005cef8 06 80 0a 3c          lui             t2,0x8006
        8005cefc 06 80 09 3c          lui             t1,0x8006
        8005cf00 c8 09 43 8c          lw              v1,0x9c8 (B0table )
        8005cf04 a8 ce 4a 25          addiu           t2,t2,-0x3158
        8005cf08 bc ce 29 25          addiu           t1,t1,-0x3144
                             PATCH_OBJ_144                                   XREF[1]:     8005cf20 (j)  
        8005cf0c c8 09 43 8c          lw              v1,0x9c8 (dst)
        8005cf10 00 00 48 8d          lw              tmp,0x0(src)=>PATCH_OBJ_E0
        8005cf14 04 00 4a 25          addiu           nextSrc ,nextSrc ,0x4
        8005cf18 fc ff 43 ad          sw              v1,-0x4(nextSrc )=>PATCH_OBJ_E0
        8005cf1c 04 00 42 24          addiu           dst,dst,0x4
        8005cf20 fa ff 49 15          bne             nextSrc ,t1,PATCH_OBJ_144
        8005cf24 c4 09 48 ac          _sw             tmp,0x9c4 (dst)
        8005cf28 e3 6c 01 0c          jal             FlushCache                                       undefined FlushCache()
        8005cf2c 00 00 00 00          _nop
        8005cf30 0a 80 1f 3c          lui             ra,0x800a
        8005cf34 b0 af ff 8f          lw              ra,-0x5050 (ra)=>DAT_8009afb0                    = ??
        8005cf38 00 00 00 00          nop
        8005cf3c 08 00 e0 03          jr              ra
        8005cf40 00 00 00 00          _nop

 */

#ifndef GENERATE_HASHES

// not doing anything about it for now
int patch_card2_execute(uint32_t* ra) {
    ra[2] = 9 | 0x10000000;
    ra[3] = 0;
    return 1;
}

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    0, 1, 1, 0, // 00
    1, 1, 0, 0, // 10
    0, 0, 0, 0, // 20
    0, 2, 0, 1, // 30
};

static const uint8_t bytes[] = {
    0x6c, 0x01, 0x42, 0x8c, 0x00, 0x00, 0x0a, 0x3c, 0x00, 0x00, 0x09, 0x3c, 0xc8, 0x09, 0x43, 0x8c, // 00
    0x00, 0x00, 0x4a, 0x25, 0x00, 0x00, 0x29, 0x25, 0xc8, 0x09, 0x43, 0x8c, 0x00, 0x00, 0x48, 0x8d, // 10
    0x04, 0x00, 0x4a, 0x25, 0xfc, 0xff, 0x43, 0xad, 0x04, 0x00, 0x42, 0x24, 0xfa, 0xff, 0x49, 0x15, // 20
    0xc4, 0x09, 0x48, 0xac, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x3c, // 30
};

uint32_t generate_hash_patch_card2(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t*) bytes, (uint8_t *) &mask, len);
}

uint32_t generate_mask_patch_card2() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
