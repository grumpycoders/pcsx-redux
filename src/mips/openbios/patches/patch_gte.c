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

/* Found in Suikoden 2 NTSC (SLUS-00958):

                    *************************************************************
                    *                           FUNCTION                          
                    *************************************************************
                             undefined  _patch_gte ()
                               assume gp = 0x80109798
             undefined         v0:1           <RETURN>                                XREF[2]:     800df484 (W), 
                                                                                                   800df4dc (W)  
             dword * *         v0:4           C0table                                 XREF[1]:     800df484 (W)  
             undefined4        t2:4           srcMatchPtr                             XREF[1]:     800df4a0 (W)  
             undefined4        v1:4           srcMatch                                XREF[1]:     800df4ac (W)  
             undefined4        t3:4           dstMatch                                XREF[1]:     800df4b0 (W)  
             undefined4        t2:4           dstMatchPtr                             XREF[1]:     800df4d0 (W)  
             undefined4        v0:4           dst                                     XREF[1]:     800df4dc (W)  
                             _patch_gte                                      XREF[1]:     InitGeom:800ddc1c (c)  
        800df46c 11 80 01 3c          lui             at,0x8011
             assume gp = <UNKNOWN>
        800df470 00 9b 3f ac          sw              ra,-0x6500 (at)=>DAT_80109b00                    = ??
        800df474 6f 52 03 0c          jal             EnterCriticalSection                             int EnterCriticalSection(void)
        800df478 00 00 00 00          _nop
        800df47c 56 00 09 24          li              t1,0x56
        800df480 b0 00 0a 24          li              t2,0xb0
        800df484 09 f8 40 01          jalr            t2=>SUB_000000b0
        800df488 00 00 00 00          _nop
        800df48c 18 00 42 8c          lw              C0table ,0x18(C0table )
        800df490 00 00 00 00          nop
        800df494 28 00 42 24          addiu           C0table ,C0table ,0x28
        800df498 21 78 40 00          move            t7,C0table
        800df49c 0e 80 0a 3c          lui             t2,0x800e
        800df4a0 18 f5 4a 25          addiu           srcMatchPtr ,srcMatchPtr ,-0xae8
        800df4a4 0e 80 09 3c          lui             t1,0x800e
        800df4a8 30 f5 29 25          addiu           t1,t1,-0xad0

                             LAB_800df4ac                                    XREF[1]:     800df4c0 (j)  
        800df4ac 00 00 43 8d          lw              srcMatch ,0x0(srcMatchPtr )=>matching_eh_start
        800df4b0 00 00 4b 8c          lw              dstMatch ,0x0(C0table )
        800df4b4 04 00 4a 25          addiu           srcMatchPtr ,srcMatchPtr ,0x4
        800df4b8 0e 00 6b 14          bne             srcMatch ,dstMatch ,LAB_800df4f4
        800df4bc 04 00 42 24          _addiu          C0table ,C0table ,0x4
        800df4c0 fa ff 49 15          bne             srcMatchPtr ,t1,LAB_800df4ac
        800df4c4 00 00 00 00          _nop
        800df4c8 21 10 e0 01          move            C0table ,t7
        800df4cc 0e 80 0a 3c          lui             srcMatchPtr ,0x800e
        800df4d0 30 f5 4a 25          addiu           dstMatchPtr ,dstMatchPtr ,-0xad0
        800df4d4 0e 80 09 3c          lui             t1,0x800e
        800df4d8 48 f5 29 25          addiu           t1,t1,-0xab8

                             LAB_800df4dc                                    XREF[1]:     800df4ec (j)  
        800df4dc 00 00 43 8d          lw              srcMatch ,0x0(dstMatchPtr )=>new_eh_start
        800df4e0 00 00 00 00          nop
        800df4e4 00 00 43 ac          sw              srcMatch ,0x0(dst)
        800df4e8 04 00 4a 25          addiu           dstMatchPtr ,dstMatchPtr ,0x4
        800df4ec fb ff 49 15          bne             dstMatchPtr ,t1,LAB_800df4dc
        800df4f0 04 00 42 24          _addiu          dst,dst,0x4

                             LAB_800df4f4                                    XREF[1]:     800df4b8 (j)  
        800df4f4 53 7d 03 0c          jal             FlushCache                                       void FlushCache(void)
        800df4f8 00 00 00 00          _nop
        800df4fc 73 52 03 0c          jal             ExitCriticalSection                              void ExitCriticalSection(void)
        800df500 00 00 00 00          _nop
        800df504 11 80 1f 3c          lui             ra,0x8011
        800df508 00 9b ff 8f          lw              ra,-0x6500 (ra)=>DAT_80109b00                    = ??
        800df50c 00 00 00 00          nop
        800df510 08 00 e0 03          jr              ra
        800df514 00 00 00 00          _nop

                             matching_eh_start                               XREF[1]:     _patch_gte:800df4ac (R)  
        800df518 04 00 41 af          sw              at,0x4(k0)

                             LAB_800df51c                                    XREF[1]:     _patch_gte:800df4ac (R)  
        800df51c 08 00 42 af          sw              v0,0x8(k0)
        800df520 0c 00 43 af          sw              v1,0xc(k0)
        800df524 7c 00 5f af          sw              ra,0x7c(k0)
        800df528 00 70 03 40          mfc0            v1,EPC
        800df52c 00 00 00 00          nop

                             new_eh_start                                    XREF[1]:     _patch_gte:800df4dc (R)  
        800df530 04 00 41 af          sw              at,0x4(k0)

                             LAB_800df534                                    XREF[1]:     _patch_gte:800df4dc (R)  
        800df534 08 00 42 af          sw              v0,0x8(k0)
        800df538 00 68 02 40          mfc0            v0,Cause
        800df53c 0c 00 43 af          sw              v1,0xc(k0)
        800df540 00 70 03 40          mfc0            v1,EPC
        800df544 7c 00 5f af          sw              ra,0x7c(k0)

                             new_eh_end
        800df548 00 00 00 00          nop

    This patch fixes older versions of the exception handler, which didn't
    take GTE instructions into account properly. Our exception handler is
    correct, so no patch nor behavior change is necessary.

 */

int patch_gte_execute(uint32_t* ra) { return 1; }

#ifdef GENERATE_HASHES
#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    0, 0, 0, 0, // 00
    1, 1, 1, 1, // 10
    0, 0, 0, 0, // 20
    0, 0, 0, 0, // 30
};

static const uint8_t bytes[] = {
    0x18, 0x00, 0x42, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x42, 0x24, 0x21, 0x78, 0x40, 0x00, // 00
    0x00, 0x00, 0x0a, 0x3c, 0x00, 0x00, 0x4a, 0x25, 0x00, 0x00, 0x09, 0x3c, 0x00, 0x00, 0x29, 0x25, // 10
    0x00, 0x00, 0x43, 0x8d, 0x00, 0x00, 0x4b, 0x8c, 0x04, 0x00, 0x4a, 0x25, 0x0e, 0x00, 0x6b, 0x14, // 20
    0x04, 0x00, 0x42, 0x24, 0xfa, 0xff, 0x49, 0x15, 0x00, 0x00, 0x00, 0x00, 0x21, 0x10, 0xe0, 0x01, // 30
};

uint32_t generate_hash_patch_gte(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t*) bytes, (uint8_t *) &mask, len);
}

uint32_t generate_mask_patch_gte() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
