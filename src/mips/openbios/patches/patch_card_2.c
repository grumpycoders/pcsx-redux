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

/* Found in Tales of Destiny Disc 2 (SLUS-01367):

                    *************************************************************
                    *                           FUNCTION
                    *************************************************************
                             undefined  _patch_card ()
                               assume gp = 0x800c5454
             undefined         v0:1           <RETURN>                                XREF[1]:     8007852c (W)
             dword * *         v0:4           C0table                                 XREF[1]:     8007852c (W)
             dword *           t2:4           src                                     XREF[1]:     80078564 (W)
                             _patch_card                                     XREF[1]:     InitCARD:80077f28 (c)
        80078514 10 80 01 3c          lui             at,0x8010
             assume gp = <UNKNOWN>
        80078518 90 37 3f ac          sw              ra,offset  DAT_80103790 (at)                      = ??
        8007851c f6 df 01 0c          jal             EnterCriticalSection                             undefined
   EnterCriticalSection() 80078520 00 00 00 00          _nop 80078524 56 00 09 24          li              t1,0x56
        80078528 b0 00 0a 24          li              t2,0xb0
        8007852c 09 f8 40 01          jalr            t2=>SUB_000000b0
        80078530 00 00 00 00          _nop
        80078534 18 00 42 8c          lw              C0table ,0x18(C0table )
        80078538 00 00 00 00          nop
        8007853c 70 00 43 8c          lw              v1,0x70(C0table )
        80078540 00 00 00 00          nop
        80078544 ff ff 69 30          andi            t1,v1,0xffff
        80078548 00 4c 09 00          sll             t1,t1,0x10
        8007854c 74 00 43 8c          lw              v1,0x74(C0table )
        80078550 00 00 00 00          nop
        80078554 ff ff 6a 30          andi            t2,v1,0xffff
        80078558 21 18 2a 01          addu            v1,t1,t2
        8007855c 28 00 62 24          addiu           C0table ,v1,0x28
        80078560 08 80 0a 3c          lui             t2,0x8008
        80078564 ec 84 4a 25          addiu           src,src,-0x7b14
        80078568 08 80 09 3c          lui             t1,0x8008
        8007856c 00 85 29 25          addiu           t1,t1,-0x7b00
                             PATCH_OBJ_138                                   XREF[1]:     80078580 (j)
        80078570 00 00 43 8d          lw              v1,0x0(src)=>PATCH_OBJ_B4
        80078574 00 00 00 00          nop
        80078578 00 00 43 ac          sw              v1,0x0(C0table )
        8007857c 04 00 4a 25          addiu           src,src,0x4
        80078580 fb ff 49 15          bne             src,t1,PATCH_OBJ_138
        80078584 04 00 42 24          _addiu          C0table ,C0table ,0x4
        80078588 01 00 01 3c          lui             at,0x1
        8007858c e2 e0 01 0c          jal             FlushCache                                       void
   FlushCache(void) 80078590 fc df 22 ac          _sw             C0table ,-0x2004 (at)=>ptrnext 80078594 10 80 1f 3c
   lui             ra,0x8010 80078598 90 37 ff 8f          lw              ra,offset  DAT_80103790 (ra) = ?? 8007859c 00
   00 00 00          nop 800785a0 08 00 e0 03          jr              ra 800785a4 00 00 00 00          _nop

 */

#ifndef GENERATE_HASHES

// not doing anything about it for now
int patch_card_2_execute(uint32_t* ra) {
    ra[2] = 18 | 0x10000000;
    ra[3] = 0;
    return 1;
}

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    0, 0, 0, 0,  // 00
    0, 0, 0, 0,  // 10
    0, 0, 0, 1,  // 20
    1, 1, 1, 0,  // 30
};

static const uint8_t bytes[] = {
    0x18, 0x00, 0x42, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x43, 0x8c, 0x00, 0x00, 0x00, 0x00,  // 00
    0xff, 0xff, 0x69, 0x30, 0x00, 0x4c, 0x09, 0x00, 0x74, 0x00, 0x43, 0x8c, 0x00, 0x00, 0x00, 0x00,  // 10
    0xff, 0xff, 0x6a, 0x30, 0x21, 0x18, 0x2a, 0x01, 0x28, 0x00, 0x62, 0x24, 0x00, 0x00, 0x0a, 0x3c,  // 20
    0x00, 0x00, 0x4a, 0x25, 0x00, 0x00, 0x09, 0x3c, 0x00, 0x00, 0x29, 0x25, 0x00, 0x00, 0x43, 0x8d,  // 30
};

uint32_t generate_hash_patch_card_2(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t *)bytes, (uint8_t *)&mask, len);
}

uint32_t generate_mask_patch_card_2() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
