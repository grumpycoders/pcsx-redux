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

#include <stdint.h>

#include "openbios/patches/patches.h"

// clang-format off

/* Found in Alien Trilogy NTSC (SLUS-00007):

                         *******************************************************
                         *                      FUNCTION                       *
                         *******************************************************
                         undefined _patch_gte()
                            assume gp = 0x0
           undefined       v0:1         <RETURN>                           XREF[1]:   80068044(W)
           dword * *       v0:4         C0table                            XREF[1]:   80068044(W)
           undefined4      k0:4         src                                XREF[1]:   80068058(W)
           undefined4      v0:4         dst
           undefined4      v1:4         val                                XREF[1]:   80068060(W)
                         _patch_gte                                XREF[1]:   FUN_80067fb0:80067fb8(c)
      80068030 09 80 01 3c          lui                 at,0x8009
           assume gp = <UNKNOWN>
      80068034 04 d3 3f ac          sw                  ra,-0x2cfc(at)=>DAT_8008d304
      80068038 30 74 01 0c          jal                 EnterCriticalSection                       undefined EnterCriticalSecti
      8006803c 00 00 00 00          _nop
      80068040 b0 00 0a 24          li                  t2,0xb0
      80068044 09 f8 40 01          jalr                t2=>SUB_000000b0
      80068048 56 00 09 24          _li                 t1,0x56
      8006804c 07 80 1a 3c          lui                 k0,0x8007
      80068050 07 80 1b 3c          lui                 k1,0x8007
      80068054 18 00 42 8c          lw                  C0table,0x18(C0table)
      80068058 98 80 5a 27          addiu               src,src,-0x7f68
      8006805c d0 80 7b 27          addiu               k1,k1,-0x7f30

                         LAB_80068060                              XREF[1]:   8006806c(j)
      80068060 00 00 43 8f          lw                  val,0x0(src)=>new_eh_start
      80068064 04 00 5a 27          addiu               src,src,0x4
      80068068 04 00 42 24          addiu               dst,dst,0x4
      8006806c fc ff 5b 17          bne                 src,k1,LAB_80068060
      80068070 fc ff 43 ac          _sw                 val,-0x4(dst)
      80068074 34 a0 01 0c          jal                 FlushCache                                 undefined FlushCache()
      80068078 00 00 00 00          _nop
      8006807c b8 74 01 0c          jal                 ExitCriticalSection                        undefined ExitCriticalSectio
      80068080 00 00 00 00          _nop
      80068084 09 80 1f 3c          lui                 ra,0x8009
      80068088 04 d3 ff 8f          lw                  ra,-0x2cfc(ra)=>DAT_8008d304
      8006808c 00 00 00 00          nop
      80068090 08 00 e0 03          jr                  ra
      80068094 00 00 00 00          _nop

                         new_eh_start                              XREF[1]:   _patch_gte:80068060(R)
      80068098 00 00 00 00          nop

                         LAB_8006809c                              XREF[1]:   _patch_gte:80068060(R)
      8006809c 00 00 00 00          nop
      800680a0 00 01 1a 24          li                  k0,0x100
      800680a4 08 00 5a 8f          lw                  k0,offset DAT_00000108(k0)
      800680a8 00 00 00 00          nop
      800680ac 00 00 5a 8f          lw                  k0,0x0(k0)
      800680b0 00 00 00 00          nop
      800680b4 08 00 5a 23          addi                k0,k0,0x8
      800680b8 04 00 41 af          sw                  at,0x4(k0)
      800680bc 08 00 42 af          sw                  v0,0x8(k0)
      800680c0 0c 00 43 af          sw                  v1,0xc(k0)
      800680c4 7c 00 5f af          sw                  ra,0x7c(k0)
      800680c8 00 68 02 40          mfc0                v0,Cause
      800680cc 00 00 00 00          nop



    This patch fixes older versions of the exception handler, which didn't
    take GTE instructions into account properly. Our exception handler is
    correct, so no patch nor behavior change is necessary. Let the patch through.

 */

// clang-format on

#ifndef GENERATE_HASHES

enum patch_behavior patch_gte_3_execute(uint32_t* ra) { return PATCH_PASSTHROUGH; }

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    1, 1, 0, 1,  // 00
    1, 0, 0, 0,  // 10
    0, 0, 2, 0,  // 20
    2, 0, 1, 1,  // 30
};

static const uint8_t bytes[] = {
    0x00, 0x00, 0x1a, 0x3c, 0x00, 0x80, 0x1b, 0x3c, 0x18, 0x00, 0x42, 0x8c, 0x00, 0x80, 0x5a, 0x27,  // 00
    0xd0, 0x00, 0x7b, 0x27, 0x00, 0x00, 0x43, 0x8f, 0x04, 0x00, 0x5a, 0x27, 0x04, 0x00, 0x42, 0x24,  // 10
    0xfc, 0xff, 0x5b, 0x17, 0xfc, 0xff, 0x43, 0xac, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,  // 20
    0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x3c, 0x00, 0x00, 0xff, 0x8f,  // 30
};

uint32_t generate_hash_patch_gte_3(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t *)bytes, (uint8_t *)&mask, len);
}

uint32_t generate_mask_patch_gte_3() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
