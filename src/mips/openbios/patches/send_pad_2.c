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

                         *******************************************************
                         *                      FUNCTION                       *
                         *******************************************************
                         undefined _send_pad()
                            assume gp = 0x0
           undefined       v0:1         <RETURN>                           XREF[1]:   80040bb8(W)
           dword * *       v0:4         B0table                            XREF[1]:   80040bb8(W)
           undefined4      t2:4         src                                XREF[1]:   80040bd4(W)
           undefined4      v0:4         dst
           undefined4      v1:4         val                                XREF[1]:   80040be0(W)
                         _send_pad                                 XREF[2]:   FUN_8004078c:800407f4(c),
                                                                               FUN_80040828:80040890(c)
      80040ba4 06 80 01 3c          lui                 at,0x8006
           assume gp = <UNKNOWN>
      80040ba8 b4 93 3f ac          sw                  ra,-0x6c4c(at)=>DAT_800593b4
      80040bac 35 01 01 0c          jal                 EnterCriticalSection                       undefined EnterCriticalSecti
      80040bb0 00 00 00 00          _nop
      80040bb4 b0 00 0a 24          li                  t2,0xb0
      80040bb8 09 f8 40 01          jalr                t2=>SUB_000000b0
      80040bbc 57 00 09 24          _li                 t1,0x57
      80040bc0 6c 01 42 8c          lw                  B0table,0x16c(B0table)
      80040bc4 04 80 0a 3c          lui                 t2,0x8004
      80040bc8 04 80 09 3c          lui                 t1,0x8004
      80040bcc 06 80 01 3c          lui                 at,0x8006
      80040bd0 a0 07 43 20          addi                v1,B0table,0x7a0
      80040bd4 20 0c 4a 25          addiu               src,src,0xc20
      80040bd8 30 0c 29 25          addiu               t1,t1,0xc30
      80040bdc b8 93 23 ac          sw                  v1,-0x6c48(at)=>captured_setPadOutputData

                         LAB_80040be0                              XREF[1]:   80040bf0(j)
      80040be0 00 00 43 8d          lw                  val,0x0(src)=>_send_pad_patch_start
      80040be4 04 00 4a 25          addiu               src,src,0x4
      80040be8 d8 03 43 ac          sw                  val,0x3d8(dst)
      80040bec 04 00 42 24          addiu               dst,dst,0x4
      80040bf0 fb ff 49 15          bne                 src,t1,LAB_80040be0
      80040bf4 dc 04 43 ac          _sw                 val,0x4dc(dst)
      80040bf8 15 01 01 0c          jal                 FlushCache                                 undefined FlushCache()
      80040bfc 00 00 00 00          _nop
      80040c00 39 01 01 0c          jal                 ExitCriticalSection                        undefined ExitCriticalSectio
      80040c04 00 00 00 00          _nop
      80040c08 06 80 1f 3c          lui                 ra,0x8006
      80040c0c b4 93 ff 8f          lw                  ra,-0x6c4c(ra)=>DAT_800593b4
      80040c10 06 80 02 3c          lui                 dst,0x8006
      80040c14 b8 93 42 8c          lw                  dst,-0x6c48(dst)=>captured_setPadOutputDa
      80040c18 08 00 e0 03          jr                  ra
      80040c1c 00 00 00 00          _nop

                         _send_pad_patch_start                     XREF[1]:   _send_pad:80040be0(R)
      80040c20 24 10 55 00          and                 v0,v0,s5

                         LAB_80040c24                              XREF[1]:   _send_pad:80040be0(R)
      80040c24 00 00 00 00          nop
      80040c28 00 00 00 00          nop
      80040c2c 00 00 00 00          nop

                         _send_patch_patch_end
      80040c30 00 00 00 00          nop
      80040c34 00 00 00 00          nop
      80040c38 00 00 00 00          nop

    This patch changes the way we send data to the pad, and grabs a pointer to
    the function that sets the data pointers.
    We toggle a boolean for this instead if we detect this patch, and we
    inject the current function for it in the pointers.

    See sio0/driver.c for more details.

 */

// clang-format on

#ifndef GENERATE_HASHES

int send_pad_2_execute(uint32_t* ra) {
    patch_send_pad();
    uint32_t ptr;
    int16_t addend;

    ptr = ra[3] & 0xffff;
    ptr <<= 16;
    addend = ra[7] & 0xffff;
    ptr += addend;
    *((uint32_t*)ptr) = patch_setPadOutputData;

    ra[2] = 12 | 0x10000000;
    ra[3] = 0;

    return 1;
}

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    0, 1, 1, 1,  // 00
    0, 0, 0, 1,  // 10
    0, 0, 0, 0,  // 20
    0, 0, 2, 0,  // 30
};

static const uint8_t bytes[] = {
    0x6c, 0x01, 0x42, 0x8c, 0x00, 0x00, 0x0a, 0x3c, 0x00, 0x00, 0x09, 0x3c, 0x00, 0x00, 0x01, 0x3c,  // 00
    0xa0, 0x07, 0x43, 0x20, 0x20, 0x0c, 0x4a, 0x25, 0x30, 0x0c, 0x29, 0x25, 0x00, 0x00, 0x23, 0xac,  // 10
    0x00, 0x00, 0x43, 0x8d, 0x04, 0x00, 0x4a, 0x25, 0xd8, 0x03, 0x43, 0xac, 0x04, 0x00, 0x42, 0x24,  // 20
    0xfb, 0xff, 0x49, 0x15, 0xdc, 0x04, 0x43, 0xac, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,  // 30
};

uint32_t generate_hash_send_pad_2(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t *)bytes, (uint8_t *)&mask, len);
}

uint32_t generate_mask_send_pad_2() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
