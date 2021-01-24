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

/* Found in Suikoden 2 NTSC (SLUS-00958):

                    *************************************************************
                    *                           FUNCTION
                    *************************************************************
                             void  _send_pad (void)
                               assume gp = 0x80109798
             void              <VOID>         <RETURN>
             dword * *         v0:4           B0table                                 XREF[1]:     800e3280 (W)
             undefined4        t2:4           src                                     XREF[1]:     800e328c (W)
             undefined4        v0:4           ptr                                     XREF[1]:     800e3298 (W)
             undefined4        v1:4           data                                    XREF[1]:     800e32ac (W)
                             _send_pad                                       XREF[2]:     PAD_init:800e2eb0 (c),
                                                                                          InitPAD:800e2f48 (c)
        800e3268 11 80 01 3c          lui             at,0x8011
             assume gp = <UNKNOWN>
        800e326c 90 9b 3f ac          sw              ra,-0x6470 (at)=>DAT_80109b90                    = ??
        800e3270 6f 52 03 0c          jal             EnterCriticalSection                             int
   EnterCriticalSection(void) 800e3274 00 00 00 00          _nop 800e3278 57 00 09 24          li              t1,0x57
        800e327c b0 00 0a 24          li              t2,0xb0
        800e3280 09 f8 40 01          jalr            t2=>SUB_000000b0
        800e3284 00 00 00 00          _nop
        800e3288 0e 80 0a 3c          lui             t2,0x800e
        800e328c f4 32 4a 25          addiu           src,src,0x32f4
        800e3290 0e 80 09 3c          lui             t1,0x800e
        800e3294 04 33 29 25          addiu           t1,t1,0x3304
        800e3298 6c 01 42 8c          lw              ptr,0x16c (ptr)
        800e329c 00 00 00 00          nop
        800e32a0 a0 07 43 20          addi            v1,ptr,0x7a0
        800e32a4 11 80 01 3c          lui             at,0x8011
        800e32a8 94 9b 23 ac          sw              v1,-0x646c (at)=>captured_setPadOutputData       = ??

                             LAB_800e32ac                                    XREF[1]:     800e32c4 (j)
        800e32ac 00 00 43 8d          lw              data,0x0(src)=>_send_pad_patch_start
        800e32b0 00 00 00 00          nop
        800e32b4 d8 03 43 ac          sw              data,0x3d8 (ptr)
        800e32b8 e0 04 43 ac          sw              data,0x4e0 (ptr)
        800e32bc 04 00 42 24          addiu           ptr,ptr,0x4
        800e32c0 04 00 4a 25          addiu           src,src,0x4
        800e32c4 f9 ff 49 15          bne             src,t1,LAB_800e32ac
        800e32c8 00 00 00 00          _nop
        800e32cc 53 7d 03 0c          jal             FlushCache                                       void
   FlushCache(void) 800e32d0 00 00 00 00          _nop 800e32d4 73 52 03 0c          jal             ExitCriticalSection
   void ExitCriticalSection(void) 800e32d8 00 00 00 00          _nop 800e32dc 11 80 1f 3c          lui ra,0x8011
        800e32e0 90 9b ff 8f          lw              ra,-0x6470 (ra)=>DAT_80109b90                    = ??
        800e32e4 11 80 02 3c          lui             ptr,0x8011
        800e32e8 94 9b 42 8c          lw              ptr,-0x646c (ptr)=>captured_setPadOutputData     = ??
        800e32ec 08 00 e0 03          jr              ra
        800e32f0 00 00 00 00          _nop
                             _send_pad_patch_start                           XREF[1]:     _send_pad:800e32ac (R)
        800e32f4 24 10 55 00          and             v0,v0,s5

                             LAB_800e32f8                                    XREF[1]:     _send_pad:800e32ac (R)
        800e32f8 00 00 00 00          nop
        800e32fc 00 00 00 00          nop
        800e3300 00 00 00 00          nop
                             _send_pad_patch_end
        800e3304 00 00 00 00          nop
        800e3308 00 00 00 00          nop

    This patch changes the way we send data to the pad, and grabs a pointer to
    the function that sets the data pointers.
    We toggle a boolean for this instead if we detect this patch, and we
    inject the current function for it in the pointers.

    See sio0/driver.c for more details.

 */

#ifndef GENERATE_HASHES

int send_pad_1_execute(uint32_t* ra) {
    patch_send_pad();
    uint32_t ptr;
    int16_t addend;

    ptr = ra[7] & 0xffff;
    ptr <<= 16;
    addend = ra[8] & 0xffff;
    ptr += addend;
    *((uint32_t*)ptr) = patch_setPadOutputData;

    ra[2] = 15 | 0x10000000;
    ra[3] = 0;

    return 1;
}

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    1, 1, 1, 1,  // 00
    0, 0, 0, 1,  // 10
    1, 0, 0, 0,  // 20
    0, 0, 0, 0,  // 30
};

static const uint8_t bytes[] = {
    0x00, 0x00, 0x0a, 0x3c, 0x00, 0x00, 0x4a, 0x25, 0x00, 0x00, 0x09, 0x3c, 0x00, 0x00, 0x29, 0x25,  // 00
    0x6c, 0x01, 0x42, 0x8c, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x07, 0x43, 0x20, 0x00, 0x00, 0x01, 0x3c,  // 10
    0x00, 0x00, 0x23, 0xac, 0x00, 0x00, 0x43, 0x8d, 0x00, 0x00, 0x00, 0x00, 0xd8, 0x03, 0x43, 0xac,  // 20
    0xe0, 0x04, 0x43, 0xac, 0x04, 0x00, 0x42, 0x24, 0x04, 0x00, 0x4a, 0x25, 0xf9, 0xff, 0x49, 0x15,  // 30
};

uint32_t generate_hash_send_pad_1(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t *)bytes, (uint8_t *)&mask, len);
}

uint32_t generate_mask_send_pad_1() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
