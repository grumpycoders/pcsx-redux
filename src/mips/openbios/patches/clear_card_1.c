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

/* Found in Cool Boarders 3 (SCUS-94251): (loaded from overlay)

                    //
                    // OVR1
                    // OVR1::800b2910-OVR1::800b2fd8
                    //
                    *************************************************************
                    *                           FUNCTION
                    *************************************************************
                             undefined  FUN_OVR1__800b2910 ()
             undefined         v0:1           <RETURN>                                XREF[2]:     OVR1::800b2928 (W
                                                                                                   OVR1::800b2930 (W
             dword * *         v0:4           C0table                                 XREF[1]:     OVR1::800b2928 (W
             undefined4        v0:4           dst                                     XREF[1]:     OVR1::800b2930 (W
             undefined4        t2:4           src                                     XREF[1]:     OVR1::800b2938 (W
                             FUN_OVR1__800b2910
     1::800b2910 0c 80 01 3c          lui             at,0x800c
     1::800b2914 c0 0f 3f ac          sw              ra,offset  DAT_800c0fc0 (at)                      = ??
     1::800b2918 f0 40 01 0c          jal             EnterCriticalSection                             undefined EnterCriticalSection()
     1::800b291c 00 00 00 00          _nop
     1::800b2920 56 00 09 24          li              t1,0x56
     1::800b2924 b0 00 0a 24          li              t2,0xb0
     1::800b2928 09 f8 40 01          jalr            t2=>SUB_000000b0
     1::800b292c 00 00 00 00          _nop
     1::800b2930 18 00 42 8c          lw              dst,0x18(dst)
     1::800b2934 0b 80 0a 3c          lui             t2,0x800b
     1::800b2938 80 29 4a 25          addiu           src,src,0x2980
     1::800b293c 0b 80 09 3c          lui             t1,0x800b
     1::800b2940 8c 29 29 25          addiu           t1,t1,0x298c
                             LAB_OVR1__800b2944                              XREF[1]:     OVR1::800b2954 (j)
     1::800b2944 00 00 43 8d          lw              v1,0x0(src)=>LAB_OVR1__800b2980
     1::800b2948 00 00 00 00          nop
     1::800b294c 70 00 43 ac          sw              v1,0x70(dst)
     1::800b2950 04 00 4a 25          addiu           src,src,0x4
     1::800b2954 fb ff 49 15          bne             src,t1,LAB_OVR1__800b2944
     1::800b2958 04 00 42 24          _addiu          dst,dst,0x4
     1::800b295c c0 59 01 0c          jal             FlushCache                                       void FlushCache(void)
     1::800b2960 00 00 00 00          _nop
     1::800b2964 f4 40 01 0c          jal             ExitCriticalSection                              undefined ExitCriticalSection()
     1::800b2968 00 00 00 00          _nop
     1::800b296c 0c 80 1f 3c          lui             ra,0x800c
     1::800b2970 c0 0f ff 8f          lw              ra,offset  DAT_800c0fc0 (ra)                      = ??
     1::800b2974 00 00 00 00          nop
     1::800b2978 08 00 e0 03          jr              ra
     1::800b297c 00 00 00 00          _nop
                             LAB_OVR1__800b2980                              XREF[1]:     FUN_OVR1__800b2910:800b2944 (R)
     1::800b2980 00 00 00 00          nop
                             LAB_OVR1__800b2984                              XREF[1]:     FUN_OVR1__800b2910:800b2944 (R)
     1::800b2984 00 00 00 00          nop
     1::800b2988 00 00 00 00          nop
     1::800b298c 00 00 00 00          nop

    This patch clears out the exception handler's memory card ISR patch.
    Since our exception handler is similar to that of the original code,
    we don't need to do anything special here.

 */

// clang-format on

#ifndef GENERATE_HASHES

enum patch_behavior clear_card_1_execute(uint32_t* ra) { return PATCH_PASSTHROUGH; }

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    0, 1, 1, 1,  // 00
    1, 0, 0, 0,  // 10
    0, 0, 0, 2,  // 20
    0, 2, 0, 1,  // 30
};

static const uint8_t bytes[] = {
    0x18, 0x00, 0x42, 0x8c, 0x00, 0x00, 0x0a, 0x3c, 0x00, 0x00, 0x4a, 0x25, 0x00, 0x00, 0x09, 0x3c,  // 00
    0x00, 0x00, 0x29, 0x25, 0x00, 0x00, 0x43, 0x8d, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x43, 0xac,  // 10
    0x04, 0x00, 0x4a, 0x25, 0xfb, 0xff, 0x49, 0x15, 0x04, 0x00, 0x42, 0x24, 0x00, 0x00, 0x00, 0x0c,  // 20
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x3c,  // 30
};

uint32_t generate_hash_clear_card_1(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t *)bytes, (uint8_t *)&mask, len);
}

uint32_t generate_mask_clear_card_1() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
