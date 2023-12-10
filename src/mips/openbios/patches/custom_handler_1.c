/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

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
#include "openbios/sio0/pad.h"

// clang-format off

/* Found in Point Blank USA:

                             *************************************************************
                             *                           FUNCTION
                             *************************************************************
                             undefined  installCustomHandler ()
                               assume gp = 0x8009c180
             undefined         v0:1           <RETURN>                                XREF[2]:     800606d4 (W) ,
                                                                                                   800606f0 (W)
             dword *           v0:4           c0table                                 XREF[2]:     800606d4 (W) ,
                                                                                                   800606f0 (W)
             dword *           v0:4           exceptionHandlerPtr                     XREF[1]:     800606f0 (W)
                             installCustomHandler                            XREF[1]:     FUN_800601bc:800602ac (c)
        800606b4 0a  80  01  3c    lui        at,0x800a
        800606b8 ac  c3  3f  ac    sw         ra,-0x3c54 (at)=>DAT_8009c3ac
        800606bc 0a  80  01  3c    lui        at,0x800a
        800606c0 a8  c3  24  ac    sw         a0,-0x3c58 (at)=>DAT_8009c3a8
        800606c4 0a  80  01  3c    lui        at,0x800a
        800606c8 49  7c  01  0c    jal        FUN_8005f124                                     undefined FUN_8005f124()
        800606cc b0  c3  25  ac    _sw        a1,-0x3c50 (at)=>DAT_8009c3b0
        800606d0 b0  00  0a  24    li         t2,0xb0
        800606d4 09  f8  40  01    jalr       t2=>SUB_000000b0
        800606d8 56  00  09  24    _li        t1,0x56
        800606dc 06  80  0a  3c    lui        t2,0x8006
        800606e0 06  80  09  3c    lui        t1,0x8006
        800606e4 18  00  42  8c    lw         c0table ,0x18 (c0table )
        800606e8 3c  08  4a  25    addiu      t2,t2,0x83c
        800606ec 4c  08  29  25    addiu      t1,t1,0x84c
                             LAB_800606f0                                    XREF[1]:     800606fc (j)
        800606f0 00  00  43  8d    lw         v1,0x0 (t2)=>LAB_8006083c
        800606f4 04  00  4a  25    addiu      t2,t2,0x4
        800606f8 04  00  42  24    addiu      exceptionHandlerPtr ,exceptionHandlerPtr ,0x4
        800606fc fc  ff  49  15    bne        t2,t1,LAB_800606f0
        80060700 7c  00  43  ac    _sw        v1,0x7c (exceptionHandlerPtr )
        80060704 06  80  02  3c    lui        exceptionHandlerPtr ,0x8006
        80060708 dc  09  42  24    addiu      exceptionHandlerPtr ,exceptionHandlerPtr ,0x9dc
        8006070c 00  00  4a  8c    lw         t2,0x0 (exceptionHandlerPtr )=>DAT_800609dc
        80060710 00  00  00  00    nop
        80060714 12  00  40  15    bne        t2,zero ,LAB_80060760
        80060718 00  00  00  00    _nop
        8006071c 80  00  0a  24    li         t2,0x80
        80060720 90  00  09  24    li         t1,0x90
                             LAB_80060724                                    XREF[1]:     80060730 (j)
        80060724 00  00  43  8d    lw         v1,0x0 (t2)=>DAT_00000080
        80060728 04  00  4a  25    addiu      t2,t2,0x4
        8006072c 04  00  42  24    addiu      exceptionHandlerPtr ,exceptionHandlerPtr ,0x4
        80060730 fc  ff  49  15    bne        t2,t1,LAB_80060724
        80060734 fc  ff  43  ac    _sw        v1,-0x4 (exceptionHandlerPtr )=>DAT_800609dc
        80060738 06  80  0a  3c    lui        t2,0x8006
        8006073c 06  80  09  3c    lui        t1,0x8006
        80060740 80  00  02  24    li         exceptionHandlerPtr ,0x80
        80060744 a0  09  4a  25    addiu      t2,t2,0x9a0
        80060748 b0  09  29  25    addiu      t1,t1,0x9b0
                             LAB_8006074c                                    XREF[1]:     80060758 (j)
        8006074c 00  00  43  8d    lw         v1,0x0 (t2)=>LAB_800609a0
        80060750 04  00  4a  25    addiu      t2,t2,0x4
        80060754 04  00  42  24    addiu      exceptionHandlerPtr ,exceptionHandlerPtr ,0x4
        80060758 fc  ff  49  15    bne        t2,t1,LAB_8006074c
        8006075c fc  ff  43  ac    _sw        v1,-0x4 (exceptionHandlerPtr )=>DAT_00000080
                             LAB_80060760                                    XREF[1]:     80060714 (j)
        80060760 11  7c  01  0c    jal        FlushCache                                       void FlushCache(void)
        80060764 00  00  00  00    _nop
        80060768 0a  80  1f  3c    lui        ra,0x800a
        8006076c ac  c3  ff  8f    lw         ra,-0x3c54 (ra)=>DAT_8009c3ac
        80060770 00  00  00  00    nop
        80060774 08  00  e0  03    jr         ra
        80060778 00  00  00  00    _nop

    This patch is very much custom, and doesn't seem to be coming from the Psy-Q SDK
    like the other patches. It's injecting two custom exception handlers into the kernel,
    once at the beginning of the exception handler itself, and one straight into
    0x80000080, which is probably the only time this has ever been done.

    Luckily, we can simply "do nothing" when encountering this patch, as the exception
    handler will play nice with this patch.
 */

// clang-format on

#ifndef GENERATE_HASHES

enum patch_behavior custom_handler_1_execute(uint32_t* ra) { return PATCH_PASSTHROUGH; }

#else

#include "openbios/patches/hash.h"

static const uint8_t masks[] = {
    1, 1, 0, 1,  // 00
    1, 0, 0, 0,  // 10
    0, 0, 1, 1,  // 20
    0, 0, 0, 0,  // 30
};

static const uint8_t bytes[] = {
    0x06, 0x80, 0x0a, 0x3c, 0x06, 0x80, 0x09, 0x3c, 0x18, 0x00, 0x42, 0x8c, 0x3c, 0x08, 0x4a, 0x25,  // 00
    0x4c, 0x08, 0x29, 0x25, 0x00, 0x00, 0x43, 0x8d, 0x04, 0x00, 0x4a, 0x25, 0x04, 0x00, 0x42, 0x24,  // 10
    0xfc, 0xff, 0x49, 0x15, 0x7c, 0x00, 0x43, 0xac, 0x06, 0x80, 0x02, 0x3c, 0xdc, 0x09, 0x42, 0x24,  // 20
    0x00, 0x00, 0x4a, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x40, 0x15, 0x00, 0x00, 0x00, 0x00,  // 30
};

uint32_t generate_hash_custom_handler_1(uint32_t mask, unsigned len) {
    return patch_hash((const uint32_t *)bytes, (uint8_t *)&mask, len);
}

uint32_t generate_mask_custom_handler_1() {
    uint32_t mask = 0;

    for (unsigned i = 0; i < 16; i++) {
        mask <<= 2;
        mask |= masks[15 - i];
    }

    return mask;
}
#endif
