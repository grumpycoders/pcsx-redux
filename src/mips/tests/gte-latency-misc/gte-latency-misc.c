/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

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

// GTE input-register latency probe - misc family.
// Covers AVSZ3 (5 cycles), AVSZ4 (6 cycles), GPF (5 cycles), GPL (5 cycles).

#include "gte-latency-common.h"

// clang-format off

#ifndef GTE_LATENCY_MISC_HELPERS_DEFINED
#define GTE_LATENCY_MISC_HELPERS_DEFINED

// AVSZ3/AVSZ4: average of SZ FIFO entries weighted by ZSF3/ZSF4.
// GPF/GPL: blend MAC1/2/3 (or zero) with IR1/2/3 weighted by IR0.
static inline void scene_setup(void) {
    cop2_putc(29, 0x0400);   // ZSF3 = 0x400 (1/4 in 1.12)
    cop2_putc(30, 0x0400);   // ZSF4

    // SZ FIFO (4-deep). AVSZ3 sums SZ1+SZ2+SZ3, AVSZ4 sums SZ0+SZ1+SZ2+SZ3.
    cop2_put(16, 100);   // SZ0
    cop2_put(17, 200);   // SZ1
    cop2_put(18, 300);   // SZ2
    cop2_put(19, 400);   // SZ3

    // For GPF/GPL: IR0 + IR1/2/3, MAC1/2/3 (read by GPL).
    cop2_put(8,  0x0800);   // IR0 = 0.5
    cop2_put(9,  0x0500);   // IR1
    cop2_put(10, 0x0600);   // IR2
    cop2_put(11, 0x0700);   // IR3
    cop2_put(25, 0x4000);   // MAC1
    cop2_put(26, 0x5000);   // MAC2
    cop2_put(27, 0x6000);   // MAC3
    cop2_put(24, 0);        // MAC0

    // FIFOs cleared (RGB unused, SXY unused).
    cop2_put(20, 0); cop2_put(21, 0); cop2_put(22, 0);
    cop2_put(12, 0); cop2_put(13, 0); cop2_put(14, 0);
    cop2_put(6, 0x00808080);  // RGBC

    cop2_putc(31, 0);
}

#define OP_AVSZ3        COP2_AVSZ3
#define OP_AVSZ4        COP2_AVSZ4
#define OP_GPF_SF1_LM1  COP2_GPF(1, 1)
#define OP_GPL_SF1_LM1  COP2_GPL(1, 1)

#define CANARY_SZ    0x0fffu
#define CANARY_ZSF   0x0123u
#define CANARY_IR0   0x0400u
#define CANARY_IR    0x0123u
#define CANARY_MAC   0x12345678u

#endif // GTE_LATENCY_MISC_HELPERS_DEFINED

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

CESTER_BEFORE_ALL(gte_latency_tests,
    gte_enable();
)

// ==========================================================================
// AVSZ3 (Average of 3 Z values): MAC0 = ZSF3 * (SZ1+SZ2+SZ3). 5 cycles.
// ==========================================================================
MAKE_DATA_TEST(avsz3_sz1, scene_setup, OP_AVSZ3, 17, CANARY_SZ,  "AVSZ3 SZ1")
MAKE_DATA_TEST(avsz3_sz2, scene_setup, OP_AVSZ3, 18, CANARY_SZ,  "AVSZ3 SZ2")
MAKE_DATA_TEST(avsz3_sz3, scene_setup, OP_AVSZ3, 19, CANARY_SZ,  "AVSZ3 SZ3")
MAKE_CTRL_TEST(avsz3_zsf3, scene_setup, OP_AVSZ3, 29, CANARY_ZSF, "AVSZ3 ZSF3")

// ==========================================================================
// AVSZ4: MAC0 = ZSF4 * (SZ0+SZ1+SZ2+SZ3). 6 cycles.
// ==========================================================================
MAKE_DATA_TEST(avsz4_sz0, scene_setup, OP_AVSZ4, 16, CANARY_SZ,  "AVSZ4 SZ0")
MAKE_DATA_TEST(avsz4_sz1, scene_setup, OP_AVSZ4, 17, CANARY_SZ,  "AVSZ4 SZ1")
MAKE_DATA_TEST(avsz4_sz2, scene_setup, OP_AVSZ4, 18, CANARY_SZ,  "AVSZ4 SZ2")
MAKE_DATA_TEST(avsz4_sz3, scene_setup, OP_AVSZ4, 19, CANARY_SZ,  "AVSZ4 SZ3")
MAKE_CTRL_TEST(avsz4_zsf4, scene_setup, OP_AVSZ4, 30, CANARY_ZSF, "AVSZ4 ZSF4")

// ==========================================================================
// GPF (General Purpose Full): MAC = IR0 * IR. 5 cycles.
// ==========================================================================
MAKE_DATA_TEST(gpf_ir0, scene_setup, OP_GPF_SF1_LM1,  8, CANARY_IR0, "GPF IR0")
MAKE_DATA_TEST(gpf_ir1, scene_setup, OP_GPF_SF1_LM1,  9, CANARY_IR,  "GPF IR1")
MAKE_DATA_TEST(gpf_ir2, scene_setup, OP_GPF_SF1_LM1, 10, CANARY_IR,  "GPF IR2")
MAKE_DATA_TEST(gpf_ir3, scene_setup, OP_GPF_SF1_LM1, 11, CANARY_IR,  "GPF IR3")

// ==========================================================================
// GPL (General Purpose Long): MAC += IR0 * IR. 5 cycles.
// Reads MAC1/2/3 in addition to IR.
// ==========================================================================
MAKE_DATA_TEST(gpl_ir0, scene_setup, OP_GPL_SF1_LM1,  8, CANARY_IR0, "GPL IR0")
MAKE_DATA_TEST(gpl_ir1, scene_setup, OP_GPL_SF1_LM1,  9, CANARY_IR,  "GPL IR1")
MAKE_DATA_TEST(gpl_ir2, scene_setup, OP_GPL_SF1_LM1, 10, CANARY_IR,  "GPL IR2")
MAKE_DATA_TEST(gpl_ir3, scene_setup, OP_GPL_SF1_LM1, 11, CANARY_IR,  "GPL IR3")
MAKE_DATA_TEST(gpl_mac1, scene_setup, OP_GPL_SF1_LM1, 25, CANARY_MAC, "GPL MAC1")
MAKE_DATA_TEST(gpl_mac2, scene_setup, OP_GPL_SF1_LM1, 26, CANARY_MAC, "GPL MAC2")
MAKE_DATA_TEST(gpl_mac3, scene_setup, OP_GPL_SF1_LM1, 27, CANARY_MAC, "GPL MAC3")
