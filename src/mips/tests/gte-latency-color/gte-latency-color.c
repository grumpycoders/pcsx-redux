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

// GTE input-register latency probe - color family.
// Covers CC (11 cycles) and CDP (13 cycles).

#include "gte-latency-common.h"

// clang-format off

#ifndef GTE_LATENCY_COLOR_HELPERS_DEFINED
#define GTE_LATENCY_COLOR_HELPERS_DEFINED

// CC and CDP read: LCM, BK, IR1/2/3, RGBC. CDP additionally reads FC, IR0.
static inline void scene_setup(void) {
    // LCM = identity diagonal
    cop2_putc(16, 0x00001000);
    cop2_putc(17, 0x00000000);
    cop2_putc(18, 0x00001000);
    cop2_putc(19, 0x00000000);
    cop2_putc(20, 0x1000);

    cop2_putc(13, 0); cop2_putc(14, 0); cop2_putc(15, 0);   // BK
    cop2_putc(21, 0x1000); cop2_putc(22, 0x1000); cop2_putc(23, 0x1000);  // FC

    cop2_put(6,  0x00808080);   // RGBC
    cop2_put(8,  0x0800);       // IR0
    cop2_put(9,  0x0500);       // IR1
    cop2_put(10, 0x0600);       // IR2
    cop2_put(11, 0x0700);       // IR3

    // FIFOs cleared.
    cop2_put(12, 0); cop2_put(13, 0); cop2_put(14, 0);
    cop2_put(16, 0); cop2_put(17, 0); cop2_put(18, 0); cop2_put(19, 0);
    cop2_put(20, 0); cop2_put(21, 0); cop2_put(22, 0);
    cop2_put(24, 0); cop2_put(25, 0); cop2_put(26, 0); cop2_put(27, 0);

    cop2_putc(31, 0);
}

#define OP_CC_SF1_LM1   COP2_CC(1, 1)
#define OP_CDP_SF1_LM1  COP2_CDP(1, 1)

#define CANARY_RGBC 0x00404040u
#define CANARY_IR0  0x0400u
#define CANARY_IR   0x0123u
#define CANARY_LMAT 0x07ff07ffu
#define CANARY_BK   0x00010000u
#define CANARY_FC   0x00010000u

#endif // GTE_LATENCY_COLOR_HELPERS_DEFINED

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
// CC (Color Color): tints RGBC by lit color (LCM*IR + BK -> mult by RGB).
// 11 cycles. Reads LCM, BK, IR1/2/3, RGBC.
// ==========================================================================
MAKE_DATA_TEST(cc_rgbc, scene_setup, OP_CC_SF1_LM1,  6, CANARY_RGBC, "CC RGBC")
MAKE_DATA_TEST(cc_ir1,  scene_setup, OP_CC_SF1_LM1,  9, CANARY_IR,   "CC IR1")
MAKE_DATA_TEST(cc_ir2,  scene_setup, OP_CC_SF1_LM1, 10, CANARY_IR,   "CC IR2")
MAKE_DATA_TEST(cc_ir3,  scene_setup, OP_CC_SF1_LM1, 11, CANARY_IR,   "CC IR3")
MAKE_CTRL_TEST(cc_lr1lr2, scene_setup, OP_CC_SF1_LM1, 16, CANARY_LMAT, "CC LR1LR2")
MAKE_CTRL_TEST(cc_lr3lg1, scene_setup, OP_CC_SF1_LM1, 17, CANARY_LMAT, "CC LR3LG1")
MAKE_CTRL_TEST(cc_lg2lg3, scene_setup, OP_CC_SF1_LM1, 18, CANARY_LMAT, "CC LG2LG3")
MAKE_CTRL_TEST(cc_lb1lb2, scene_setup, OP_CC_SF1_LM1, 19, CANARY_LMAT, "CC LB1LB2")
MAKE_CTRL_TEST(cc_lb3,    scene_setup, OP_CC_SF1_LM1, 20, CANARY_LMAT, "CC LB3")
MAKE_CTRL_TEST(cc_rbk, scene_setup, OP_CC_SF1_LM1, 13, CANARY_BK, "CC RBK")
MAKE_CTRL_TEST(cc_gbk, scene_setup, OP_CC_SF1_LM1, 14, CANARY_BK, "CC GBK")
MAKE_CTRL_TEST(cc_bbk, scene_setup, OP_CC_SF1_LM1, 15, CANARY_BK, "CC BBK")

// ==========================================================================
// CDP (Color Depth-cue Pass): CC's color stage + depth-cue toward FC.
// 13 cycles. Reads LCM, BK, IR0/1/2/3, RGBC, FC.
// ==========================================================================
MAKE_DATA_TEST(cdp_rgbc, scene_setup, OP_CDP_SF1_LM1,  6, CANARY_RGBC, "CDP RGBC")
MAKE_DATA_TEST(cdp_ir0,  scene_setup, OP_CDP_SF1_LM1,  8, CANARY_IR0,  "CDP IR0")
MAKE_DATA_TEST(cdp_ir1,  scene_setup, OP_CDP_SF1_LM1,  9, CANARY_IR,   "CDP IR1")
MAKE_DATA_TEST(cdp_ir2,  scene_setup, OP_CDP_SF1_LM1, 10, CANARY_IR,   "CDP IR2")
MAKE_DATA_TEST(cdp_ir3,  scene_setup, OP_CDP_SF1_LM1, 11, CANARY_IR,   "CDP IR3")
MAKE_CTRL_TEST(cdp_lr1lr2, scene_setup, OP_CDP_SF1_LM1, 16, CANARY_LMAT, "CDP LR1LR2")
MAKE_CTRL_TEST(cdp_lr3lg1, scene_setup, OP_CDP_SF1_LM1, 17, CANARY_LMAT, "CDP LR3LG1")
MAKE_CTRL_TEST(cdp_lg2lg3, scene_setup, OP_CDP_SF1_LM1, 18, CANARY_LMAT, "CDP LG2LG3")
MAKE_CTRL_TEST(cdp_lb1lb2, scene_setup, OP_CDP_SF1_LM1, 19, CANARY_LMAT, "CDP LB1LB2")
MAKE_CTRL_TEST(cdp_lb3,    scene_setup, OP_CDP_SF1_LM1, 20, CANARY_LMAT, "CDP LB3")
MAKE_CTRL_TEST(cdp_rbk, scene_setup, OP_CDP_SF1_LM1, 13, CANARY_BK, "CDP RBK")
MAKE_CTRL_TEST(cdp_gbk, scene_setup, OP_CDP_SF1_LM1, 14, CANARY_BK, "CDP GBK")
MAKE_CTRL_TEST(cdp_bbk, scene_setup, OP_CDP_SF1_LM1, 15, CANARY_BK, "CDP BBK")
MAKE_CTRL_TEST(cdp_rfc, scene_setup, OP_CDP_SF1_LM1, 21, CANARY_FC, "CDP RFC")
MAKE_CTRL_TEST(cdp_gfc, scene_setup, OP_CDP_SF1_LM1, 22, CANARY_FC, "CDP GFC")
MAKE_CTRL_TEST(cdp_bfc, scene_setup, OP_CDP_SF1_LM1, 23, CANARY_FC, "CDP BFC")
