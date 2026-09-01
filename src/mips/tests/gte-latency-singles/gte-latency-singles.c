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

// GTE input-register latency probe - lighting singles family.
// Single-vertex variants of the lighting pipeline: NCS, NCCS, NCDS.
// Each operates only on V0 (no V1/V2), but goes through the full
// lighting -> color/depth-cue stages.

#include "gte-latency-common.h"

// clang-format off

#ifndef GTE_LATENCY_SINGLES_HELPERS_DEFINED
#define GTE_LATENCY_SINGLES_HELPERS_DEFINED

// Test scene shared by all the single-vertex lighting tests.
//
// V0 = (0x600, 0x800, 0xA00)   non-axis-aligned so EVERY L matrix entry
//                              contributes to the lighting result. With an
//                              axis-aligned V0, the canary on, say, L11
//                              would have no effect because L11 is always
//                              multiplied by V0_X=0 - we'd report a false
//                              "latched at N=0" boundary.
// LLM = identity diagonal
// LCM = identity diagonal
// BK = (0, 0, 0)
// FC = (0x1000, 0x1000, 0x1000)   used by NCDS
// IR0 = 0x800                     used by NCDS depth cue
// RGBC = (0x80, 0x80, 0x80, 0)   used by NCCS / NCDS color stage
static inline void scene_setup(void) {
    cop2_putc(8,  0x00001000);
    cop2_putc(9,  0x00000000);
    cop2_putc(10, 0x00001000);
    cop2_putc(11, 0x00000000);
    cop2_putc(12, 0x1000);
    cop2_putc(16, 0x00001000);
    cop2_putc(17, 0x00000000);
    cop2_putc(18, 0x00001000);
    cop2_putc(19, 0x00000000);
    cop2_putc(20, 0x1000);
    cop2_putc(13, 0); cop2_putc(14, 0); cop2_putc(15, 0);   // BK
    cop2_putc(21, 0x1000); cop2_putc(22, 0x1000); cop2_putc(23, 0x1000);   // FC
    cop2_put(0, (0x0800u << 16) | 0x0600u);  // V0: VX=0x600, VY=0x800
    cop2_put(1, 0x00000A00);                 //     VZ=0xA00
    // V1, V2 set to placeholders (NCS/NCCS/NCDS don't read them).
    cop2_put(2, 0); cop2_put(3, 0);
    cop2_put(4, 0); cop2_put(5, 0);
    cop2_put(6, 0x00808080);   // RGBC
    cop2_put(8, 0x0800);       // IR0 = 0.5
    // Clear RGB FIFO and SXY FIFO so stale entries from prior probes
    // don't end up in the comparison. Single-vertex lighting ops only
    // push one entry per call; the older slots would otherwise hold
    // garbage from earlier tests.
    cop2_put(20, 0); cop2_put(21, 0); cop2_put(22, 0);   // RGB FIFO
    cop2_put(12, 0); cop2_put(13, 0); cop2_put(14, 0);   // SXY FIFO entries
    cop2_put(16, 0); cop2_put(17, 0); cop2_put(18, 0); cop2_put(19, 0);  // SZ FIFO
    cop2_put(24, 0); cop2_put(25, 0); cop2_put(26, 0); cop2_put(27, 0);  // MAC0..3
    cop2_putc(31, 0);          // FLAG
}

#define OP_NCS_SF1_LM1   COP2_NCS(1, 1)
#define OP_NCCS_SF1_LM1  COP2_NCCS(1, 1)
#define OP_NCDS_SF1_LM1  COP2_NCDS(1, 1)

// Canaries: values different from baseline that produce visibly
// different GTE outputs. For 16/16-packed matrix entries we set BOTH
// halves so the canary perturbs both the low and high entries.
#define CANARY_VXY  0x05000400u   // VX=0x400, VY=0x500 (vs 0x600/0x800)
#define CANARY_VZ   0x00000400u   // VZ=0x400 (vs 0xA00)
#define CANARY_RGBC 0x00404040u
#define CANARY_LMAT 0x07ff07ffu   // both halves 0x7ff (off-diagonal 0 -> 0x7ff,
                                  // diagonal 0x1000 -> 0x7ff)
#define CANARY_BK   0x00010000u
#define CANARY_FC   0x00010000u

#endif // GTE_LATENCY_SINGLES_HELPERS_DEFINED

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
// NCS (Normal Color Single): lighting only, no per-vertex color tint.
// 14 cycles. Reads V0, LLM, LCM, BK.
// ==========================================================================
MAKE_DATA_TEST(ncs_vxy0, scene_setup, OP_NCS_SF1_LM1, 0, CANARY_VXY,  "NCS VXY0")
MAKE_DATA_TEST(ncs_vz0,  scene_setup, OP_NCS_SF1_LM1, 1, CANARY_VZ,   "NCS VZ0")
MAKE_CTRL_TEST(ncs_l11l12, scene_setup, OP_NCS_SF1_LM1,  8, CANARY_LMAT, "NCS L11L12")
MAKE_CTRL_TEST(ncs_l13l21, scene_setup, OP_NCS_SF1_LM1,  9, CANARY_LMAT, "NCS L13L21")
MAKE_CTRL_TEST(ncs_l22l23, scene_setup, OP_NCS_SF1_LM1, 10, CANARY_LMAT, "NCS L22L23")
MAKE_CTRL_TEST(ncs_l31l32, scene_setup, OP_NCS_SF1_LM1, 11, CANARY_LMAT, "NCS L31L32")
MAKE_CTRL_TEST(ncs_l33,    scene_setup, OP_NCS_SF1_LM1, 12, CANARY_LMAT, "NCS L33")
MAKE_CTRL_TEST(ncs_lr1lr2, scene_setup, OP_NCS_SF1_LM1, 16, CANARY_LMAT, "NCS LR1LR2")
MAKE_CTRL_TEST(ncs_lr3lg1, scene_setup, OP_NCS_SF1_LM1, 17, CANARY_LMAT, "NCS LR3LG1")
MAKE_CTRL_TEST(ncs_lg2lg3, scene_setup, OP_NCS_SF1_LM1, 18, CANARY_LMAT, "NCS LG2LG3")
MAKE_CTRL_TEST(ncs_lb1lb2, scene_setup, OP_NCS_SF1_LM1, 19, CANARY_LMAT, "NCS LB1LB2")
MAKE_CTRL_TEST(ncs_lb3,    scene_setup, OP_NCS_SF1_LM1, 20, CANARY_LMAT, "NCS LB3")
MAKE_CTRL_TEST(ncs_rbk, scene_setup, OP_NCS_SF1_LM1, 13, CANARY_BK, "NCS RBK")
MAKE_CTRL_TEST(ncs_gbk, scene_setup, OP_NCS_SF1_LM1, 14, CANARY_BK, "NCS GBK")
MAKE_CTRL_TEST(ncs_bbk, scene_setup, OP_NCS_SF1_LM1, 15, CANARY_BK, "NCS BBK")

// ==========================================================================
// NCCS (Normal Color Color Single): lighting + per-vertex RGBC tint.
// 17 cycles. Adds RGBC to NCS's input set.
// ==========================================================================
MAKE_DATA_TEST(nccs_vxy0, scene_setup, OP_NCCS_SF1_LM1, 0, CANARY_VXY,  "NCCS VXY0")
MAKE_DATA_TEST(nccs_vz0,  scene_setup, OP_NCCS_SF1_LM1, 1, CANARY_VZ,   "NCCS VZ0")
MAKE_DATA_TEST(nccs_rgbc, scene_setup, OP_NCCS_SF1_LM1, 6, CANARY_RGBC, "NCCS RGBC")
MAKE_CTRL_TEST(nccs_l11l12, scene_setup, OP_NCCS_SF1_LM1,  8, CANARY_LMAT, "NCCS L11L12")
MAKE_CTRL_TEST(nccs_l13l21, scene_setup, OP_NCCS_SF1_LM1,  9, CANARY_LMAT, "NCCS L13L21")
MAKE_CTRL_TEST(nccs_l22l23, scene_setup, OP_NCCS_SF1_LM1, 10, CANARY_LMAT, "NCCS L22L23")
MAKE_CTRL_TEST(nccs_l31l32, scene_setup, OP_NCCS_SF1_LM1, 11, CANARY_LMAT, "NCCS L31L32")
MAKE_CTRL_TEST(nccs_l33,    scene_setup, OP_NCCS_SF1_LM1, 12, CANARY_LMAT, "NCCS L33")
MAKE_CTRL_TEST(nccs_lr1lr2, scene_setup, OP_NCCS_SF1_LM1, 16, CANARY_LMAT, "NCCS LR1LR2")
MAKE_CTRL_TEST(nccs_lr3lg1, scene_setup, OP_NCCS_SF1_LM1, 17, CANARY_LMAT, "NCCS LR3LG1")
MAKE_CTRL_TEST(nccs_lg2lg3, scene_setup, OP_NCCS_SF1_LM1, 18, CANARY_LMAT, "NCCS LG2LG3")
MAKE_CTRL_TEST(nccs_lb1lb2, scene_setup, OP_NCCS_SF1_LM1, 19, CANARY_LMAT, "NCCS LB1LB2")
MAKE_CTRL_TEST(nccs_lb3,    scene_setup, OP_NCCS_SF1_LM1, 20, CANARY_LMAT, "NCCS LB3")
MAKE_CTRL_TEST(nccs_rbk, scene_setup, OP_NCCS_SF1_LM1, 13, CANARY_BK, "NCCS RBK")
MAKE_CTRL_TEST(nccs_gbk, scene_setup, OP_NCCS_SF1_LM1, 14, CANARY_BK, "NCCS GBK")
MAKE_CTRL_TEST(nccs_bbk, scene_setup, OP_NCCS_SF1_LM1, 15, CANARY_BK, "NCCS BBK")

// ==========================================================================
// NCDS (Normal Color Depth-cue Single): lighting + RGBC + depth cue.
// 19 cycles. Adds FC to NCCS's input set.
// ==========================================================================
MAKE_DATA_TEST(ncds_vxy0, scene_setup, OP_NCDS_SF1_LM1, 0, CANARY_VXY,  "NCDS VXY0")
MAKE_DATA_TEST(ncds_vz0,  scene_setup, OP_NCDS_SF1_LM1, 1, CANARY_VZ,   "NCDS VZ0")
MAKE_DATA_TEST(ncds_rgbc, scene_setup, OP_NCDS_SF1_LM1, 6, CANARY_RGBC, "NCDS RGBC")
MAKE_CTRL_TEST(ncds_l11l12, scene_setup, OP_NCDS_SF1_LM1,  8, CANARY_LMAT, "NCDS L11L12")
MAKE_CTRL_TEST(ncds_l13l21, scene_setup, OP_NCDS_SF1_LM1,  9, CANARY_LMAT, "NCDS L13L21")
MAKE_CTRL_TEST(ncds_l22l23, scene_setup, OP_NCDS_SF1_LM1, 10, CANARY_LMAT, "NCDS L22L23")
MAKE_CTRL_TEST(ncds_l31l32, scene_setup, OP_NCDS_SF1_LM1, 11, CANARY_LMAT, "NCDS L31L32")
MAKE_CTRL_TEST(ncds_l33,    scene_setup, OP_NCDS_SF1_LM1, 12, CANARY_LMAT, "NCDS L33")
MAKE_CTRL_TEST(ncds_lr1lr2, scene_setup, OP_NCDS_SF1_LM1, 16, CANARY_LMAT, "NCDS LR1LR2")
MAKE_CTRL_TEST(ncds_lr3lg1, scene_setup, OP_NCDS_SF1_LM1, 17, CANARY_LMAT, "NCDS LR3LG1")
MAKE_CTRL_TEST(ncds_lg2lg3, scene_setup, OP_NCDS_SF1_LM1, 18, CANARY_LMAT, "NCDS LG2LG3")
MAKE_CTRL_TEST(ncds_lb1lb2, scene_setup, OP_NCDS_SF1_LM1, 19, CANARY_LMAT, "NCDS LB1LB2")
MAKE_CTRL_TEST(ncds_lb3,    scene_setup, OP_NCDS_SF1_LM1, 20, CANARY_LMAT, "NCDS LB3")
MAKE_CTRL_TEST(ncds_rbk, scene_setup, OP_NCDS_SF1_LM1, 13, CANARY_BK, "NCDS RBK")
MAKE_CTRL_TEST(ncds_gbk, scene_setup, OP_NCDS_SF1_LM1, 14, CANARY_BK, "NCDS GBK")
MAKE_CTRL_TEST(ncds_bbk, scene_setup, OP_NCDS_SF1_LM1, 15, CANARY_BK, "NCDS BBK")
MAKE_CTRL_TEST(ncds_rfc, scene_setup, OP_NCDS_SF1_LM1, 21, CANARY_FC, "NCDS RFC")
MAKE_CTRL_TEST(ncds_gfc, scene_setup, OP_NCDS_SF1_LM1, 22, CANARY_FC, "NCDS GFC")
MAKE_CTRL_TEST(ncds_bfc, scene_setup, OP_NCDS_SF1_LM1, 23, CANARY_FC, "NCDS BFC")
