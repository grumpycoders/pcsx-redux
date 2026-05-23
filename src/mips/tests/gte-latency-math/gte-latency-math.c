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

// GTE input-register latency probe - math family.
// Covers SQR (5 cycles), OP (6 cycles), NCLIP (8 cycles).

#include "gte-latency-common.h"

// clang-format off

#ifndef GTE_LATENCY_MATH_HELPERS_DEFINED
#define GTE_LATENCY_MATH_HELPERS_DEFINED

// Test scene for the math instructions.
// SQR reads IR1/2/3 only.
// OP reads R-matrix diagonal (R11, R22, R33 == control regs 0/2/4 low halves)
//    and IR1/2/3.
// NCLIP reads SXY0, SXY1, SXY2 (data regs 12, 13, 14).
static inline void scene_setup(void) {
    // R matrix - diagonal used by OP. Off-diagonal entries don't matter
    // for OP but we set them to 0 for cleanliness.
    cop2_putc(0, 0x00001000);  // R11=0x1000 (R12 high half)
    cop2_putc(1, 0x00000000);  // R13=0, R21=0
    cop2_putc(2, 0x00001000);  // R22=0x1000
    cop2_putc(3, 0x00000000);  // R31=0, R32=0
    cop2_putc(4, 0x1000);      // R33=0x1000

    // IR1/2/3 - SQR/OP inputs. Distinct non-zero values so any change
    // is observable.
    cop2_put(9,  0x0500);   // IR1
    cop2_put(10, 0x0600);   // IR2
    cop2_put(11, 0x0700);   // IR3
    cop2_put(8,  0x0800);   // IR0 (not read by SQR/OP/NCLIP but kept stable)

    // SXY0/1/2 - NCLIP inputs (screen-space 16/16-packed).
    // Triangle in screen space, non-degenerate.
    cop2_put(12, (50  << 16) | 100);   // SXY0 = (100, 50)
    cop2_put(13, (200 << 16) | 150);   // SXY1 = (150, 200)
    cop2_put(14, (250 << 16) | 80);    // SXY2 = (80, 250)

    // Clear other state we read in comparison so it doesn't drift.
    cop2_put(20, 0); cop2_put(21, 0); cop2_put(22, 0);  // RGB FIFO
    cop2_put(16, 0); cop2_put(17, 0); cop2_put(18, 0); cop2_put(19, 0);  // SZ FIFO
    cop2_put(24, 0); cop2_put(25, 0); cop2_put(26, 0); cop2_put(27, 0);  // MAC0..3

    cop2_putc(31, 0);
}

#define OP_SQR_SF1_LM1   COP2_SQR(1, 1)
#define OP_OP_SF1_LM1    COP2_OP_CP(1, 1)   // OP collides with C macro names; cop2.h uses COP2_OP_CP
#define OP_NCLIP         COP2_NCLIP

#define CANARY_IR    0x0123u   // small value
#define CANARY_RMAT  0x07ff07ffu
#define CANARY_SXY   0x12345678u

#endif // GTE_LATENCY_MATH_HELPERS_DEFINED

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
// SQR (Square): IR1/2/3 squared. 5 cycles.
// ==========================================================================
MAKE_DATA_TEST(sqr_ir1, scene_setup, OP_SQR_SF1_LM1,  9, CANARY_IR, "SQR IR1")
MAKE_DATA_TEST(sqr_ir2, scene_setup, OP_SQR_SF1_LM1, 10, CANARY_IR, "SQR IR2")
MAKE_DATA_TEST(sqr_ir3, scene_setup, OP_SQR_SF1_LM1, 11, CANARY_IR, "SQR IR3")

// ==========================================================================
// OP (cross product of R diagonal and IR): 6 cycles.
// Reads R11, R22, R33 (low halves of R11R12, R22R23, and R33) and IR1/2/3.
// ==========================================================================
MAKE_DATA_TEST(op_ir1, scene_setup, OP_OP_SF1_LM1,  9, CANARY_IR, "OP IR1")
MAKE_DATA_TEST(op_ir2, scene_setup, OP_OP_SF1_LM1, 10, CANARY_IR, "OP IR2")
MAKE_DATA_TEST(op_ir3, scene_setup, OP_OP_SF1_LM1, 11, CANARY_IR, "OP IR3")
MAKE_CTRL_TEST(op_r11r12, scene_setup, OP_OP_SF1_LM1, 0, CANARY_RMAT, "OP R11R12")
MAKE_CTRL_TEST(op_r22r23, scene_setup, OP_OP_SF1_LM1, 2, CANARY_RMAT, "OP R22R23")
MAKE_CTRL_TEST(op_r33,    scene_setup, OP_OP_SF1_LM1, 4, CANARY_RMAT, "OP R33")

// ==========================================================================
// NCLIP (normal clip - signed area of screen-space triangle): 8 cycles.
// Reads SXY0, SXY1, SXY2 (data regs 12, 13, 14).
// ==========================================================================
MAKE_DATA_TEST(nclip_sxy0, scene_setup, OP_NCLIP, 12, CANARY_SXY, "NCLIP SXY0")
MAKE_DATA_TEST(nclip_sxy1, scene_setup, OP_NCLIP, 13, CANARY_SXY, "NCLIP SXY1")
MAKE_DATA_TEST(nclip_sxy2, scene_setup, OP_NCLIP, 14, CANARY_SXY, "NCLIP SXY2")
