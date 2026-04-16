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

#pragma once

// COP2 (GTE) instruction encoder and register access helpers.
//
// GTE command encoding (25-bit immediate for cop2 instruction):
//
//   24      20  19  18-17  16-15  14-13  12-11  10  9-6  5-0
//   [fake ] [pad][sf][ mx ][ v  ][ cv  ][ pad ][lm][pad][cmd]
//
//   sf:  shift flag (0 = no shift, 1 = shift right 12)
//   mx:  matrix select (0=RT, 1=LL, 2=LC, 3=garbage)
//   v:   vector select (0=V0, 1=V1, 2=V2, 3=IR)
//   cv:  control vector select (0=TR, 1=BK, 2=FC/bugged, 3=zero)
//   lm:  limit flag (0=clamp -0x8000..0x7fff, 1=clamp 0..0x7fff)
//   cmd: function code (6 bits)
//
// The upper bits (20-24) contain a "fake" opcode number that Sony's
// documentation uses for instruction naming. Hardware ignores these
// bits for dispatch - only the 6-bit function code matters.

#include <stdint.h>

// ==========================================================================
// Bitfield encoding
// ==========================================================================

#define COP2_SF_SHIFT  19
#define COP2_MX_SHIFT  17
#define COP2_V_SHIFT   15
#define COP2_CV_SHIFT  13
#define COP2_LM_SHIFT  10

// Shift factor
#define COP2_SF0  0  // No shift
#define COP2_SF1  1  // Shift right 12

// Matrix select
#define COP2_MX_RT  0  // Rotation matrix
#define COP2_MX_LL  1  // Light matrix
#define COP2_MX_LC  2  // Light color matrix
#define COP2_MX_BAD 3  // Garbage matrix (undocumented)

// Vector select
#define COP2_V_V0  0
#define COP2_V_V1  1
#define COP2_V_V2  2
#define COP2_V_IR  3  // IR1/IR2/IR3

// Control vector select
#define COP2_CV_TR   0  // Translation vector
#define COP2_CV_BK   1  // Background color
#define COP2_CV_FC   2  // Far color (bugged)
#define COP2_CV_NONE 3  // Zero / no translation

// Limit mode
#define COP2_LM_SIGNED   0  // Clamp IR to [-0x8000, 0x7FFF]
#define COP2_LM_UNSIGNED 1  // Clamp IR to [0, 0x7FFF]

// Function codes (bits 5-0)
#define COP2_FN_RTPS   0x01
#define COP2_FN_NCLIP  0x06
#define COP2_FN_OP     0x0c
#define COP2_FN_DPCS   0x10
#define COP2_FN_INTPL  0x11
#define COP2_FN_MVMVA  0x12
#define COP2_FN_NCDS   0x13
#define COP2_FN_CDP    0x14
#define COP2_FN_NCDT   0x16
#define COP2_FN_NCCS   0x1b
#define COP2_FN_CC     0x1c
#define COP2_FN_NCS    0x1e
#define COP2_FN_NCT    0x20
#define COP2_FN_SQR    0x28
#define COP2_FN_DCPL   0x29
#define COP2_FN_DPCT   0x2a
#define COP2_FN_AVSZ3  0x2d
#define COP2_FN_AVSZ4  0x2e
#define COP2_FN_RTPT   0x30
#define COP2_FN_GPF    0x3d
#define COP2_FN_GPL    0x3e
#define COP2_FN_NCCT   0x3f

// ==========================================================================
// Generic encoder: build a cop2 opcode from individual fields
// ==========================================================================

// Generic encoder: build a cop2 opcode from individual fields.
// The fake field (bits 24-20) is Sony's instruction number. Hardware
// ignores it, but conventional encodings include it.
#define COP2_OP(fake, sf, mx, v, cv, lm, fn) \
    (((fake) << 20) | ((sf) << COP2_SF_SHIFT) | ((mx) << COP2_MX_SHIFT) | \
     ((v) << COP2_V_SHIFT) | ((cv) << COP2_CV_SHIFT) | \
     ((lm) << COP2_LM_SHIFT) | (fn))

// ==========================================================================
// Named instruction encoders
// ==========================================================================
// Each macro embeds the conventional fake field value from Sony's docs.
// The sf and lm parameters are user-selectable. Other fields (mx, v, cv)
// are fixed per instruction - only MVMVA exposes them.

// Perspective transform (single / triple)
#define COP2_RTPS(sf, lm)   COP2_OP( 1, sf, 0, 0, 0, lm, COP2_FN_RTPS)
#define COP2_RTPT(sf, lm)   COP2_OP( 2, sf, 0, 0, 0, lm, COP2_FN_RTPT)

// Normal clipping
#define COP2_NCLIP           COP2_OP(20, 0, 0, 0, 0, 0, COP2_FN_NCLIP)

// Cross product (rotation diagonal x IR)
#define COP2_OP_CP(sf, lm)  COP2_OP(23, sf, 0, 0, 0, lm, COP2_FN_OP)

// Depth cue
#define COP2_DPCS(sf, lm)   COP2_OP( 7, sf, 0, 0, 0, lm, COP2_FN_DPCS)
#define COP2_DPCT(sf, lm)   COP2_OP(15, sf, 0, 0, 0, lm, COP2_FN_DPCT)
#define COP2_DCPL(sf, lm)   COP2_OP( 6, sf, 0, 0, 0, lm, COP2_FN_DCPL)
#define COP2_INTPL(sf, lm)  COP2_OP( 9, sf, 0, 0, 0, lm, COP2_FN_INTPL)

// Matrix-vector multiply and add (fully parameterized)
#define COP2_MVMVA(sf, mx, v, cv, lm) \
    COP2_OP(4, sf, mx, v, cv, lm, COP2_FN_MVMVA)

// Lighting: normal color (single / triple)
#define COP2_NCS(sf, lm)    COP2_OP(12, sf, 0, 0, 0, lm, COP2_FN_NCS)
#define COP2_NCT(sf, lm)    COP2_OP(13, sf, 0, 0, 0, lm, COP2_FN_NCT)
#define COP2_NCCS(sf, lm)   COP2_OP(16, sf, 0, 0, 0, lm, COP2_FN_NCCS)
#define COP2_NCCT(sf, lm)   COP2_OP(17, sf, 0, 0, 0, lm, COP2_FN_NCCT)
#define COP2_NCDS(sf, lm)   COP2_OP(14, sf, 0, 0, 0, lm, COP2_FN_NCDS)
#define COP2_NCDT(sf, lm)   COP2_OP(15, sf, 0, 0, 0, lm, COP2_FN_NCDT)

// Color
#define COP2_CC(sf, lm)     COP2_OP(19, sf, 0, 0, 0, lm, COP2_FN_CC)
#define COP2_CDP(sf, lm)    COP2_OP(18, sf, 0, 0, 0, lm, COP2_FN_CDP)

// Square
#define COP2_SQR(sf, lm)    COP2_OP(10, sf, 0, 0, 0, lm, COP2_FN_SQR)

// Average Z
#define COP2_AVSZ3           COP2_OP(21, 1, 0, 0, 0, 0, COP2_FN_AVSZ3)
#define COP2_AVSZ4           COP2_OP(22, 1, 0, 0, 0, 0, COP2_FN_AVSZ4)

// General purpose interpolation
#define COP2_GPF(sf, lm)    COP2_OP(25, sf, 0, 0, 0, lm, COP2_FN_GPF)
#define COP2_GPL(sf, lm)    COP2_OP(26, sf, 0, 0, 0, lm, COP2_FN_GPL)

// ==========================================================================
// Execution macro
// ==========================================================================

#define cop2_cmd(op) __asm__ volatile("cop2 %0" : : "i"(op))

// ==========================================================================
// Register access
// ==========================================================================

// GTE data registers (MTC2/MFC2, $0-$31)
#define cop2_put(reg, val) do {             \
    uint32_t _v = (val);                    \
    __asm__ volatile("mtc2 %0, $" #reg      \
                     "\n\tnop\n\tnop"        \
                     : : "r"(_v));          \
} while (0)

#define cop2_get(reg, dest) do {            \
    __asm__ volatile("mfc2 %0, $" #reg      \
                     "\n\tnop\n\tnop"        \
                     : "=r"(dest));          \
} while (0)

// GTE control registers (CTC2/CFC2, $0-$31)
#define cop2_putc(reg, val) do {            \
    uint32_t _v = (val);                    \
    __asm__ volatile("ctc2 %0, $" #reg      \
                     "\n\tnop\n\tnop"        \
                     : : "r"(_v));          \
} while (0)

#define cop2_getc(reg, dest) do {           \
    __asm__ volatile("cfc2 %0, $" #reg      \
                     "\n\tnop\n\tnop"        \
                     : "=r"(dest));          \
} while (0)

// ==========================================================================
// Data register indices
// ==========================================================================

#define COP2_VXY0   0   // VX0 (low16), VY0 (high16)
#define COP2_VZ0    1
#define COP2_VXY1   2
#define COP2_VZ1    3
#define COP2_VXY2   4
#define COP2_VZ2    5
#define COP2_RGBC   6   // R (low8), G, B, CODE (high8)
#define COP2_OTZ    7   // 16-bit unsigned, zero-extended on read
#define COP2_IR0    8   // 16-bit signed, sign-extended on read
#define COP2_IR1    9
#define COP2_IR2   10
#define COP2_IR3   11
#define COP2_SXY0  12
#define COP2_SXY1  13
#define COP2_SXY2  14
#define COP2_SXYP  15  // Write pushes SXY FIFO, read returns SXY2
#define COP2_SZ0   16  // 16-bit unsigned, zero-extended on read
#define COP2_SZ1   17
#define COP2_SZ2   18
#define COP2_SZ3   19
#define COP2_RGB0  20  // Color FIFO entry 0 (oldest)
#define COP2_RGB1  21
#define COP2_RGB2  22  // Color FIFO entry 2 (newest, written by instructions)
#define COP2_RES1  23  // Reserved (but read/write works)
#define COP2_MAC0  24  // 32-bit signed
#define COP2_MAC1  25
#define COP2_MAC2  26
#define COP2_MAC3  27
#define COP2_IRGB  28  // Write expands 5-bit fields to IR1-3. Read packs IR1-3.
#define COP2_ORGB  29  // Read-only: packs IR1-3 with saturation
#define COP2_LZCS  30  // Write triggers LZCR computation
#define COP2_LZCR  31  // Read-only: leading bit count result

// ==========================================================================
// Control register indices
// ==========================================================================

#define COP2_R11R12   0
#define COP2_R13R21   1
#define COP2_R22R23   2
#define COP2_R31R32   3
#define COP2_R33      4   // 16-bit, sign-extended on read/write
#define COP2_TRX      5   // 32-bit
#define COP2_TRY      6
#define COP2_TRZ      7
#define COP2_L11L12   8
#define COP2_L13L21   9
#define COP2_L22L23  10
#define COP2_L31L32  11
#define COP2_L33     12   // 16-bit, sign-extended
#define COP2_RBK     13   // 32-bit
#define COP2_GBK     14
#define COP2_BBK     15
#define COP2_LR1LR2  16
#define COP2_LR3LG1  17
#define COP2_LG2LG3  18
#define COP2_LB1LB2  19
#define COP2_LB3     20   // 16-bit, sign-extended
#define COP2_RFC     21   // 32-bit
#define COP2_GFC     22
#define COP2_BFC     23
#define COP2_OFX     24   // 32-bit (16.16 fixed)
#define COP2_OFY     25
#define COP2_H       26   // 16-bit unsigned (but sign-extends on CFC2 read)
#define COP2_DQA     27   // 16-bit, sign-extended
#define COP2_DQB     28   // 32-bit
#define COP2_ZSF3    29   // 16-bit, sign-extended
#define COP2_ZSF4    30   // 16-bit, sign-extended
#define COP2_FLAG    31   // FLAG register (write mask 0x7FFFF000, bit 31 recomputed)

// ==========================================================================
// FLAG register bit definitions
// ==========================================================================

#define COP2_FLAG_MAC1_OVER_POS  (1u << 30)  // MAC1 result > +0x7FFFFFFFFFF
#define COP2_FLAG_MAC2_OVER_POS  (1u << 29)
#define COP2_FLAG_MAC3_OVER_POS  (1u << 28)
#define COP2_FLAG_MAC1_OVER_NEG  (1u << 27)  // MAC1 result < -0x80000000000
#define COP2_FLAG_MAC2_OVER_NEG  (1u << 26)
#define COP2_FLAG_MAC3_OVER_NEG  (1u << 25)
#define COP2_FLAG_IR1_SAT        (1u << 24)  // IR1 saturated (sets summary)
#define COP2_FLAG_IR2_SAT        (1u << 23)  // IR2 saturated (sets summary)
#define COP2_FLAG_IR3_SAT        (1u << 22)  // IR3 saturated (NO summary)
#define COP2_FLAG_COLOR_R_SAT    (1u << 21)  // Color R saturated to [0,255] (NO summary)
#define COP2_FLAG_COLOR_G_SAT    (1u << 20)  // Color G saturated (NO summary)
#define COP2_FLAG_COLOR_B_SAT    (1u << 19)  // Color B saturated (NO summary)
#define COP2_FLAG_SZ3_OTZ_SAT   (1u << 18)  // SZ3/OTZ saturated to [0,0xFFFF] (sets summary)
#define COP2_FLAG_DIV_OVERFLOW   (1u << 17)  // Division overflow H >= 2*SZ3 (sets summary)
#define COP2_FLAG_MAC0_OVER_POS  (1u << 16)  // MAC0 > 0x7FFFFFFF (sets summary)
#define COP2_FLAG_MAC0_OVER_NEG  (1u << 15)  // MAC0 < -0x80000000 (sets summary)
#define COP2_FLAG_SX2_SAT        (1u << 14)  // SX2 saturated to [-0x400,0x3FF] (sets summary)
#define COP2_FLAG_SY2_SAT        (1u << 13)  // SY2 saturated (sets summary)
#define COP2_FLAG_IR0_SAT        (1u << 12)  // IR0 saturated to [0,0x1000] (NO summary)
#define COP2_FLAG_ERROR          (1u << 31)  // Error summary (OR of bits that set summary)

// Bits that set the error summary (bit 31):
// 30-23 (MAC overflow, IR1/IR2 sat) and 18-13 (SZ3, div, MAC0, SX2, SY2)
// Bits that do NOT set summary: 22 (IR3), 21-19 (color RGB), 12 (IR0)
