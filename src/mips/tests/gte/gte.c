/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

// GTE (Geometry Transformation Engine) hardware validation test suite.
// All test expectations verified against SCPH-5501 silicon.
//
// Sub-test files are included into this single compilation unit
// because libcester requires a single TU via __BASE_FILE__ re-include.

#include "common/syscalls/syscalls.h"

// clang-format off

// ==========================================================================
// GTE register access macros
// ==========================================================================
//
// The GTE has no hardware interlock between COP2 register writes and reads.
// Two NOPs after MTC2/CTC2 cover the pipeline hazard. IRGB (reg 28) needs
// 4 NOPs because it side-effects IR1/IR2/IR3 asynchronously.

#define GTE_WRITE_DATA(reg, val) do {       \
    uint32_t _v = (val);                    \
    __asm__ volatile("mtc2 %0, $" #reg      \
                     "\n\tnop\n\tnop"        \
                     : : "r"(_v));          \
} while (0)

#define GTE_READ_DATA(reg, dest) do {       \
    __asm__ volatile("mfc2 %0, $" #reg      \
                     : "=r"(dest));          \
} while (0)

#define GTE_WRITE_CTRL(reg, val) do {       \
    uint32_t _v = (val);                    \
    __asm__ volatile("ctc2 %0, $" #reg      \
                     "\n\tnop\n\tnop"        \
                     : : "r"(_v));          \
} while (0)

#define GTE_READ_CTRL(reg, dest) do {       \
    __asm__ volatile("cfc2 %0, $" #reg      \
                     : "=r"(dest));          \
} while (0)

#define GTE_EXEC(cmd) __asm__ volatile("cop2 %0" : : "i"(cmd))

// ==========================================================================
// GTE command opcodes (from psyqo/gte-kernels.hh)
// ==========================================================================

#define GTE_CMD_RTPS      0x0180001
#define GTE_CMD_RTPS_SF0  0x0100001
#define GTE_CMD_RTPT      0x0280030
#define GTE_CMD_NCLIP     0x1400006
#define GTE_CMD_OP_SF     0x0178000c
#define GTE_CMD_OP        0x0170000c
#define GTE_CMD_DPCS      0x0780010
#define GTE_CMD_DPCT      0x0f8002a
#define GTE_CMD_INTPL     0x0980011
#define GTE_CMD_SQR_SF    0x0a80428
#define GTE_CMD_SQR       0x0a00428
#define GTE_CMD_DCPL      0x0680029
#define GTE_CMD_AVSZ3     0x158002d
#define GTE_CMD_AVSZ4     0x168002e
#define GTE_CMD_GPF_SF    0x0198003d
#define GTE_CMD_GPF       0x0190003d
#define GTE_CMD_GPF_SF_LM 0x0198043d
#define GTE_CMD_GPL_SF    0x01a8003e
#define GTE_CMD_GPL       0x01a0003e
#define GTE_CMD_NCDS      0x0e80413
#define GTE_CMD_NCDT      0x0f80416
#define GTE_CMD_NCCS      0x108041b
#define GTE_CMD_NCCT      0x118043f
#define GTE_CMD_NCS       0x0c8041e
#define GTE_CMD_NCT       0x0d80420
#define GTE_CMD_CC        0x138041c
#define GTE_CMD_CDP       0x1280414

#define GTE_CMD_MVMVA(sf, mx, v, cv, lm) \
    ((4 << 20) | ((sf) << 19) | ((mx) << 17) | ((v) << 15) | ((cv) << 13) | ((lm) << 10) | 18)

// ==========================================================================
// GTE register indices (for reference)
// ==========================================================================
//
// Data registers (MTC2/MFC2):
//   0:VXY0  1:VZ0  2:VXY1  3:VZ1  4:VXY2  5:VZ2  6:RGBC  7:OTZ
//   8:IR0  9:IR1  10:IR2  11:IR3
//   12:SXY0  13:SXY1  14:SXY2  15:SXYP
//   16:SZ0  17:SZ1  18:SZ2  19:SZ3
//   20:RGB0  21:RGB1  22:RGB2  23:RES1
//   24:MAC0  25:MAC1  26:MAC2  27:MAC3
//   28:IRGB  29:ORGB  30:LZCS  31:LZCR
//
// Control registers (CTC2/CFC2):
//   0:R11R12  1:R13R21  2:R22R23  3:R31R32  4:R33
//   5:TRX  6:TRY  7:TRZ
//   8:L11L12  9:L13L21  10:L22L23  11:L31L32  12:L33
//   13:RBK  14:GBK  15:BBK
//   16:LR1LR2  17:LR3LG1  18:LG2LG3  19:LB1LB2  20:LB3
//   21:RFC  22:GFC  23:BFC
//   24:OFX  25:OFY  26:H  27:DQA  28:DQB
//   29:ZSF3  30:ZSF4  31:FLAG

// ==========================================================================
// Helper functions (guarded against cester double-include)
// ==========================================================================

#ifndef GTE_HELPERS_DEFINED
#define GTE_HELPERS_DEFINED

static inline void gte_enable(void) {
    uint32_t sr;
    __asm__ volatile("mfc0 %0, $12" : "=r"(sr));
    sr |= 0x40000000;
    __asm__ volatile("mtc0 %0, $12; nop; nop" : : "r"(sr));
}

static inline void gte_clear_flag(void) {
    GTE_WRITE_CTRL(31, 0);
}

static inline uint32_t gte_read_flag(void) {
    uint32_t flag;
    GTE_READ_CTRL(31, flag);
    return flag;
}

// Set rotation matrix to identity
static inline void gte_set_identity_rotation(void) {
    GTE_WRITE_CTRL(0, 0x00001000);  // R11=0x1000, R12=0
    GTE_WRITE_CTRL(1, 0x00000000);  // R13=0, R21=0
    GTE_WRITE_CTRL(2, 0x00001000);  // R22=0x1000, R23=0
    GTE_WRITE_CTRL(3, 0x00000000);  // R31=0, R32=0
    GTE_WRITE_CTRL(4, 0x1000);      // R33=0x1000
}

// Set light matrix to simple Z-direction
static inline void gte_set_simple_light(void) {
    GTE_WRITE_CTRL(8, 0x00000000);   // L11=0, L12=0
    GTE_WRITE_CTRL(9, 0x00000000);   // L13=0, L21=0
    GTE_WRITE_CTRL(10, 0x00000000);  // L22=0, L23=0
    GTE_WRITE_CTRL(11, 0x00000000);  // L31=0, L32=0
    GTE_WRITE_CTRL(12, 0x1000);      // L33=0x1000
}

// Set light color matrix to white (identity diagonal)
static inline void gte_set_white_light_color(void) {
    GTE_WRITE_CTRL(16, 0x00001000);  // LR1=0x1000, LR2=0
    GTE_WRITE_CTRL(17, 0x00000000);  // LR3=0, LG1=0
    GTE_WRITE_CTRL(18, 0x00001000);  // LG2=0x1000, LG3=0
    GTE_WRITE_CTRL(19, 0x00000000);  // LB1=0, LB2=0
    GTE_WRITE_CTRL(20, 0x1000);      // LB3=0x1000
}

// Set background color to zero
static inline void gte_set_zero_bk(void) {
    GTE_WRITE_CTRL(13, 0);  // RBK
    GTE_WRITE_CTRL(14, 0);  // GBK
    GTE_WRITE_CTRL(15, 0);  // BBK
}

// Set far color
static inline void gte_set_far_color(int32_t r, int32_t g, int32_t b) {
    GTE_WRITE_CTRL(21, r);  // RFC
    GTE_WRITE_CTRL(22, g);  // GFC
    GTE_WRITE_CTRL(23, b);  // BFC
}

// Set translation vector
static inline void gte_set_translation(int32_t x, int32_t y, int32_t z) {
    GTE_WRITE_CTRL(5, x);
    GTE_WRITE_CTRL(6, y);
    GTE_WRITE_CTRL(7, z);
}

// Set screen offset and projection
static inline void gte_set_screen(int32_t ofx, int32_t ofy, uint16_t h) {
    GTE_WRITE_CTRL(24, ofx);
    GTE_WRITE_CTRL(25, ofy);
    GTE_WRITE_CTRL(26, h);
    GTE_WRITE_CTRL(27, 0);  // DQA
    GTE_WRITE_CTRL(28, 0);  // DQB
}

#endif // GTE_HELPERS_DEFINED

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

CESTER_BEFORE_ALL(gte_tests,
    gte_enable();
)

// Include sub-test files
#include "gte-regio.c"
#include "gte-nclip.c"
#include "gte-avsz.c"
#include "gte-sqr.c"
#include "gte-op.c"
#include "gte-gpf-gpl.c"
#include "gte-rtps.c"
#include "gte-mvmva.c"
#include "gte-depthcue.c"
#include "gte-lighting.c"
