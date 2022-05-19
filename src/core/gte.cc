/*
 * PlayStation Geometry Transformation Engine emulator
 *
 * Copyright 2003-2013 smf
 *
 */

#include "core/gte.h"

#include <algorithm>

#include "core/pgxp_debug.h"
#include "core/pgxp_gte.h"
#include "core/psxmem.h"

#undef GTE_SF
#undef GTE_MX
#undef GTE_V
#undef GTE_CV
#undef GTE_LM
#undef GTE_FUNCT

#undef VX0
#undef VY0
#undef VZ0
#undef VX1
#undef VY1
#undef VZ1
#undef VX2
#undef VY2
#undef VZ2
#undef R
#undef G
#undef B
#undef CODE
#undef OTZ
#undef IR0
#undef IR1
#undef IR2
#undef IR3
#undef SXY0
#undef SX0
#undef SY0
#undef SXY1
#undef SX1
#undef SY1
#undef SXY2
#undef SX2
#undef SY2
#undef SXYP
#undef SXP
#undef SYP
#undef SZ0
#undef SZ1
#undef SZ2
#undef SZ3
#undef RGB0
#undef R0
#undef G0
#undef B0
#undef CD0
#undef RGB1
#undef R1
#undef G1
#undef B1
#undef CD1
#undef RGB2
#undef R2
#undef G2
#undef B2
#undef CD2
#undef RES1
#undef MAC0
#undef MAC1
#undef MAC2
#undef MAC3
#undef IRGB
#undef ORGB
#undef LZCS
#undef LZCR

#undef R11
#undef R12
#undef R13
#undef R21
#undef R22
#undef R23
#undef R31
#undef R32
#undef R33
#undef TRX
#undef TRY
#undef TRZ
#undef L11
#undef L12
#undef L13
#undef L21
#undef L22
#undef L23
#undef L31
#undef L32
#undef L33
#undef RBK
#undef GBK
#undef BBK
#undef LR1
#undef LR2
#undef LR3
#undef LG1
#undef LG2
#undef LG3
#undef LB1
#undef LB2
#undef LB3
#undef RFC
#undef GFC
#undef BFC
#undef OFX
#undef OFY
#undef H
#undef DQA
#undef DQB
#undef ZSF3
#undef ZSF4
#undef FLAG

#undef VX
#undef VY
#undef VZ
#undef MX11
#undef MX12
#undef MX13
#undef MX21
#undef MX22
#undef MX23
#undef MX31
#undef MX32
#undef MX33
#undef CV1
#undef CV2
#undef CV3

#define GTE_SF(op) ((op >> 19) & 1)
#define GTE_MX(op) ((op >> 17) & 3)
#define GTE_V(op) ((op >> 15) & 3)
#define GTE_CV(op) ((op >> 13) & 3)
#define GTE_LM(op) ((op >> 10) & 1)
#define GTE_FUNCT(op) (op & 63)

#define VX0 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[0].sw.l)
#define VY0 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[0].sw.h)
#define VZ0 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[1].sw.l)
#define VX1 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[2].w.l)
#define VY1 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[2].w.h)
#define VZ1 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[3].w.l)
#define VX2 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[4].w.l)
#define VY2 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[4].w.h)
#define VZ2 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[5].w.l)
#define R (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[6].b.l)
#define G (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[6].b.h)
#define B (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[6].b.h2)
#define CODE (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[6].b.h3)
#define OTZ (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[7].w.l)
#define IR0 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[8].sw.l)
#define IR1 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[9].sw.l)
#define IR2 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[10].sw.l)
#define IR3 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[11].sw.l)
#define SXY0 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[12].d)
#define SX0 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[12].sw.l)
#define SY0 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[12].sw.h)
#define SXY1 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[13].d)
#define SX1 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[13].sw.l)
#define SY1 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[13].sw.h)
#define SXY2 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[14].d)
#define SX2 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[14].sw.l)
#define SY2 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[14].sw.h)
#define SXYP (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[15].d)
#define SXP (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[15].sw.l)
#define SYP (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[15].sw.h)
#define SZ0 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[16].w.l)
#define SZ1 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[17].w.l)
#define SZ2 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[18].w.l)
#define SZ3 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[19].w.l)
#define RGB0 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[20].d)
#define R0 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[20].b.l)
#define G0 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[20].b.h)
#define B0 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[20].b.h2)
#define CD0 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[20].b.h3)
#define RGB1 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[21].d)
#define R1 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[21].b.l)
#define G1 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[21].b.h)
#define B1 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[21].b.h2)
#define CD1 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[21].b.h3)
#define RGB2 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[22].d)
#define R2 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[22].b.l)
#define G2 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[22].b.h)
#define B2 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[22].b.h2)
#define CD2 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[22].b.h3)
#define RES1 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[23].d)
#define MAC0 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[24].sd)
#define MAC1 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[25].sd)
#define MAC2 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[26].sd)
#define MAC3 (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[27].sd)
#define IRGB (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[28].d)
#define ORGB (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[29].d)
#define LZCS (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[30].d)
#define LZCR (PCSX::g_emulator->m_cpu->m_regs.CP2D.p[31].d)

#define R11 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[0].sw.l)
#define R12 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[0].sw.h)
#define R13 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[1].sw.l)
#define R21 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[1].sw.h)
#define R22 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[2].sw.l)
#define R23 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[2].sw.h)
#define R31 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[3].sw.l)
#define R32 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[3].sw.h)
#define R33 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[4].sw.l)
#define TRX (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[5].sd)
#define TRY (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[6].sd)
#define TRZ (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[7].sd)
#define L11 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[8].sw.l)
#define L12 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[8].sw.h)
#define L13 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[9].sw.l)
#define L21 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[9].sw.h)
#define L22 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[10].sw.l)
#define L23 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[10].sw.h)
#define L31 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[11].sw.l)
#define L32 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[11].sw.h)
#define L33 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[12].sw.l)
#define RBK (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[13].sd)
#define GBK (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[14].sd)
#define BBK (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[15].sd)
#define LR1 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[16].sw.l)
#define LR2 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[16].sw.h)
#define LR3 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[17].sw.l)
#define LG1 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[17].sw.h)
#define LG2 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[18].sw.l)
#define LG3 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[18].sw.h)
#define LB1 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[19].sw.l)
#define LB2 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[19].sw.h)
#define LB3 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[20].sw.l)
#define RFC (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[21].sd)
#define GFC (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[22].sd)
#define BFC (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[23].sd)
#define OFX (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[24].sd)
#define OFY (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[25].sd)
#define H (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[26].sw.l)
#define DQA (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[27].sw.l)
#define DQB (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[28].sd)
#define ZSF3 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[29].sw.l)
#define ZSF4 (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[30].sw.l)
#define FLAG (PCSX::g_emulator->m_cpu->m_regs.CP2C.p[31].d)

#define VX(n) (n < 3 ? PCSX::g_emulator->m_cpu->m_regs.CP2D.p[n << 1].sw.l : IR1)
#define VY(n) (n < 3 ? PCSX::g_emulator->m_cpu->m_regs.CP2D.p[n << 1].sw.h : IR2)
#define VZ(n) (n < 3 ? PCSX::g_emulator->m_cpu->m_regs.CP2D.p[(n << 1) + 1].sw.l : IR3)
#define MX11(n) (n < 3 ? PCSX::g_emulator->m_cpu->m_regs.CP2C.p[(n << 3)].sw.l : -R << 4)
#define MX12(n) (n < 3 ? PCSX::g_emulator->m_cpu->m_regs.CP2C.p[(n << 3)].sw.h : R << 4)
#define MX13(n) (n < 3 ? PCSX::g_emulator->m_cpu->m_regs.CP2C.p[(n << 3) + 1].sw.l : IR0)
#define MX21(n) (n < 3 ? PCSX::g_emulator->m_cpu->m_regs.CP2C.p[(n << 3) + 1].sw.h : R13)
#define MX22(n) (n < 3 ? PCSX::g_emulator->m_cpu->m_regs.CP2C.p[(n << 3) + 2].sw.l : R13)
#define MX23(n) (n < 3 ? PCSX::g_emulator->m_cpu->m_regs.CP2C.p[(n << 3) + 2].sw.h : R13)
#define MX31(n) (n < 3 ? PCSX::g_emulator->m_cpu->m_regs.CP2C.p[(n << 3) + 3].sw.l : R22)
#define MX32(n) (n < 3 ? PCSX::g_emulator->m_cpu->m_regs.CP2C.p[(n << 3) + 3].sw.h : R22)
#define MX33(n) (n < 3 ? PCSX::g_emulator->m_cpu->m_regs.CP2C.p[(n << 3) + 4].sw.l : R22)
#define CV1(n) (n < 3 ? PCSX::g_emulator->m_cpu->m_regs.CP2C.p[(n << 3) + 5].sd : 0)
#define CV2(n) (n < 3 ? PCSX::g_emulator->m_cpu->m_regs.CP2C.p[(n << 3) + 6].sd : 0)
#define CV3(n) (n < 3 ? PCSX::g_emulator->m_cpu->m_regs.CP2C.p[(n << 3) + 7].sd : 0)

static int32_t LIM(int32_t value, int32_t max, int32_t min, uint32_t flag) {
    if (value > max) {
        FLAG |= flag;
        return max;
    } else if (value < min) {
        FLAG |= flag;
        return min;
    }

    return value;
}

uint32_t PCSX::GTE::MFC2_internal(int reg) {
    switch (reg) {
        case 1:
        case 3:
        case 5:
        case 8:
        case 9:
        case 10:
        case 11:
            PCSX::g_emulator->m_cpu->m_regs.CP2D.p[reg].d = (int32_t)PCSX::g_emulator->m_cpu->m_regs.CP2D.p[reg].sw.l;
            break;

        case 7:
        case 16:
        case 17:
        case 18:
        case 19:
            PCSX::g_emulator->m_cpu->m_regs.CP2D.p[reg].d = (uint32_t)PCSX::g_emulator->m_cpu->m_regs.CP2D.p[reg].w.l;
            break;

        case 15:
            PCSX::g_emulator->m_cpu->m_regs.CP2D.p[reg].d = SXY2;
            break;

        case 28:
        case 29:
            PCSX::g_emulator->m_cpu->m_regs.CP2D.p[reg].d =
                LIM(IR1 >> 7, 0x1f, 0, 0) | (LIM(IR2 >> 7, 0x1f, 0, 0) << 5) | (LIM(IR3 >> 7, 0x1f, 0, 0) << 10);
            break;
    }

    return PCSX::g_emulator->m_cpu->m_regs.CP2D.p[reg].d;
}

void PCSX::GTE::MTC2_internal(uint32_t value, int reg) {
    switch (reg) {
        case 15:
            SXY0 = SXY1;
            SXY1 = SXY2;
            SXY2 = value;
            break;

        case 28:
            IR1 = (value & 0x1f) << 7;
            IR2 = (value & 0x3e0) << 2;
            IR3 = (value & 0x7c00) >> 3;
            break;

        case 30:
            LZCR = countLeadingBits(value);
            break;

        case 31:
            return;
    }

    PCSX::g_emulator->m_cpu->m_regs.CP2D.p[reg].d = value;
}

void PCSX::GTE::CTC2_internal(uint32_t value, int reg) {
    switch (reg) {
        case 4:
        case 12:
        case 20:
        case 26:
        case 27:
        case 29:
        case 30:
            value = (int32_t)(int16_t)value;
            break;

        case 31:
            value = value & 0x7ffff000;
            if ((value & 0x7f87e000) != 0) value |= 0x80000000;
            break;
    }

    PCSX::g_emulator->m_cpu->m_regs.CP2C.p[reg].d = value;
}

// Push a Z value to the Z-coordinate FIFO
void PCSX::GTE::pushZ(uint16_t z) {
    SZ0 = SZ1;
    SZ1 = SZ2;
    SZ2 = SZ3;
    SZ3 = z;
}

// Arithmetic shift right by (sf * 12)
static inline int64_t gte_shift(int64_t a, int sf) { return sf == 0 ? a : a >> 12; }
// Shift left by (sf * 12) for GPL
static inline int64_t gte_shift_GPL(int64_t a, int sf) { return sf == 0 ? a : a << 12; }

int32_t PCSX::GTE::BOUNDS(int44 value, int max_flag, int min_flag) {
    if (value.positiveOverflow()) FLAG |= max_flag;
    if (value.negativeOverflow()) FLAG |= min_flag;

    return gte_shift(value.value(), s_sf);
}

static uint32_t gte_divide(uint16_t numerator, uint16_t denominator) {
    if (numerator >= denominator * 2) {  // Division overflow
        FLAG |= (1 << 31) | (1 << 17);
        return 0x1ffff;
    }

    static uint8_t table[] = {
        0xff, 0xfd, 0xfb, 0xf9, 0xf7, 0xf5, 0xf3, 0xf1, 0xef, 0xee, 0xec, 0xea, 0xe8, 0xe6, 0xe4, 0xe3, 0xe1, 0xdf,
        0xdd, 0xdc, 0xda, 0xd8, 0xd6, 0xd5, 0xd3, 0xd1, 0xd0, 0xce, 0xcd, 0xcb, 0xc9, 0xc8, 0xc6, 0xc5, 0xc3, 0xc1,
        0xc0, 0xbe, 0xbd, 0xbb, 0xba, 0xb8, 0xb7, 0xb5, 0xb4, 0xb2, 0xb1, 0xb0, 0xae, 0xad, 0xab, 0xaa, 0xa9, 0xa7,
        0xa6, 0xa4, 0xa3, 0xa2, 0xa0, 0x9f, 0x9e, 0x9c, 0x9b, 0x9a, 0x99, 0x97, 0x96, 0x95, 0x94, 0x92, 0x91, 0x90,
        0x8f, 0x8d, 0x8c, 0x8b, 0x8a, 0x89, 0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81, 0x7f, 0x7e, 0x7d, 0x7c, 0x7b,
        0x7a, 0x79, 0x78, 0x77, 0x75, 0x74, 0x73, 0x72, 0x71, 0x70, 0x6f, 0x6e, 0x6d, 0x6c, 0x6b, 0x6a, 0x69, 0x68,
        0x67, 0x66, 0x65, 0x64, 0x63, 0x62, 0x61, 0x60, 0x5f, 0x5e, 0x5d, 0x5d, 0x5c, 0x5b, 0x5a, 0x59, 0x58, 0x57,
        0x56, 0x55, 0x54, 0x53, 0x53, 0x52, 0x51, 0x50, 0x4f, 0x4e, 0x4d, 0x4d, 0x4c, 0x4b, 0x4a, 0x49, 0x48, 0x48,
        0x47, 0x46, 0x45, 0x44, 0x43, 0x43, 0x42, 0x41, 0x40, 0x3f, 0x3f, 0x3e, 0x3d, 0x3c, 0x3c, 0x3b, 0x3a, 0x39,
        0x39, 0x38, 0x37, 0x36, 0x36, 0x35, 0x34, 0x33, 0x33, 0x32, 0x31, 0x31, 0x30, 0x2f, 0x2e, 0x2e, 0x2d, 0x2c,
        0x2c, 0x2b, 0x2a, 0x2a, 0x29, 0x28, 0x28, 0x27, 0x26, 0x26, 0x25, 0x24, 0x24, 0x23, 0x22, 0x22, 0x21, 0x20,
        0x20, 0x1f, 0x1e, 0x1e, 0x1d, 0x1d, 0x1c, 0x1b, 0x1b, 0x1a, 0x19, 0x19, 0x18, 0x18, 0x17, 0x16, 0x16, 0x15,
        0x15, 0x14, 0x14, 0x13, 0x12, 0x12, 0x11, 0x11, 0x10, 0x0f, 0x0f, 0x0e, 0x0e, 0x0d, 0x0d, 0x0c, 0x0c, 0x0b,
        0x0a, 0x0a, 0x09, 0x09, 0x08, 0x08, 0x07, 0x07, 0x06, 0x06, 0x05, 0x05, 0x04, 0x04, 0x03, 0x03, 0x02, 0x02,
        0x01, 0x01, 0x00, 0x00, 0x00};

    int shift = PCSX::GTE::countLeadingZeros16(denominator);

    int r1 = (denominator << shift) & 0x7fff;
    int r2 = table[((r1 + 0x40) >> 7)] + 0x101;
    int r3 = ((0x80 - (r2 * (r1 + 0x8000))) >> 8) & 0x1ffff;
    uint32_t reciprocal = ((r2 * r3) + 0x80) >> 8;

    const uint32_t res = ((((uint64_t)reciprocal * (numerator << shift)) + 0x8000) >> 16);

    // Some divisions like 0xF015/0x780B result in 0x20000, but are saturated to 0x1ffff without setting FLAG
    return std::min<uint32_t>(0x1ffff, res);
}

// Setting bits 12 & 19-22 in FLAG does not set bit 31

int32_t PCSX::GTE::A1(int44 a) { return BOUNDS(a, (1 << 31) | (1 << 30), (1 << 31) | (1 << 27)); }
int32_t PCSX::GTE::A2(int44 a) { return BOUNDS(a, (1 << 31) | (1 << 29), (1 << 31) | (1 << 26)); }
int32_t PCSX::GTE::A3(int44 a) {
    s_mac3 = a.value();
    return BOUNDS(a, (1 << 31) | (1 << 28), (1 << 31) | (1 << 25));
}
static int32_t Lm_B1(int32_t a, int lm) { return LIM(a, 0x7fff, -0x8000 * !lm, (1 << 31) | (1 << 24)); }
static int32_t Lm_B2(int32_t a, int lm) { return LIM(a, 0x7fff, -0x8000 * !lm, (1 << 31) | (1 << 23)); }
static int32_t Lm_B3(int32_t a, int lm) { return LIM(a, 0x7fff, -0x8000 * !lm, (1 << 22)); }

static int32_t Lm_B3_sf(int64_t value, int sf, int lm) {
    int32_t value_sf = gte_shift(value, sf);
    int32_t value_12 = gte_shift(value, 1);
    constexpr int32_t max = 0x7fff;
    int32_t min = 0;
    if (lm == 0) min = -0x8000;

    if (value_12 < -0x8000 || value_12 > 0x7fff) FLAG |= (1 << 22);
    return std::clamp<int32_t>(value_sf, min, max);
}

static int32_t Lm_C1(int32_t a) { return LIM(a, 0x00ff, 0x0000, (1 << 21)); }
static int32_t Lm_C2(int32_t a) { return LIM(a, 0x00ff, 0x0000, (1 << 20)); }
static int32_t Lm_C3(int32_t a) { return LIM(a, 0x00ff, 0x0000, (1 << 19)); }
static int32_t Lm_D(int64_t a, int sf) { return LIM(gte_shift(a, sf), 0xffff, 0x0000, (1 << 31) | (1 << 18)); }

int64_t PCSX::GTE::F(int64_t a) {
    s_mac0 = a;

    if (a > S64(0x7fffffff)) FLAG |= (1 << 31) | (1 << 16);

    if (a < S64(-0x80000000)) FLAG |= (1 << 31) | (1 << 15);

    return a;
}

static int32_t Lm_G1(int64_t a) {
    if (a > 0x3ff) {
        FLAG |= (1 << 31) | (1 << 14);
        return 0x3ff;
    }
    if (a < -0x400) {
        FLAG |= (1 << 31) | (1 << 14);
        return -0x400;
    }

    return a;
}

static int32_t Lm_G2(int64_t a) {
    if (a > 0x3ff) {
        FLAG |= (1 << 31) | (1 << 13);
        return 0x3ff;
    }

    if (a < -0x400) {
        FLAG |= (1 << 31) | (1 << 13);
        return -0x400;
    }

    return a;
}

static int32_t Lm_G1_ia(int64_t a) { return std::clamp<int64_t>(a, -0x4000000, 0x3ffffff); }
static int32_t Lm_G2_ia(int64_t a) { return std::clamp<int64_t>(a, -0x4000000, 0x3ffffff); }

static int32_t Lm_H(int64_t value, int sf) {
    int64_t value_sf = gte_shift(value, sf);
    int32_t value_12 = gte_shift(value, 1);
    constexpr int32_t max = 0x1000;
    constexpr int32_t min = 0x0000;

    if (value_sf < min || value_sf > max) FLAG |= (1 << 12);
    return std::clamp<int32_t>(value_12, min, max);
}

void PCSX::GTE::RTPS(uint32_t op) {
    GTE_LOG("%08x GTE: RTPS|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    MAC1 = A1(int44((int64_t)TRX << 12) + (R11 * VX0) + (R12 * VY0) + (R13 * VZ0));
    MAC2 = A2(int44((int64_t)TRY << 12) + (R21 * VX0) + (R22 * VY0) + (R23 * VZ0));
    MAC3 = A3(int44((int64_t)TRZ << 12) + (R31 * VX0) + (R32 * VY0) + (R33 * VZ0));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3_sf(s_mac3, s_sf, lm);
    pushZ(Lm_D(s_mac3, 1));

    const int32_t h_over_sz3 = gte_divide(H, SZ3);
    SXY0 = SXY1;
    SXY1 = SXY2;
    SX2 =
        Lm_G1(F((int64_t)OFX + ((int64_t)IR1 * h_over_sz3) * (PCSX::g_emulator->config().Widescreen ? 0.75 : 1)) >> 16);

    SY2 = Lm_G2(F((int64_t)OFY + ((int64_t)IR2 * h_over_sz3)) >> 16);

    PGXP_pushSXYZ2s(
        Lm_G1_ia((int64_t)OFX + (int64_t)(IR1 * h_over_sz3) * (PCSX::g_emulator->config().Widescreen ? 0.75 : 1)),
        Lm_G2_ia((int64_t)OFY + (int64_t)(IR2 * h_over_sz3)), std::max((int)SZ3, H / 2), SXY2);

    // PGXP_RTPS(0, SXY2);

    MAC0 = F((int64_t)DQB + ((int64_t)DQA * h_over_sz3));
    IR0 = Lm_H(s_mac0, 1);
}

void PCSX::GTE::NCLIP(uint32_t op) {
    GTE_LOG("%08x GTE: NCLIP|", op);
    FLAG = 0;

    if (PGXP_NLCIP_valid(SXY0, SXY1, SXY2))
        MAC0 = F(PGXP_NCLIP());
    else
        MAC0 = F((int64_t)(SX0 * SY1) + (SX1 * SY2) + (SX2 * SY0) - (SX0 * SY2) - (SX1 * SY0) - (SX2 * SY1));
}

void PCSX::GTE::OP(uint32_t op) {
    GTE_LOG("%08x GTE: OP|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    MAC1 = A1((int64_t)(R22 * IR3) - (R33 * IR2));
    MAC2 = A2((int64_t)(R33 * IR1) - (R11 * IR3));
    MAC3 = A3((int64_t)(R11 * IR2) - (R22 * IR1));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
}

void PCSX::GTE::DPCS(uint32_t op) {
    GTE_LOG("%08x GTE: DPCS|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    MAC1 = A1((R << 16) + (IR0 * Lm_B1(A1(((int64_t)RFC << 12) - (R << 16)), 0)));
    MAC2 = A2((G << 16) + (IR0 * Lm_B2(A2(((int64_t)GFC << 12) - (G << 16)), 0)));
    MAC3 = A3((B << 16) + (IR0 * Lm_B3(A3(((int64_t)BFC << 12) - (B << 16)), 0)));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    RGB0 = RGB1;
    RGB1 = RGB2;
    CD2 = CODE;
    R2 = Lm_C1(MAC1 >> 4);
    G2 = Lm_C2(MAC2 >> 4);
    B2 = Lm_C3(MAC3 >> 4);
}

void PCSX::GTE::INTPL(uint32_t op) {
    GTE_LOG("%08x GTE: INTPL|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    MAC1 = A1((IR1 << 12) + (IR0 * Lm_B1(A1(((int64_t)RFC << 12) - (IR1 << 12)), 0)));
    MAC2 = A2((IR2 << 12) + (IR0 * Lm_B2(A2(((int64_t)GFC << 12) - (IR2 << 12)), 0)));
    MAC3 = A3((IR3 << 12) + (IR0 * Lm_B3(A3(((int64_t)BFC << 12) - (IR3 << 12)), 0)));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    RGB0 = RGB1;
    RGB1 = RGB2;
    CD2 = CODE;
    R2 = Lm_C1(MAC1 >> 4);
    G2 = Lm_C2(MAC2 >> 4);
    B2 = Lm_C3(MAC3 >> 4);
}

void PCSX::GTE::MVMVA(uint32_t op) {
    GTE_LOG("%08x GTE: MVMVA|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    const int mx = GTE_MX(gteop(op));
    const int v = GTE_V(gteop(op));
    const int cv = GTE_CV(gteop(op));

    switch (cv) {
        case 2:
            MAC1 = A1((int64_t)(MX12(mx) * VY(v)) + (MX13(mx) * VZ(v)));
            MAC2 = A2((int64_t)(MX22(mx) * VY(v)) + (MX23(mx) * VZ(v)));
            MAC3 = A3((int64_t)(MX32(mx) * VY(v)) + (MX33(mx) * VZ(v)));
            Lm_B1(A1(((int64_t)CV1(cv) << 12) + (MX11(mx) * VX(v))), 0);
            Lm_B2(A2(((int64_t)CV2(cv) << 12) + (MX21(mx) * VX(v))), 0);
            Lm_B3(A3(((int64_t)CV3(cv) << 12) + (MX31(mx) * VX(v))), 0);
            break;

        default:
            MAC1 = A1(int44((int64_t)CV1(cv) << 12) + (MX11(mx) * VX(v)) + (MX12(mx) * VY(v)) + (MX13(mx) * VZ(v)));
            MAC2 = A2(int44((int64_t)CV2(cv) << 12) + (MX21(mx) * VX(v)) + (MX22(mx) * VY(v)) + (MX23(mx) * VZ(v)));
            MAC3 = A3(int44((int64_t)CV3(cv) << 12) + (MX31(mx) * VX(v)) + (MX32(mx) * VY(v)) + (MX33(mx) * VZ(v)));
            break;
    }

    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
}

void PCSX::GTE::NCDS(uint32_t op) {
    GTE_LOG("%08x GTE: NCDS|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    MAC1 = A1((int64_t)(L11 * VX0) + (L12 * VY0) + (L13 * VZ0));
    MAC2 = A2((int64_t)(L21 * VX0) + (L22 * VY0) + (L23 * VZ0));
    MAC3 = A3((int64_t)(L31 * VX0) + (L32 * VY0) + (L33 * VZ0));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    MAC1 = A1(int44((int64_t)RBK << 12) + (LR1 * IR1) + (LR2 * IR2) + (LR3 * IR3));
    MAC2 = A2(int44((int64_t)GBK << 12) + (LG1 * IR1) + (LG2 * IR2) + (LG3 * IR3));
    MAC3 = A3(int44((int64_t)BBK << 12) + (LB1 * IR1) + (LB2 * IR2) + (LB3 * IR3));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    MAC1 = A1(((R << 4) * IR1) + (IR0 * Lm_B1(A1(((int64_t)RFC << 12) - ((R << 4) * IR1)), 0)));
    MAC2 = A2(((G << 4) * IR2) + (IR0 * Lm_B2(A2(((int64_t)GFC << 12) - ((G << 4) * IR2)), 0)));
    MAC3 = A3(((B << 4) * IR3) + (IR0 * Lm_B3(A3(((int64_t)BFC << 12) - ((B << 4) * IR3)), 0)));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    RGB0 = RGB1;
    RGB1 = RGB2;
    CD2 = CODE;
    R2 = Lm_C1(MAC1 >> 4);
    G2 = Lm_C2(MAC2 >> 4);
    B2 = Lm_C3(MAC3 >> 4);
}

void PCSX::GTE::CDP(uint32_t op) {
    GTE_LOG("%08x GTE: CDP|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    MAC1 = A1(int44((int64_t)RBK << 12) + (LR1 * IR1) + (LR2 * IR2) + (LR3 * IR3));
    MAC2 = A2(int44((int64_t)GBK << 12) + (LG1 * IR1) + (LG2 * IR2) + (LG3 * IR3));
    MAC3 = A3(int44((int64_t)BBK << 12) + (LB1 * IR1) + (LB2 * IR2) + (LB3 * IR3));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    MAC1 = A1(((R << 4) * IR1) + (IR0 * Lm_B1(A1(((int64_t)RFC << 12) - ((R << 4) * IR1)), 0)));
    MAC2 = A2(((G << 4) * IR2) + (IR0 * Lm_B2(A2(((int64_t)GFC << 12) - ((G << 4) * IR2)), 0)));
    MAC3 = A3(((B << 4) * IR3) + (IR0 * Lm_B3(A3(((int64_t)BFC << 12) - ((B << 4) * IR3)), 0)));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    RGB0 = RGB1;
    RGB1 = RGB2;
    CD2 = CODE;
    R2 = Lm_C1(MAC1 >> 4);
    G2 = Lm_C2(MAC2 >> 4);
    B2 = Lm_C3(MAC3 >> 4);
}

void PCSX::GTE::NCDT(uint32_t op) {
    GTE_LOG("%08x GTE: NCDT|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    for (int v = 0; v < 3; v++) {
        MAC1 = A1((int64_t)(L11 * VX(v)) + (L12 * VY(v)) + (L13 * VZ(v)));
        MAC2 = A2((int64_t)(L21 * VX(v)) + (L22 * VY(v)) + (L23 * VZ(v)));
        MAC3 = A3((int64_t)(L31 * VX(v)) + (L32 * VY(v)) + (L33 * VZ(v)));
        IR1 = Lm_B1(MAC1, lm);
        IR2 = Lm_B2(MAC2, lm);
        IR3 = Lm_B3(MAC3, lm);
        MAC1 = A1(int44((int64_t)RBK << 12) + (LR1 * IR1) + (LR2 * IR2) + (LR3 * IR3));
        MAC2 = A2(int44((int64_t)GBK << 12) + (LG1 * IR1) + (LG2 * IR2) + (LG3 * IR3));
        MAC3 = A3(int44((int64_t)BBK << 12) + (LB1 * IR1) + (LB2 * IR2) + (LB3 * IR3));
        IR1 = Lm_B1(MAC1, lm);
        IR2 = Lm_B2(MAC2, lm);
        IR3 = Lm_B3(MAC3, lm);
        MAC1 = A1(((R << 4) * IR1) + (IR0 * Lm_B1(A1(((int64_t)RFC << 12) - ((R << 4) * IR1)), 0)));
        MAC2 = A2(((G << 4) * IR2) + (IR0 * Lm_B2(A2(((int64_t)GFC << 12) - ((G << 4) * IR2)), 0)));
        MAC3 = A3(((B << 4) * IR3) + (IR0 * Lm_B3(A3(((int64_t)BFC << 12) - ((B << 4) * IR3)), 0)));
        IR1 = Lm_B1(MAC1, lm);
        IR2 = Lm_B2(MAC2, lm);
        IR3 = Lm_B3(MAC3, lm);
        RGB0 = RGB1;
        RGB1 = RGB2;
        CD2 = CODE;
        R2 = Lm_C1(MAC1 >> 4);
        G2 = Lm_C2(MAC2 >> 4);
        B2 = Lm_C3(MAC3 >> 4);
    }
}

void PCSX::GTE::NCCS(uint32_t op) {
    GTE_LOG("%08x GTE: NCCS|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    MAC1 = A1((int64_t)(L11 * VX0) + (L12 * VY0) + (L13 * VZ0));
    MAC2 = A2((int64_t)(L21 * VX0) + (L22 * VY0) + (L23 * VZ0));
    MAC3 = A3((int64_t)(L31 * VX0) + (L32 * VY0) + (L33 * VZ0));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    MAC1 = A1(int44((int64_t)RBK << 12) + (LR1 * IR1) + (LR2 * IR2) + (LR3 * IR3));
    MAC2 = A2(int44((int64_t)GBK << 12) + (LG1 * IR1) + (LG2 * IR2) + (LG3 * IR3));
    MAC3 = A3(int44((int64_t)BBK << 12) + (LB1 * IR1) + (LB2 * IR2) + (LB3 * IR3));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    MAC1 = A1((R << 4) * IR1);
    MAC2 = A2((G << 4) * IR2);
    MAC3 = A3((B << 4) * IR3);
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    RGB0 = RGB1;
    RGB1 = RGB2;
    CD2 = CODE;
    R2 = Lm_C1(MAC1 >> 4);
    G2 = Lm_C2(MAC2 >> 4);
    B2 = Lm_C3(MAC3 >> 4);
}

void PCSX::GTE::CC(uint32_t op) {
    GTE_LOG("%08x GTE: CC|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    GTE_LOG("%08x GTE: CC|", op);
    MAC1 = A1(int44(((int64_t)RBK) << 12) + (LR1 * IR1) + (LR2 * IR2) + (LR3 * IR3));
    MAC2 = A2(int44(((int64_t)GBK) << 12) + (LG1 * IR1) + (LG2 * IR2) + (LG3 * IR3));
    MAC3 = A3(int44(((int64_t)BBK) << 12) + (LB1 * IR1) + (LB2 * IR2) + (LB3 * IR3));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    MAC1 = A1((R << 4) * IR1);
    MAC2 = A2((G << 4) * IR2);
    MAC3 = A3((B << 4) * IR3);
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    RGB0 = RGB1;
    RGB1 = RGB2;
    CD2 = CODE;
    R2 = Lm_C1(MAC1 >> 4);
    G2 = Lm_C2(MAC2 >> 4);
    B2 = Lm_C3(MAC3 >> 4);
}

void PCSX::GTE::NCS(uint32_t op) {
    GTE_LOG("%08x GTE: NCS|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    MAC1 = A1((int64_t)(L11 * VX0) + (L12 * VY0) + (L13 * VZ0));
    MAC2 = A2((int64_t)(L21 * VX0) + (L22 * VY0) + (L23 * VZ0));
    MAC3 = A3((int64_t)(L31 * VX0) + (L32 * VY0) + (L33 * VZ0));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    MAC1 = A1(int44((int64_t)RBK << 12) + (LR1 * IR1) + (LR2 * IR2) + (LR3 * IR3));
    MAC2 = A2(int44((int64_t)GBK << 12) + (LG1 * IR1) + (LG2 * IR2) + (LG3 * IR3));
    MAC3 = A3(int44((int64_t)BBK << 12) + (LB1 * IR1) + (LB2 * IR2) + (LB3 * IR3));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    RGB0 = RGB1;
    RGB1 = RGB2;
    CD2 = CODE;
    R2 = Lm_C1(MAC1 >> 4);
    G2 = Lm_C2(MAC2 >> 4);
    B2 = Lm_C3(MAC3 >> 4);
}

void PCSX::GTE::NCT(uint32_t op) {
    GTE_LOG("%08x GTE: NCT|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    for (int v = 0; v < 3; v++) {
        MAC1 = A1((int64_t)(L11 * VX(v)) + (L12 * VY(v)) + (L13 * VZ(v)));
        MAC2 = A2((int64_t)(L21 * VX(v)) + (L22 * VY(v)) + (L23 * VZ(v)));
        MAC3 = A3((int64_t)(L31 * VX(v)) + (L32 * VY(v)) + (L33 * VZ(v)));
        IR1 = Lm_B1(MAC1, lm);
        IR2 = Lm_B2(MAC2, lm);
        IR3 = Lm_B3(MAC3, lm);
        MAC1 = A1(int44((int64_t)RBK << 12) + (LR1 * IR1) + (LR2 * IR2) + (LR3 * IR3));
        MAC2 = A2(int44((int64_t)GBK << 12) + (LG1 * IR1) + (LG2 * IR2) + (LG3 * IR3));
        MAC3 = A3(int44((int64_t)BBK << 12) + (LB1 * IR1) + (LB2 * IR2) + (LB3 * IR3));
        IR1 = Lm_B1(MAC1, lm);
        IR2 = Lm_B2(MAC2, lm);
        IR3 = Lm_B3(MAC3, lm);
        RGB0 = RGB1;
        RGB1 = RGB2;
        CD2 = CODE;
        R2 = Lm_C1(MAC1 >> 4);
        G2 = Lm_C2(MAC2 >> 4);
        B2 = Lm_C3(MAC3 >> 4);
    }
}

void PCSX::GTE::SQR(uint32_t op) {
    GTE_LOG("%08x GTE: SQR|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    MAC1 = A1(IR1 * IR1);
    MAC2 = A2(IR2 * IR2);
    MAC3 = A3(IR3 * IR3);
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
}

void PCSX::GTE::DCPL(uint32_t op) {
    GTE_LOG("%08x GTE: DCPL|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    MAC1 = A1(((R << 4) * IR1) + (IR0 * Lm_B1(A1(((int64_t)RFC << 12) - ((R << 4) * IR1)), 0)));
    MAC2 = A2(((G << 4) * IR2) + (IR0 * Lm_B2(A2(((int64_t)GFC << 12) - ((G << 4) * IR2)), 0)));
    MAC3 = A3(((B << 4) * IR3) + (IR0 * Lm_B3(A3(((int64_t)BFC << 12) - ((B << 4) * IR3)), 0)));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    RGB0 = RGB1;
    RGB1 = RGB2;
    CD2 = CODE;
    R2 = Lm_C1(MAC1 >> 4);
    G2 = Lm_C2(MAC2 >> 4);
    B2 = Lm_C3(MAC3 >> 4);
}

void PCSX::GTE::DPCT(uint32_t op) {
    GTE_LOG("%08x GTE: DPCT|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    for (int v = 0; v < 3; v++) {
        MAC1 = A1((R0 << 16) + (IR0 * Lm_B1(A1(((int64_t)RFC << 12) - (R0 << 16)), 0)));
        MAC2 = A2((G0 << 16) + (IR0 * Lm_B2(A2(((int64_t)GFC << 12) - (G0 << 16)), 0)));
        MAC3 = A3((B0 << 16) + (IR0 * Lm_B3(A3(((int64_t)BFC << 12) - (B0 << 16)), 0)));
        IR1 = Lm_B1(MAC1, lm);
        IR2 = Lm_B2(MAC2, lm);
        IR3 = Lm_B3(MAC3, lm);
        RGB0 = RGB1;
        RGB1 = RGB2;
        CD2 = CODE;
        R2 = Lm_C1(MAC1 >> 4);
        G2 = Lm_C2(MAC2 >> 4);
        B2 = Lm_C3(MAC3 >> 4);
    }
}

void PCSX::GTE::AVSZ3(uint32_t op) {
    GTE_LOG("%08x GTE: AVSZ3|", op);
    FLAG = 0;

    MAC0 = F((int64_t)(ZSF3 * SZ1) + (ZSF3 * SZ2) + (ZSF3 * SZ3));
    OTZ = Lm_D(s_mac0, 1);
}

void PCSX::GTE::AVSZ4(uint32_t op) {
    GTE_LOG("%08x GTE: AVSZ4|", op);
    FLAG = 0;

    MAC0 = F((int64_t)(ZSF4 * SZ0) + (ZSF4 * SZ1) + (ZSF4 * SZ2) + (ZSF4 * SZ3));
    OTZ = Lm_D(s_mac0, 1);
}

void PCSX::GTE::RTPT(uint32_t op) {
    GTE_LOG("%08x GTE: RTPT|", op);

    int32_t h_over_sz3;
    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    for (int v = 0; v < 3; v++) {
        MAC1 = A1(int44((int64_t)TRX << 12) + (R11 * VX(v)) + (R12 * VY(v)) + (R13 * VZ(v)));
        MAC2 = A2(int44((int64_t)TRY << 12) + (R21 * VX(v)) + (R22 * VY(v)) + (R23 * VZ(v)));
        MAC3 = A3(int44((int64_t)TRZ << 12) + (R31 * VX(v)) + (R32 * VY(v)) + (R33 * VZ(v)));
        IR1 = Lm_B1(MAC1, lm);
        IR2 = Lm_B2(MAC2, lm);
        IR3 = Lm_B3_sf(s_mac3, s_sf, lm);
        pushZ(Lm_D(s_mac3, 1));

        h_over_sz3 = gte_divide(H, SZ3);
        SXY0 = SXY1;
        SXY1 = SXY2;
        SX2 = Lm_G1(
            F((int64_t)OFX + ((int64_t)IR1 * h_over_sz3) * (PCSX::g_emulator->config().Widescreen ? 0.75 : 1)) >> 16);
        SY2 = Lm_G2(F((int64_t)OFY + ((int64_t)IR2 * h_over_sz3)) >> 16);

        PGXP_pushSXYZ2s(
            Lm_G1_ia((int64_t)OFX + (int64_t)(IR1 * h_over_sz3) * (PCSX::g_emulator->config().Widescreen ? 0.75 : 1)),
            Lm_G2_ia((int64_t)OFY + (int64_t)(IR2 * h_over_sz3)), std::max((int)SZ3, H / 2), SXY2);

        // PGXP_RTPS(v, SXY2);
    }

    MAC0 = F((int64_t)DQB + ((int64_t)DQA * h_over_sz3));
    IR0 = Lm_H(s_mac0, 1);
}

void PCSX::GTE::GPL(uint32_t op) {
    GTE_LOG("%08x GTE: GPL|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    MAC1 = A1(gte_shift_GPL(MAC1, s_sf) + (IR0 * IR1));
    MAC2 = A2(gte_shift_GPL(MAC2, s_sf) + (IR0 * IR2));
    MAC3 = A3(gte_shift_GPL(MAC3, s_sf) + (IR0 * IR3));
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    RGB0 = RGB1;
    RGB1 = RGB2;
    CD2 = CODE;
    R2 = Lm_C1(MAC1 >> 4);
    G2 = Lm_C2(MAC2 >> 4);
    B2 = Lm_C3(MAC3 >> 4);
}

void PCSX::GTE::GPF(uint32_t op) {
    GTE_LOG("%08x GTE: GPF|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    MAC1 = A1(IR0 * IR1);
    MAC2 = A2(IR0 * IR2);
    MAC3 = A3(IR0 * IR3);
    IR1 = Lm_B1(MAC1, lm);
    IR2 = Lm_B2(MAC2, lm);
    IR3 = Lm_B3(MAC3, lm);
    RGB0 = RGB1;
    RGB1 = RGB2;
    CD2 = CODE;
    R2 = Lm_C1(MAC1 >> 4);
    G2 = Lm_C2(MAC2 >> 4);
    B2 = Lm_C3(MAC3 >> 4);
}

void PCSX::GTE::NCCT(uint32_t op) {
    GTE_LOG("%08x GTE: NCCT|", op);

    const int lm = GTE_LM(gteop(op));
    s_sf = GTE_SF(gteop(op));
    FLAG = 0;

    for (int v = 0; v < 3; v++) {
        MAC1 = A1((int64_t)(L11 * VX(v)) + (L12 * VY(v)) + (L13 * VZ(v)));
        MAC2 = A2((int64_t)(L21 * VX(v)) + (L22 * VY(v)) + (L23 * VZ(v)));
        MAC3 = A3((int64_t)(L31 * VX(v)) + (L32 * VY(v)) + (L33 * VZ(v)));
        IR1 = Lm_B1(MAC1, lm);
        IR2 = Lm_B2(MAC2, lm);
        IR3 = Lm_B3(MAC3, lm);
        MAC1 = A1(int44((int64_t)RBK << 12) + (LR1 * IR1) + (LR2 * IR2) + (LR3 * IR3));
        MAC2 = A2(int44((int64_t)GBK << 12) + (LG1 * IR1) + (LG2 * IR2) + (LG3 * IR3));
        MAC3 = A3(int44((int64_t)BBK << 12) + (LB1 * IR1) + (LB2 * IR2) + (LB3 * IR3));
        IR1 = Lm_B1(MAC1, lm);
        IR2 = Lm_B2(MAC2, lm);
        IR3 = Lm_B3(MAC3, lm);
        MAC1 = A1((R << 4) * IR1);
        MAC2 = A2((G << 4) * IR2);
        MAC3 = A3((B << 4) * IR3);
        IR1 = Lm_B1(MAC1, lm);
        IR2 = Lm_B2(MAC2, lm);
        IR3 = Lm_B3(MAC3, lm);
        RGB0 = RGB1;
        RGB1 = RGB2;
        CD2 = CODE;
        R2 = Lm_C1(MAC1 >> 4);
        G2 = Lm_C2(MAC2 >> 4);
        B2 = Lm_C3(MAC3 >> 4);
    }
}
