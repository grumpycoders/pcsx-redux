/***************************************************************************
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#ifndef __R3000A_H__
#define __R3000A_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "psxbios.h"
#include "psxcommon.h"
#include "psxcounters.h"
#include "psxmem.h"

typedef struct {
    int (*Init)();
    void (*Reset)();
    void (*Execute)();      /* executes up to a break */
    void (*ExecuteBlock)(); /* executes up to a jump */
    void (*Clear)(u32 Addr, u32 Size);
    void (*Shutdown)();
    void (*SetPGXPMode)(u32 pgxpMode);
} R3000Acpu;

extern R3000Acpu *psxCpu;
extern R3000Acpu g_psxInt;
extern R3000Acpu g_psxRec;
#define PSXREC

typedef union {
#if defined(__BIGENDIAN__)
    struct {
        u8 h3, h2, h, l;
    } b;
    struct {
        s8 h3, h2, h, l;
    } sb;
    struct {
        u16 h, l;
    } w;
    struct {
        s16 h, l;
    } sw;
#else
    struct {
        u8 l, h, h2, h3;
    } b;
    struct {
        u16 l, h;
    } w;
    struct {
        s8 l, h, h2, h3;
    } sb;
    struct {
        s16 l, h;
    } sw;
#endif
    u32 d;
    s32 sd;
} PAIR;

typedef union {
    struct {
        u32 r0, at, v0, v1, a0, a1, a2, a3, t0, t1, t2, t3, t4, t5, t6, t7, s0, s1, s2, s3, s4, s5, s6, s7, t8, t9, k0,
            k1, gp, sp, s8, ra, lo, hi;
    } n;
    u32 r[34]; /* Lo, Hi in r[32] and r[33] */
    PAIR p[34];
} psxGPRRegs;

typedef union {
    struct {
        u32 Index, Random, EntryLo0, BPC, Context, BDA, PIDMask, DCIC, BadVAddr, BDAM, EntryHi, BPCM, Status, Cause,
            EPC, PRid, Config, LLAddr, WatchLO, WatchHI, XContext, Reserved1, Reserved2, Reserved3, Reserved4,
            Reserved5, ECC, CacheErr, TagLo, TagHi, ErrorEPC, Reserved6;
    } n;
    u32 r[32];
} psxCP0Regs;

typedef struct {
    short x, y;
} SVector2D;

typedef struct {
    short z, pad;
} SVector2Dz;

typedef struct {
    short x, y, z, pad;
} SVector3D;

typedef struct {
    short x, y, z, pad;
} LVector3D;

typedef struct {
    unsigned char r, g, b, c;
} CBGR;

typedef struct {
    short m11, m12, m13, m21, m22, m23, m31, m32, m33, pad;
} SMatrix3D;

typedef union {
    struct {
        SVector3D v0, v1, v2;
        CBGR rgb;
        s32 otz;
        s32 ir0, ir1, ir2, ir3;
        SVector2D sxy0, sxy1, sxy2, sxyp;
        SVector2Dz sz0, sz1, sz2, sz3;
        CBGR rgb0, rgb1, rgb2;
        s32 reserved;
        s32 mac0, mac1, mac2, mac3;
        u32 irgb, orgb;
        s32 lzcs, lzcr;
    } n;
    u32 r[32];
    PAIR p[32];
} psxCP2Data;

typedef union {
    struct {
        SMatrix3D rMatrix;
        s32 trX, trY, trZ;
        SMatrix3D lMatrix;
        s32 rbk, gbk, bbk;
        SMatrix3D cMatrix;
        s32 rfc, gfc, bfc;
        s32 ofx, ofy;
        s32 h;
        s32 dqa, dqb;
        s32 zsf3, zsf4;
        s32 flag;
    } n;
    u32 r[32];
    PAIR p[32];
} psxCP2Ctrl;

enum {
    PSXINT_SIO = 0,
    PSXINT_CDR,
    PSXINT_CDREAD,
    PSXINT_GPUDMA,
    PSXINT_MDECOUTDMA,
    PSXINT_SPUDMA,
    PSXINT_GPUBUSY,
    PSXINT_MDECINDMA,
    PSXINT_GPUOTCDMA,
    PSXINT_CDRDMA,
    PSXINT_SPUASYNC,
    PSXINT_CDRDBUF,
    PSXINT_CDRLID,
    PSXINT_CDRPLAY
};

typedef struct {
    psxGPRRegs GPR;  /* General Purpose Registers */
    psxCP0Regs CP0;  /* Coprocessor0 Registers */
    psxCP2Data CP2D; /* Cop2 data registers */
    psxCP2Ctrl CP2C; /* Cop2 control registers */
    u32 pc;          /* Program counter */
    u32 code;        /* The instruction */
    u32 cycle;
    u32 interrupt;
    struct {
        u32 sCycle, cycle;
    } intCycle[32];
    u8 ICache_Addr[0x1000];
    u8 ICache_Code[0x1000];
    boolean ICache_valid;
} psxRegisters;

extern psxRegisters g_psxRegs;

/*
Formula One 2001
- Use old CPU cache code when the RAM location is
  updated with new code (affects in-game racing)

TODO:
- I-cache / D-cache swapping
- Isolate D-cache from RAM
*/

static inline u32 *Read_ICache(u32 pc, boolean isolate) {
    u32 pc_bank, pc_offset, pc_cache;
    u8 *IAddr, *ICode;

    pc_bank = pc >> 24;
    pc_offset = pc & 0xffffff;
    pc_cache = pc & 0xfff;

    IAddr = g_psxRegs.ICache_Addr;
    ICode = g_psxRegs.ICache_Code;

    // clear I-cache
    if (!g_psxRegs.ICache_valid) {
        memset(g_psxRegs.ICache_Addr, 0xff, sizeof(g_psxRegs.ICache_Addr));
        memset(g_psxRegs.ICache_Code, 0xff, sizeof(g_psxRegs.ICache_Code));

        g_psxRegs.ICache_valid = TRUE;
    }

    // uncached
    if (pc_bank >= 0xa0) return (u32 *)PSXM(pc);

    // cached - RAM
    if (pc_bank == 0x80 || pc_bank == 0x00) {
        if (SWAP32(*(u32 *)(IAddr + pc_cache)) == pc_offset) {
            // Cache hit - return last opcode used
            return (u32 *)(ICode + pc_cache);
        } else {
            // Cache miss - addresses don't match
            // - default: 0xffffffff (not init)

            if (!isolate) {
                // cache line is 4 bytes wide
                pc_offset &= ~0xf;
                pc_cache &= ~0xf;

                // address line
                *(u32 *)(IAddr + pc_cache + 0x0) = SWAP32(pc_offset + 0x0);
                *(u32 *)(IAddr + pc_cache + 0x4) = SWAP32(pc_offset + 0x4);
                *(u32 *)(IAddr + pc_cache + 0x8) = SWAP32(pc_offset + 0x8);
                *(u32 *)(IAddr + pc_cache + 0xc) = SWAP32(pc_offset + 0xc);

                // opcode line
                pc_offset = pc & ~0xf;
                *(u32 *)(ICode + pc_cache + 0x0) = psxMu32ref(pc_offset + 0x0);
                *(u32 *)(ICode + pc_cache + 0x4) = psxMu32ref(pc_offset + 0x4);
                *(u32 *)(ICode + pc_cache + 0x8) = psxMu32ref(pc_offset + 0x8);
                *(u32 *)(ICode + pc_cache + 0xc) = psxMu32ref(pc_offset + 0xc);
            }

            // normal code
            return (u32 *)PSXM(pc);
        }
    }

    /*
    TODO: Probably should add cached BIOS
    */

    // default
    return (u32 *)PSXM(pc);
}

// U64 and S64 are used to wrap long integer constants.
#define U64(val) val##ULL
#define S64(val) val##LL

#if defined(__BIGENDIAN__)

#define _i32(x) *(s32 *)&x
#define _u32(x) x

#define _i16(x) (((short *)&x)[1])
#define _u16(x) (((unsigned short *)&x)[1])

#define _i8(x) (((char *)&x)[3])
#define _u8(x) (((unsigned char *)&x)[3])

#else

#define _i32(x) *(s32 *)&x
#define _u32(x) x

#define _i16(x) *(short *)&x
#define _u16(x) *(unsigned short *)&x

#define _i8(x) *(char *)&x
#define _u8(x) *(unsigned char *)&x

#endif

/**** R3000A Instruction Macros ****/
#define _PC_ g_psxRegs.pc  // The next PC to be executed

#define _fOp_(code) ((code >> 26))           // The opcode part of the instruction register
#define _fFunct_(code) ((code)&0x3F)         // The funct part of the instruction register
#define _fRd_(code) ((code >> 11) & 0x1F)    // The rd part of the instruction register
#define _fRt_(code) ((code >> 16) & 0x1F)    // The rt part of the instruction register
#define _fRs_(code) ((code >> 21) & 0x1F)    // The rs part of the instruction register
#define _fSa_(code) ((code >> 6) & 0x1F)     // The sa part of the instruction register
#define _fIm_(code) ((u16)code)              // The immediate part of the instruction register
#define _fTarget_(code) (code & 0x03ffffff)  // The target part of the instruction register

#define _fImm_(code) ((s16)code)       // sign-extended immediate
#define _fImmU_(code) (code & 0xffff)  // zero-extended immediate
#define _fImmLU_(code) (code << 16)    // LUI

#define _Op_ _fOp_(g_psxRegs.code)
#define _Funct_ _fFunct_(g_psxRegs.code)
#define _Rd_ _fRd_(g_psxRegs.code)
#define _Rt_ _fRt_(g_psxRegs.code)
#define _Rs_ _fRs_(g_psxRegs.code)
#define _Sa_ _fSa_(g_psxRegs.code)
#define _Im_ _fIm_(g_psxRegs.code)
#define _Target_ _fTarget_(g_psxRegs.code)

#define _Imm_ _fImm_(g_psxRegs.code)
#define _ImmU_ _fImmU_(g_psxRegs.code)
#define _ImmLU_ _fImmLU_(g_psxRegs.code)

#define _rRs_ g_psxRegs.GPR.r[_Rs_]  // Rs register
#define _rRt_ g_psxRegs.GPR.r[_Rt_]  // Rt register
#define _rRd_ g_psxRegs.GPR.r[_Rd_]  // Rd register
#define _rSa_ g_psxRegs.GPR.r[_Sa_]  // Sa register
#define _rFs_ g_psxRegs.CP0.r[_Rd_]  // Fs register

#define _c2dRs_ g_psxRegs.CP2D.r[_Rs_]  // Rs cop2 data register
#define _c2dRt_ g_psxRegs.CP2D.r[_Rt_]  // Rt cop2 data register
#define _c2dRd_ g_psxRegs.CP2D.r[_Rd_]  // Rd cop2 data register
#define _c2dSa_ g_psxRegs.CP2D.r[_Sa_]  // Sa cop2 data register

#define _rHi_ g_psxRegs.GPR.n.hi  // The HI register
#define _rLo_ g_psxRegs.GPR.n.lo  // The LO register

#define _JumpTarget_ ((_Target_ * 4) + (_PC_ & 0xf0000000))  // Calculates the target during a jump instruction
#define _BranchTarget_ ((s16)_Im_ * 4 + _PC_)                // Calculates the target during a branch instruction

#define _SetLink(x) g_psxRegs.GPR.r[x] = _PC_ + 4;  // Sets the return address in the link register

int psxInit();
void psxReset();
void psxShutdown();
void psxException(u32 code, u32 bd);
void psxBranchTest();
void psxExecuteBios();
int psxTestLoadDelay(int reg, u32 tmp);
void psxDelayTest(int reg, u32 bpc);
void psxTestSWInts();
void psxJumpTest();

void psxSetPGXPMode(u32 pgxpMode);

#ifdef __cplusplus
}
#endif
#endif
