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

/*
 * R3000A disassembler.
 */

#include "core/psxemulator.h"
#include "core/r3000a.h"

static char s_ostr[512];

// Names of registers
const char *g_disRNameGPR[] = {
    "r0", "at", "v0", "v1", "a0", "a1", "a2", "a3",  // 00
    "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",  // 08
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",  // 10
    "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",  // 18
};

const char *g_disRNameCP2D[] = {
    "vxy0", "vz0",  "vxy1", "vz1",  "vxy2", "vz2",  "rgb",  "otz",   // 00
    "ir0",  "ir1",  "ir2",  "ir3",  "sxy0", "sxy1", "sxy2", "sxyp",  // 08
    "sz0",  "sz1",  "sz2",  "sz3",  "rgb0", "rgb1", "rgb2", "res1",  // 10
    "mac0", "mac1", "mac2", "mac3", "irgb", "orgb", "lzcs", "lzcr",  // 18
};

const char *g_disRNameCP2C[] = {
    "r11r12", "r13r21", "r22r23", "r31r32", "r33", "trx",  "try",  "trz",   // 00
    "l11l12", "l13l21", "l22l23", "l31l32", "l33", "rbk",  "bbk",  "gbk",   // 08
    "lr1lr2", "lr3lg1", "lg2lg3", "lb1lb2", "lb3", "rfc",  "gfc",  "bfc",   // 10
    "ofx",    "ofy",    "h",      "dqa",    "dqb", "zsf3", "zsf4", "flag",  // 18
};

const char *g_disRNameCP0[] = {
    "Index",    "Random",   "EntryLo0", "EntryLo1",  // 00
    "Context",  "PageMask", "Wired",    "+Checkme",  // 04
    "BadVAddr", "Count",    "EntryHi",  "Compare",   // 08
    "Status",   "Cause",    "ExceptPC", "PRevID",    // 0c
    "Config",   "LLAddr",   "WatchLo",  "WatchHi",   // 10
    "XContext", "*RES*",    "*RES*",    "*RES*",     // 14
    "*RES*",    "*RES*",    "PErr",     "CacheErr",  // 18
    "TagLo",    "TagHi",    "ErrorEPC", "*RES*",     // 1c
};

// Type definition of our functions

typedef const char *(*TdisR3000AF)(uint32_t code, uint32_t pc);

// These macros are used to assemble the disassembler functions
#define MakeDisFg(fn, b)                         \
    const char *fn(uint32_t code, uint32_t pc) { \
        b;                                       \
        return s_ostr;                           \
    }
#define MakeDisF(fn, b)                                 \
    static const char *fn(uint32_t code, uint32_t pc) { \
        sprintf(s_ostr, "%8.8x %8.8x:", pc, code);      \
        b; /*s_ostr[(strlen(s_ostr) - 1)] = 0;*/        \
        return s_ostr;                                  \
    }

#undef _Funct_
#undef _Rd_
#undef _Rt_
#undef _Rs_
#undef _Sa_
#undef _Im_
#undef _Target_

#define _Funct_ ((code)&0x3F)       // The funct part of the instruction register
#define _Rd_ ((code >> 11) & 0x1F)  // The rd part of the instruction register
#define _Rt_ ((code >> 16) & 0x1F)  // The rt part of the instruction register
#define _Rs_ ((code >> 21) & 0x1F)  // The rs part of the instruction register
#define _Sa_ ((code >> 6) & 0x1F)   // The sa part of the instruction register
#define _Im_ (code & 0xFFFF)        // The immediate part of the instruction register

#define _Target_ ((pc & 0xf0000000) + ((code & 0x03ffffff) * 4))
#define _Branch_ (pc + 4 + ((short)_Im_ * 4))
#define _OfB_ _Im_, _nRs_

#define dName(i) sprintf(s_ostr, "%s %-7s", s_ostr, i)
#define dGPR(i) \
    sprintf(s_ostr, "%s %s,", s_ostr, g_disRNameGPR[i])
#define dCP0(i) \
    sprintf(s_ostr, "%s %s,", s_ostr, g_disRNameCP0[i])
#define dCP2D(i) \
    sprintf(s_ostr, "%s %s,", s_ostr, g_disRNameCP2D[i])
#define dCP2C(i) \
    sprintf(s_ostr, "%s %s,", s_ostr, g_disRNameCP2C[i])
#define dHI() sprintf(s_ostr, "%s hi,", s_ostr)
#define dLO() sprintf(s_ostr, "%s lo,", s_ostr)
#define dImm() sprintf(s_ostr, "%s 0x%4.4x,", s_ostr, _Im_)
#define dTarget() sprintf(s_ostr, "%s 0x%8.8x,", s_ostr, _Target_)
#define dSa() sprintf(s_ostr, "%s 0x%2.2x,", s_ostr, _Sa_)
#define dOfB()                                                                                                \
    sprintf(s_ostr, "%s 0x%4.4x (%s),", s_ostr, _Im_, \
            g_disRNameGPR[_Rs_])
#define dOffset() sprintf(s_ostr, "%s 0x%8.8x,", s_ostr, _Branch_)
#define dCode() sprintf(s_ostr, "%s 0x%8.8x,", s_ostr, (code >> 6) & 0xffffff)

/*********************************************************
 * Arithmetic with immediate operand                      *
 * Format:  OP rt, rs, immediate                          *
 *********************************************************/
MakeDisF(disADDI, dName("addi"); dGPR(_Rt_); dGPR(_Rs_); dImm(););
MakeDisF(disADDIU, dName("addiu"); dGPR(_Rt_); dGPR(_Rs_); dImm(););
MakeDisF(disANDI, dName("andi"); dGPR(_Rt_); dGPR(_Rs_); dImm(););
MakeDisF(disORI, dName("ori"); dGPR(_Rt_); dGPR(_Rs_); dImm(););
MakeDisF(disSLTI, dName("slti"); dGPR(_Rt_); dGPR(_Rs_); dImm(););
MakeDisF(disSLTIU, dName("sltiu"); dGPR(_Rt_); dGPR(_Rs_); dImm(););
MakeDisF(disXORI, dName("xori"); dGPR(_Rt_); dGPR(_Rs_); dImm(););

/*********************************************************
 * Register arithmetic                                    *
 * Format:  OP rd, rs, rt                                 *
 *********************************************************/
MakeDisF(disADD, dName("add"); dGPR(_Rd_); dGPR(_Rs_); dGPR(_Rt_););
MakeDisF(disADDU, dName("addu"); dGPR(_Rd_); dGPR(_Rs_); dGPR(_Rt_););
MakeDisF(disAND, dName("and"); dGPR(_Rd_); dGPR(_Rs_); dGPR(_Rt_););
MakeDisF(disNOR, dName("nor"); dGPR(_Rd_); dGPR(_Rs_); dGPR(_Rt_););
MakeDisF(disOR, dName("or"); dGPR(_Rd_); dGPR(_Rs_); dGPR(_Rt_););
MakeDisF(disSLT, dName("slt"); dGPR(_Rd_); dGPR(_Rs_); dGPR(_Rt_););
MakeDisF(disSLTU, dName("sltu"); dGPR(_Rd_); dGPR(_Rs_); dGPR(_Rt_););
MakeDisF(disSUB, dName("sub"); dGPR(_Rd_); dGPR(_Rs_); dGPR(_Rt_););
MakeDisF(disSUBU, dName("subu"); dGPR(_Rd_); dGPR(_Rs_); dGPR(_Rt_););
MakeDisF(disXOR, dName("xor"); dGPR(_Rd_); dGPR(_Rs_); dGPR(_Rt_););

/*********************************************************
 * Register arithmetic & Register trap logic              *
 * Format:  OP rs, rt                                     *
 *********************************************************/
MakeDisF(disDIV, dName("div"); dGPR(_Rs_); dGPR(_Rt_););
MakeDisF(disDIVU, dName("divu"); dGPR(_Rs_); dGPR(_Rt_););
MakeDisF(disMULT, dName("mult"); dGPR(_Rs_); dGPR(_Rt_););
MakeDisF(disMULTU, dName("multu"); dGPR(_Rs_); dGPR(_Rt_););

/*********************************************************
 * Register branch logic                                  *
 * Format:  OP rs, offset                                 *
 *********************************************************/
MakeDisF(disBGEZ, dName("bgez"); dGPR(_Rs_); dOffset(););
MakeDisF(disBGEZAL, dName("bgezal"); dGPR(_Rs_); dOffset(););
MakeDisF(disBGTZ, dName("bgtz"); dGPR(_Rs_); dOffset(););
MakeDisF(disBLEZ, dName("blez"); dGPR(_Rs_); dOffset(););
MakeDisF(disBLTZ, dName("bltz"); dGPR(_Rs_); dOffset(););
MakeDisF(disBLTZAL, dName("bltzal"); dGPR(_Rs_); dOffset(););

/*********************************************************
 * Shift arithmetic with constant shift                   *
 * Format:  OP rd, rt, sa                                 *
 *********************************************************/
MakeDisF(disSLL,
         if (code) {
             dName("sll");
             dGPR(_Rd_);
             dGPR(_Rt_);
             dSa();
         } else { dName("nop"); });
MakeDisF(disSRA, dName("sra"); dGPR(_Rd_); dGPR(_Rt_); dSa(););
MakeDisF(disSRL, dName("srl"); dGPR(_Rd_); dGPR(_Rt_); dSa(););

/*********************************************************
 * Shift arithmetic with variant register shift           *
 * Format:  OP rd, rt, rs                                 *
 *********************************************************/
MakeDisF(disSLLV, dName("sllv"); dGPR(_Rd_); dGPR(_Rt_); dGPR(_Rs_););
MakeDisF(disSRAV, dName("srav"); dGPR(_Rd_); dGPR(_Rt_); dGPR(_Rs_););
MakeDisF(disSRLV, dName("srlv"); dGPR(_Rd_); dGPR(_Rt_); dGPR(_Rs_););

/*********************************************************
 * Load higher 16 bits of the first word in GPR with imm  *
 * Format:  OP rt, immediate                              *
 *********************************************************/
MakeDisF(disLUI, dName("lui"); dGPR(_Rt_); dImm(););

/*********************************************************
 * Move from HI/LO to GPR                                 *
 * Format:  OP rd                                         *
 *********************************************************/
MakeDisF(disMFHI, dName("mfhi"); dGPR(_Rd_); dHI(););
MakeDisF(disMFLO, dName("mflo"); dGPR(_Rd_); dLO(););

/*********************************************************
 * Move from GPR to HI/LO                                 *
 * Format:  OP rd                                         *
 *********************************************************/
MakeDisF(disMTHI, dName("mthi"); dHI(); dGPR(_Rs_););
MakeDisF(disMTLO, dName("mtlo"); dLO(); dGPR(_Rs_););

/*********************************************************
 * Special purpose instructions                           *
 * Format:  OP                                            *
 *********************************************************/
MakeDisF(disBREAK, dName("break"));
MakeDisF(disRFE, dName("rfe"));
MakeDisF(disSYSCALL, dName("syscall"));
MakeDisF(disHLE, dName("hle"));

MakeDisF(disRTPS, dName("rtps"));
MakeDisF(disOP, dName("op"));
MakeDisF(disNCLIP, dName("nclip"));
MakeDisF(disDPCS, dName("dpcs"));
MakeDisF(disINTPL, dName("intpl"));
MakeDisF(disMVMVA, dName("mvmva"));
MakeDisF(disNCDS, dName("ncds"));
MakeDisF(disCDP, dName("cdp"));
MakeDisF(disNCDT, dName("ncdt"));
MakeDisF(disNCCS, dName("nccs"));
MakeDisF(disCC, dName("cc"));
MakeDisF(disNCS, dName("ncs"));
MakeDisF(disNCT, dName("nct"));
MakeDisF(disSQR, dName("sqr"));
MakeDisF(disDCPL, dName("dcpl"));
MakeDisF(disDPCT, dName("dpct"));
MakeDisF(disAVSZ3, dName("avsz3"));
MakeDisF(disAVSZ4, dName("avsz4"));
MakeDisF(disRTPT, dName("rtpt"));
MakeDisF(disGPF, dName("gpf"));
MakeDisF(disGPL, dName("gpl"));
MakeDisF(disNCCT, dName("ncct"));

MakeDisF(disMFC2, dName("mfc2"); dGPR(_Rt_); dCP2C(_Rd_););
MakeDisF(disMTC2, dName("mtc2"); dCP2C(_Rd_); dGPR(_Rt_););
MakeDisF(disCFC2, dName("cfc2"); dGPR(_Rt_); dCP2C(_Rd_););
MakeDisF(disCTC2, dName("ctc2"); dCP2C(_Rd_); dGPR(_Rt_););

/*********************************************************
 * Register branch logic                                  *
 * Format:  OP rs, rt, offset                             *
 *********************************************************/
MakeDisF(disBEQ, dName("beq"); dGPR(_Rs_); dGPR(_Rt_); dOffset(););
MakeDisF(disBNE, dName("bne"); dGPR(_Rs_); dGPR(_Rt_); dOffset(););

/*********************************************************
 * Jump to target                                         *
 * Format:  OP target                                     *
 *********************************************************/
MakeDisF(disJ, dName("j"); dTarget(););
MakeDisF(disJAL, dName("jal"); dTarget(););

/*********************************************************
 * Register jump                                          *
 * Format:  OP rs, rd                                     *
 *********************************************************/
MakeDisF(disJR, dName("jr"); dGPR(_Rs_););
MakeDisF(disJALR, dName("jalr"); dGPR(_Rs_); dGPR(_Rd_));

/*********************************************************
 * Load and store for GPR                                 *
 * Format:  OP rt, offset(base)                           *
 *********************************************************/
MakeDisF(disLB, dName("lb"); dGPR(_Rt_); dOfB(););
MakeDisF(disLBU, dName("lbu"); dGPR(_Rt_); dOfB(););
MakeDisF(disLH, dName("lh"); dGPR(_Rt_); dOfB(););
MakeDisF(disLHU, dName("lhu"); dGPR(_Rt_); dOfB(););
MakeDisF(disLW, dName("lw"); dGPR(_Rt_); dOfB(););
MakeDisF(disLWL, dName("lwl"); dGPR(_Rt_); dOfB(););
MakeDisF(disLWR, dName("lwr"); dGPR(_Rt_); dOfB(););
MakeDisF(disLWC2, dName("lwc2"); dCP2D(_Rt_); dOfB(););
MakeDisF(disSB, dName("sb"); dGPR(_Rt_); dOfB(););
MakeDisF(disSH, dName("sh"); dGPR(_Rt_); dOfB(););
MakeDisF(disSW, dName("sw"); dGPR(_Rt_); dOfB(););
MakeDisF(disSWL, dName("swl"); dGPR(_Rt_); dOfB(););
MakeDisF(disSWR, dName("swr"); dGPR(_Rt_); dOfB(););
MakeDisF(disSWC2, dName("swc2"); dCP2D(_Rt_); dOfB(););

/*********************************************************
 * Moves between GPR and COPx                             *
 * Format:  OP rt, fs                                     *
 *********************************************************/
MakeDisF(disMFC0, dName("mfc0"); dGPR(_Rt_); dCP0(_Rd_););
MakeDisF(disMTC0, dName("mtc0"); dCP0(_Rd_); dGPR(_Rt_););
MakeDisF(disCFC0, dName("cfc0"); dGPR(_Rt_); dCP0(_Rd_););
MakeDisF(disCTC0, dName("ctc0"); dCP0(_Rd_); dGPR(_Rt_););

/*********************************************************
 * Unknow instruction (would generate an exception)       *
 * Format:  ?                                             *
 *********************************************************/
MakeDisF(disNULL, dName("*** Bad OP ***"););

TdisR3000AF disR3000A_SPECIAL[] = {
    // Subset of disSPECIAL
    disSLL,  disNULL,  disSRL,  disSRA,  disSLLV,    disNULL,  disSRLV, disSRAV,  // 00
    disJR,   disJALR,  disNULL, disNULL, disSYSCALL, disBREAK, disNULL, disNULL,  // 08
    disMFHI, disMTHI,  disMFLO, disMTLO, disNULL,    disNULL,  disNULL, disNULL,  // 10
    disMULT, disMULTU, disDIV,  disDIVU, disNULL,    disNULL,  disNULL, disNULL,  // 18
    disADD,  disADDU,  disSUB,  disSUBU, disAND,     disOR,    disXOR,  disNOR,   // 20
    disNULL, disNULL,  disSLT,  disSLTU, disNULL,    disNULL,  disNULL, disNULL,  // 28
    disNULL, disNULL,  disNULL, disNULL, disNULL,    disNULL,  disNULL, disNULL,  // 30
    disNULL, disNULL,  disNULL, disNULL, disNULL,    disNULL,  disNULL, disNULL,  // 38
};

MakeDisF(disSPECIAL, disR3000A_SPECIAL[_Funct_](code, pc));

TdisR3000AF disR3000A_BCOND[] = {
    // Subset of disBCOND
    disBLTZ,   disBGEZ,   disNULL, disNULL, disNULL, disNULL, disNULL, disNULL,  // 00
    disNULL,   disNULL,   disNULL, disNULL, disNULL, disNULL, disNULL, disNULL,  // 08
    disBLTZAL, disBGEZAL, disNULL, disNULL, disNULL, disNULL, disNULL, disNULL,  // 10
    disNULL,   disNULL,   disNULL, disNULL, disNULL, disNULL, disNULL, disNULL,  // 18
};

MakeDisF(disBCOND, disR3000A_BCOND[_Rt_](code, pc));

TdisR3000AF disR3000A_COP0[] = {
    // Subset of disCOP0
    disMFC0, disNULL, disCFC0, disNULL, disMTC0, disNULL, disCTC0, disNULL,  // 00
    disNULL, disNULL, disNULL, disNULL, disNULL, disNULL, disNULL, disNULL,  // 08
    disRFE,  disNULL, disNULL, disNULL, disNULL, disNULL, disNULL, disNULL,  // 10
    disNULL, disNULL, disNULL, disNULL, disNULL, disNULL, disNULL, disNULL,  // 18
};

MakeDisF(disCOP0, disR3000A_COP0[_Rs_](code, pc));

TdisR3000AF disR3000A_BASIC[] = {
    // Subset of disBASIC (based on rs)
    disMFC2, disNULL, disCFC2, disNULL, disMTC2, disNULL, disCTC2, disNULL,  // 00
    disNULL, disNULL, disNULL, disNULL, disNULL, disNULL, disNULL, disNULL,  // 08
    disNULL, disNULL, disNULL, disNULL, disNULL, disNULL, disNULL, disNULL,  // 10
    disNULL, disNULL, disNULL, disNULL, disNULL, disNULL, disNULL, disNULL,  // 18
};

MakeDisF(disBASIC, disR3000A_BASIC[_Rs_](code, pc));

TdisR3000AF disR3000A_COP2[] = {
    // Subset of disR3000F_COP2 (based on funct)
    disBASIC, disRTPS,  disNULL,  disNULL, disNULL, disNULL,  disNCLIP, disNULL,  // 00
    disNULL,  disNULL,  disNULL,  disNULL, disOP,   disNULL,  disNULL,  disNULL,  // 08
    disDPCS,  disINTPL, disMVMVA, disNCDS, disCDP,  disNULL,  disNCDT,  disNULL,  // 10
    disNULL,  disNULL,  disNULL,  disNCCS, disCC,   disNULL,  disNCS,   disNULL,  // 18
    disNCT,   disNULL,  disNULL,  disNULL, disNULL, disNULL,  disNULL,  disNULL,  // 20
    disSQR,   disDCPL,  disDPCT,  disNULL, disNULL, disAVSZ3, disAVSZ4, disNULL,  // 28
    disRTPT,  disNULL,  disNULL,  disNULL, disNULL, disNULL,  disNULL,  disNULL,  // 30
    disNULL,  disNULL,  disNULL,  disNULL, disNULL, disGPF,   disGPL,   disNCCT,  // 38
};

MakeDisF(disCOP2, disR3000A_COP2[_Funct_](code, pc));

TdisR3000AF disR3000A[] = {
    disSPECIAL, disBCOND, disJ,    disJAL,   disBEQ,  disBNE,  disBLEZ, disBGTZ,  // 00
    disADDI,    disADDIU, disSLTI, disSLTIU, disANDI, disORI,  disXORI, disLUI,   // 08
    disCOP0,    disNULL,  disCOP2, disNULL,  disNULL, disNULL, disNULL, disNULL,  // 10
    disNULL,    disNULL,  disNULL, disNULL,  disNULL, disNULL, disNULL, disNULL,  // 18
    disLB,      disLH,    disLWL,  disLW,    disLBU,  disLHU,  disLWR,  disNULL,  // 20
    disSB,      disSH,    disSWL,  disSW,    disNULL, disNULL, disSWR,  disNULL,  // 28
    disNULL,    disNULL,  disLWC2, disNULL,  disNULL, disNULL, disNULL, disNULL,  // 30
    disNULL,    disNULL,  disSWC2, disHLE,   disNULL, disNULL, disNULL, disNULL,  // 38
};

MakeDisFg(disR3000AF, disR3000A[code >> 26](code, pc));
