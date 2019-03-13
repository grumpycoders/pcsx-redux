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

#include <stdarg.h>

#include "core/disr3000a.h"
#include "core/psxemulator.h"
#include "core/r3000a.h"

// Names of registers
const char *PCSX::Disasm::s_disRNameGPR[] = {
    "r0", "at", "v0", "v1", "a0", "a1", "a2", "a3",  // 00
    "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",  // 08
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",  // 10
    "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",  // 18
};

const char *PCSX::Disasm::s_disRNameCP2D[] = {
    "vxy0", "vz0",  "vxy1", "vz1",  "vxy2", "vz2",  "rgb",  "otz",   // 00
    "ir0",  "ir1",  "ir2",  "ir3",  "sxy0", "sxy1", "sxy2", "sxyp",  // 08
    "sz0",  "sz1",  "sz2",  "sz3",  "rgb0", "rgb1", "rgb2", "res1",  // 10
    "mac0", "mac1", "mac2", "mac3", "irgb", "orgb", "lzcs", "lzcr",  // 18
};

const char *PCSX::Disasm::s_disRNameCP2C[] = {
    "r11r12", "r13r21", "r22r23", "r31r32", "r33", "trx",  "try",  "trz",   // 00
    "l11l12", "l13l21", "l22l23", "l31l32", "l33", "rbk",  "bbk",  "gbk",   // 08
    "lr1lr2", "lr3lg1", "lg2lg3", "lb1lb2", "lb3", "rfc",  "gfc",  "bfc",   // 10
    "ofx",    "ofy",    "h",      "dqa",    "dqb", "zsf3", "zsf4", "flag",  // 18
};

const char *PCSX::Disasm::s_disRNameCP0[] = {
    "Index",    "Random",   "EntryLo0", "EntryLo1",  // 00
    "Context",  "PageMask", "Wired",    "+Checkme",  // 04
    "BadVAddr", "Count",    "EntryHi",  "Compare",   // 08
    "Status",   "Cause",    "ExceptPC", "PRevID",    // 0c
    "Config",   "LLAddr",   "WatchLo",  "WatchHi",   // 10
    "XContext", "*RES*",    "*RES*",    "*RES*",     // 14
    "*RES*",    "*RES*",    "PErr",     "CacheErr",  // 18
    "TagLo",    "TagHi",    "ErrorEPC", "*RES*",     // 1c
};

#undef declare
#undef _Funct_
#undef _Rd_
#undef _Rt_
#undef _Rs_
#undef _Sa_
#undef _Im_
#undef _Target_

#define declare(n) void PCSX::Disasm::n(uint32_t code, uint32_t nextCode, uint32_t pc, bool *skipNext)
#define _Funct_ ((code)&0x3F)       // The funct part of the instruction register
#define _Rd_ ((code >> 11) & 0x1F)  // The rd part of the instruction register
#define _Rt_ ((code >> 16) & 0x1F)  // The rt part of the instruction register
#define _Rs_ ((code >> 21) & 0x1F)  // The rs part of the instruction register
#define _Sa_ ((code >> 6) & 0x1F)   // The sa part of the instruction register
#define _Im_ (code & 0xFFFF)        // The immediate part of the instruction register

#define _Target_ ((pc & 0xf0000000) + ((code & 0x03ffffff) * 4))
#define _Branch_ (pc + 4 + ((short)_Im_ * 4))
#define _OfB_ _Im_, _nRs_

namespace {
struct StringDisasm : public PCSX::Disasm {
    void append(const char *str, ...) {
        va_list va;
        va_start(va, str);
        char buf[64];
        std::vsnprintf(buf, 64, str, va);
        va_end(va);
        size_t len = strlen(buf);
        memcpy(m_buf + m_len, buf, len + 1);
        m_len += len;
    }
    void comma() {
        if (m_gotArg) append(", ");
        m_gotArg = true;
    }
    virtual void OpCode(const char *name) final {
        std::sprintf(m_buf, "%-7s", name);
        m_gotArg = false;
        m_len = 7;
    }
    virtual void GPR(uint8_t reg) final {
        comma();
        append(s_disRNameGPR[reg]);
    }
    virtual void CP0(uint8_t reg) final {
        comma();
        append(s_disRNameCP0[reg]);
    }
    virtual void CP2D(uint8_t reg) final {
        comma();
        append(s_disRNameCP2D[reg]);
    }
    virtual void CP2C(uint8_t reg) final {
        comma();
        append(s_disRNameCP2C[reg]);
    }
    virtual void HI() final {
        comma();
        append("hi");
    }
    virtual void LO() final {
        comma();
        append("lo");
    }
    virtual void Imm(uint16_t value) final {
        comma();
        append("0x%4.4x", value);
    }
    virtual void Imm32(uint32_t value) final {
        comma();
        append("0x%8.8x", value);
    }
    virtual void Target(uint32_t value) final {
        comma();
        append("0x%8.8x", value);
    }
    virtual void Sa(uint8_t value) final {
        comma();
        append("0x%2.2x", value);
    }
    virtual void OfB(uint16_t offset, uint8_t reg) {
        comma();
        append("%s[0x%4.4x]", s_disRNameGPR[reg], offset);
    }
    virtual void Offset(uint32_t value) final {
        comma();
        append("0x%8.8x", value);
    }
    virtual void reset() final {
        m_buf[0] = 0;
        m_len = 0;
    }
    char m_buf[512];
    size_t m_len = 0;
    bool m_gotArg = false;

  public:
    std::string get() { return m_buf; }
};
}  // namespace

#define dOpCode(i) \
    do {           \
        reset();   \
        OpCode(i); \
    } while (0)
#define dGPR(i) GPR(i);
#define dCP0(i) CP0(i)
#define dCP2D(i) CP2D(i)
#define dCP2C(i) CP2C(i)
#define dHI() HI()
#define dLO() LO()
#define dImm() Imm(_Im_)
#define dTarget() Target(_Target_)
#define dSa() Sa(_Sa_)
#define dOfB() OfB(_Im_, _Rs_)
#define dOffset() Offset(_Branch_)

/*********************************************************
 * Arithmetic with immediate operand                      *
 * Format:  OP rt, rs, immediate                          *
 *********************************************************/
declare(disADDI) {
    dOpCode("addi");
    if (_Rt_ == _Rs_) {
        dGPR(_Rt_);
    } else {
        dGPR(_Rt_);
        dGPR(_Rs_);
    }
    dImm();
}
declare(disADDIU) {
    dOpCode("addiu");
    if (_Rt_ == _Rs_) {
        dGPR(_Rt_);
    } else {
        dGPR(_Rt_);
        dGPR(_Rs_);
    }
    dImm();
}
declare(disANDI) {
    dOpCode("andi");
    if (_Rt_ == _Rs_) {
        dGPR(_Rt_);
    } else {
        dGPR(_Rt_);
        dGPR(_Rs_);
    }
    dImm();
}
declare(disORI) {
    dOpCode("ori");
    if (_Rt_ == _Rs_) {
        dGPR(_Rt_);
    } else {
        dGPR(_Rt_);
        dGPR(_Rs_);
    }
    dImm();
}
declare(disSLTI) {
    dOpCode("slti");
    if (_Rt_ == _Rs_) {
        dGPR(_Rt_);
    } else {
        dGPR(_Rt_);
        dGPR(_Rs_);
    }
    dImm();
}
declare(disSLTIU) {
    dOpCode("sltiu");
    if (_Rt_ == _Rs_) {
        dGPR(_Rt_);
    } else {
        dGPR(_Rt_);
        dGPR(_Rs_);
    }
    dImm();
}
declare(disXORI) {
    dOpCode("xori");
    if (_Rt_ == _Rs_) {
        dGPR(_Rt_);
    } else {
        dGPR(_Rt_);
        dGPR(_Rs_);
    }
    dImm();
}

/*********************************************************
 * Register arithmetic                                    *
 * Format:  OP rd, rs, rt                                 *
 *********************************************************/
declare(disADD) {
    dOpCode("add");
    if (_Rd_ == _Rs_) {
        dGPR(_Rd_);
    } else {
        dGPR(_Rd_);
        dGPR(_Rs_);
    }
    dGPR(_Rt_);
}
declare(disADDU) {
    dOpCode("addu");
    if (_Rd_ == _Rs_) {
        dGPR(_Rd_);
    } else {
        dGPR(_Rd_);
        dGPR(_Rs_);
    }

    dGPR(_Rt_);
}
declare(disAND) {
    dOpCode("and");
    if (_Rd_ == _Rs_) {
        dGPR(_Rd_);
    } else {
        dGPR(_Rd_);
        dGPR(_Rs_);
    }

    dGPR(_Rt_);
}
declare(disNOR) {
    dOpCode("nor");
    if (_Rd_ == _Rs_) {
        dGPR(_Rd_);
    } else {
        dGPR(_Rd_);
        dGPR(_Rs_);
    }

    dGPR(_Rt_);
}
declare(disOR) {
    dOpCode("or");
    if (_Rd_ == _Rs_) {
        dGPR(_Rd_);
    } else {
        dGPR(_Rd_);
        dGPR(_Rs_);
    }

    dGPR(_Rt_);
}
declare(disSLT) {
    dOpCode("slt");
    if (_Rd_ == _Rs_) {
        dGPR(_Rd_);
    } else {
        dGPR(_Rd_);
        dGPR(_Rs_);
    }

    dGPR(_Rt_);
}
declare(disSLTU) {
    dOpCode("sltu");
    if (_Rd_ == _Rs_) {
        dGPR(_Rd_);
    } else {
        dGPR(_Rd_);
        dGPR(_Rs_);
    }

    dGPR(_Rt_);
}
declare(disSUB) {
    dOpCode("sub");
    if (_Rd_ == _Rs_) {
        dGPR(_Rd_);
    } else {
        dGPR(_Rd_);
        dGPR(_Rs_);
    }

    dGPR(_Rt_);
}
declare(disSUBU) {
    dOpCode("subu");
    if (_Rd_ == _Rs_) {
        dGPR(_Rd_);
    } else {
        dGPR(_Rd_);
        dGPR(_Rs_);
    }

    dGPR(_Rt_);
}
declare(disXOR) {
    dOpCode("xor");
    if (_Rd_ == _Rs_) {
        dGPR(_Rd_);
    } else {
        dGPR(_Rd_);
        dGPR(_Rs_);
    }

    dGPR(_Rt_);
}

/*********************************************************
 * Register arithmetic & Register trap logic              *
 * Format:  OP rs, rt                                     *
 *********************************************************/
declare(disDIV) {
    dOpCode("div");
    dGPR(_Rs_);
    dGPR(_Rt_);
}
declare(disDIVU) {
    dOpCode("divu");
    dGPR(_Rs_);
    dGPR(_Rt_);
}
declare(disMULT) {
    dOpCode("mult");
    dGPR(_Rs_);
    dGPR(_Rt_);
}
declare(disMULTU) {
    dOpCode("multu");
    dGPR(_Rs_);
    dGPR(_Rt_);
}

/*********************************************************
 * Register branch logic                                  *
 * Format:  OP rs, offset                                 *
 *********************************************************/
declare(disBGEZ) {
    dOpCode("bgez");
    dGPR(_Rs_);
    dOffset();
}
declare(disBGEZAL) {
    dOpCode("bgezal");
    dGPR(_Rs_);
    dOffset();
}
declare(disBGTZ) {
    dOpCode("bgtz");
    dGPR(_Rs_);
    dOffset();
}
declare(disBLEZ) {
    dOpCode("blez");
    dGPR(_Rs_);
    dOffset();
}
declare(disBLTZ) {
    dOpCode("bltz");
    dGPR(_Rs_);
    dOffset();
}
declare(disBLTZAL) {
    dOpCode("bltzal");
    dGPR(_Rs_);
    dOffset();
}

/*********************************************************
 * Shift arithmetic with constant shift                   *
 * Format:  OP rd, rt, sa                                 *
 *********************************************************/
declare(disSLL) {
    if (code) {
        dOpCode("sll");
        if (_Rd_ == _Rt_) {
            dGPR(_Rd_);
        } else {
            dGPR(_Rd_);
            dGPR(_Rt_);
        }
        dSa();
    } else {
        dOpCode("nop");
    }
}
declare(disSRA) {
    dOpCode("sra");
    if (_Rd_ == _Rt_) {
        dGPR(_Rd_);
    } else {
        dGPR(_Rd_);
        dGPR(_Rt_);
    }

    dSa();
}
declare(disSRL) {
    dOpCode("srl");
    if (_Rd_ == _Rt_) {
        dGPR(_Rd_);
    } else {
        dGPR(_Rd_);
        dGPR(_Rt_);
    }

    dSa();
}

/*********************************************************
 * Shift arithmetic with variant register shift           *
 * Format:  OP rd, rt, rs                                 *
 *********************************************************/
declare(disSLLV) {
    dOpCode("sllv");
    if (_Rd_ == _Rt_) {
        dGPR(_Rd_);
    } else {
        dGPR(_Rd_);
        dGPR(_Rt_);
    }

    dGPR(_Rs_);
}
declare(disSRAV) {
    dOpCode("srav");
    if (_Rd_ == _Rt_) {
        dGPR(_Rd_);
    } else {
        dGPR(_Rd_);
        dGPR(_Rt_);
    }

    dGPR(_Rs_);
}
declare(disSRLV) {
    dOpCode("srlv");
    if (_Rd_ == _Rt_) {
        dGPR(_Rd_);
    } else {
        dGPR(_Rd_);
        dGPR(_Rt_);
    }

    dGPR(_Rs_);
}

/*********************************************************
 * Load higher 16 bits of the first word in GPR with imm  *
 * Format:  OP rt, immediate                              *
 *********************************************************/
declare(disLUI) {
    uint8_t nextIns = nextCode >> 26;
    uint8_t nextRt = (nextCode >> 16) & 0x1f;
    uint8_t nextRs = (nextCode >> 21) & 0x1f;
    uint16_t nextImm = nextCode & 0xffff;
    if (skipNext && (nextIns == 9) && (_Rt_ == nextRt) && (nextRt == nextRs)) {
        dOpCode("li");
        dGPR(_Rt_);
        uint32_t imm = static_cast<uint32_t>(nextImm) + _Imm_;
        Imm32(imm);
        *skipNext = true;
    } else if (skipNext && (nextIns == 13) && (_Rt_ == nextRt) && (nextRt == nextRs)) {
        dOpCode("li");
        dGPR(_Rt_);
        uint32_t imm = static_cast<uint32_t>(nextImm) | _Imm_;
        Imm32(imm);
        *skipNext = true;
    } else {
        dOpCode("lui");
        dGPR(_Rt_);
        dImm();
    }
}

/*********************************************************
 * Move from HI/LO to GPR                                 *
 * Format:  OP rd                                         *
 *********************************************************/
declare(disMFHI) {
    dOpCode("mfhi");
    dGPR(_Rd_);
    dHI();
}
declare(disMFLO) {
    dOpCode("mflo");
    dGPR(_Rd_);
    dLO();
}

/*********************************************************
 * Move from GPR to HI/LO                                 *
 * Format:  OP rd                                         *
 *********************************************************/
declare(disMTHI) {
    dOpCode("mthi");
    dHI();
    dGPR(_Rs_);
}
declare(disMTLO) {
    dOpCode("mtlo");
    dLO();
    dGPR(_Rs_);
}

/*********************************************************
 * Special purpose instructions                           *
 * Format:  OP                                            *
 *********************************************************/
declare(disBREAK) { dOpCode("break"); }
declare(disRFE) { dOpCode("rfe"); }
declare(disSYSCALL) { dOpCode("syscall"); }
declare(disHLE) { dOpCode("hle"); }

declare(disRTPS) { dOpCode("rtps"); }
declare(disOP) { dOpCode("op"); }
declare(disNCLIP) { dOpCode("nclip"); }
declare(disDPCS) { dOpCode("dpcs"); }
declare(disINTPL) { dOpCode("intpl"); }
declare(disMVMVA) { dOpCode("mvmva"); }
declare(disNCDS) { dOpCode("ncds"); }
declare(disCDP) { dOpCode("cdp"); }
declare(disNCDT) { dOpCode("ncdt"); }
declare(disNCCS) { dOpCode("nccs"); }
declare(disCC) { dOpCode("cc"); }
declare(disNCS) { dOpCode("ncs"); }
declare(disNCT) { dOpCode("nct"); }
declare(disSQR) { dOpCode("sqr"); }
declare(disDCPL) { dOpCode("dcpl"); }
declare(disDPCT) { dOpCode("dpct"); }
declare(disAVSZ3) { dOpCode("avsz3"); }
declare(disAVSZ4) { dOpCode("avsz4"); }
declare(disRTPT) { dOpCode("rtpt"); }
declare(disGPF) { dOpCode("gpf"); }
declare(disGPL) { dOpCode("gpl"); }
declare(disNCCT) { dOpCode("ncct"); }

declare(disMFC2) {
    dOpCode("mfc2");
    dGPR(_Rt_);
    dCP2C(_Rd_);
}
declare(disMTC2) {
    dOpCode("mtc2");
    dCP2C(_Rd_);
    dGPR(_Rt_);
}
declare(disCFC2) {
    dOpCode("cfc2");
    dGPR(_Rt_);
    dCP2C(_Rd_);
}
declare(disCTC2) {
    dOpCode("ctc2");
    dCP2C(_Rd_);
    dGPR(_Rt_);
}

/*********************************************************
 * Register branch logic                                  *
 * Format:  OP rs, rt, offset                             *
 *********************************************************/
declare(disBEQ) {
    dOpCode("beq");
    dGPR(_Rs_);
    dGPR(_Rt_);
    dOffset();
}
declare(disBNE) {
    dOpCode("bne");
    dGPR(_Rs_);
    dGPR(_Rt_);
    dOffset();
}

/*********************************************************
 * Jump to target                                         *
 * Format:  OP target                                     *
 *********************************************************/
declare(disJ) {
    dOpCode("j");
    dTarget();
}
declare(disJAL) {
    dOpCode("jal");
    dTarget();
}

/*********************************************************
 * Register jump                                          *
 * Format:  OP rs, rd                                     *
 *********************************************************/
declare(disJR) {
    dOpCode("jr");
    dGPR(_Rs_);
}
declare(disJALR) {
    dOpCode("jalr");
    dGPR(_Rs_);
    if (_Rd_ != 31) {
        dGPR(_Rd_);
    }
}

/*********************************************************
 * Load and store for GPR                                 *
 * Format:  OP rt, offset(base)                           *
 *********************************************************/
declare(disLB) {
    dOpCode("lb");
    dGPR(_Rt_);
    dOfB();
}
declare(disLBU) {
    dOpCode("lbu");
    dGPR(_Rt_);
    dOfB();
}
declare(disLH) {
    dOpCode("lh");
    dGPR(_Rt_);
    dOfB();
}
declare(disLHU) {
    dOpCode("lhu");
    dGPR(_Rt_);
    dOfB();
}
declare(disLW) {
    dOpCode("lw");
    dGPR(_Rt_);
    dOfB();
}
declare(disLWL) {
    dOpCode("lwl");
    dGPR(_Rt_);
    dOfB();
}
declare(disLWR) {
    dOpCode("lwr");
    dGPR(_Rt_);
    dOfB();
}
declare(disLWC2) {
    dOpCode("lwc2");
    dCP2D(_Rt_);
    dOfB();
}
declare(disSB) {
    dOpCode("sb");
    dGPR(_Rt_);
    dOfB();
}
declare(disSH) {
    dOpCode("sh");
    dGPR(_Rt_);
    dOfB();
}
declare(disSW) {
    dOpCode("sw");
    dGPR(_Rt_);
    dOfB();
}
declare(disSWL) {
    dOpCode("swl");
    dGPR(_Rt_);
    dOfB();
}
declare(disSWR) {
    dOpCode("swr");
    dGPR(_Rt_);
    dOfB();
}
declare(disSWC2) {
    dOpCode("swc2");
    dCP2D(_Rt_);
    dOfB();
}

/*********************************************************
 * Moves between GPR and COPx                             *
 * Format:  OP rt, fs                                     *
 *********************************************************/
declare(disMFC0) {
    dOpCode("mfc0");
    dGPR(_Rt_);
    dCP0(_Rd_);
}
declare(disMTC0) {
    dOpCode("mtc0");
    dCP0(_Rd_);
    dGPR(_Rt_);
}
declare(disCFC0) {
    dOpCode("cfc0");
    dGPR(_Rt_);
    dCP0(_Rd_);
}
declare(disCTC0) {
    dOpCode("ctc0");
    dCP0(_Rd_);
    dGPR(_Rt_);
}

/*********************************************************
 * Unknow instruction (would generate an exception)       *
 * Format:  ?                                             *
 *********************************************************/
declare(disNULL) { dOpCode("*** Bad OP ***"); }

const PCSX::Disasm::TdisR3000AF PCSX::Disasm::s_disR3000A_SPECIAL[] = {
    // Subset of disSPECIAL
    &Disasm::disSLL,     &Disasm::disNULL,  &Disasm::disSRL,  &Disasm::disSRA,   // 00
    &Disasm::disSLLV,    &Disasm::disNULL,  &Disasm::disSRLV, &Disasm::disSRAV,  // 04
    &Disasm::disJR,      &Disasm::disJALR,  &Disasm::disNULL, &Disasm::disNULL,  // 08
    &Disasm::disSYSCALL, &Disasm::disBREAK, &Disasm::disNULL, &Disasm::disNULL,  // 0c
    &Disasm::disMFHI,    &Disasm::disMTHI,  &Disasm::disMFLO, &Disasm::disMTLO,  // 10
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disNULL, &Disasm::disNULL,  // 14
    &Disasm::disMULT,    &Disasm::disMULTU, &Disasm::disDIV,  &Disasm::disDIVU,  // 18
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disNULL, &Disasm::disNULL,  // 1c
    &Disasm::disADD,     &Disasm::disADDU,  &Disasm::disSUB,  &Disasm::disSUBU,  // 20
    &Disasm::disAND,     &Disasm::disOR,    &Disasm::disXOR,  &Disasm::disNOR,   // 24
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disSLT,  &Disasm::disSLTU,  // 28
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disNULL, &Disasm::disNULL,  // 2c
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disNULL, &Disasm::disNULL,  // 30
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disNULL, &Disasm::disNULL,  // 34
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disNULL, &Disasm::disNULL,  // 38
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disNULL, &Disasm::disNULL,  // 3c
};

declare(disSPECIAL) {
    cTdisR3000AF ptr = s_disR3000A_SPECIAL[_Funct_];
    (*this.*ptr)(code, nextCode, pc, skipNext);
}

const PCSX::Disasm::TdisR3000AF PCSX::Disasm::s_disR3000A_BCOND[] = {
    // Subset of disBCOND
    &Disasm::disBLTZ,   &Disasm::disBGEZ,   &Disasm::disNULL, &Disasm::disNULL,  // 00
    &Disasm::disNULL,   &Disasm::disNULL,   &Disasm::disNULL, &Disasm::disNULL,  // 04
    &Disasm::disNULL,   &Disasm::disNULL,   &Disasm::disNULL, &Disasm::disNULL,  // 08
    &Disasm::disNULL,   &Disasm::disNULL,   &Disasm::disNULL, &Disasm::disNULL,  // 0c
    &Disasm::disBLTZAL, &Disasm::disBGEZAL, &Disasm::disNULL, &Disasm::disNULL,  // 10
    &Disasm::disNULL,   &Disasm::disNULL,   &Disasm::disNULL, &Disasm::disNULL,  // 14
    &Disasm::disNULL,   &Disasm::disNULL,   &Disasm::disNULL, &Disasm::disNULL,  // 18
    &Disasm::disNULL,   &Disasm::disNULL,   &Disasm::disNULL, &Disasm::disNULL,  // 1c
};

declare(disBCOND) {
    cTdisR3000AF ptr = s_disR3000A_BCOND[_Rt_];
    (*this.*ptr)(code, nextCode, pc, skipNext);
}

const PCSX::Disasm::TdisR3000AF PCSX::Disasm::s_disR3000A_COP0[] = {
    // Subset of disCOP0
    &Disasm::disMFC0, &Disasm::disNULL, &Disasm::disCFC0, &Disasm::disNULL,  // 00
    &Disasm::disMTC0, &Disasm::disNULL, &Disasm::disCTC0, &Disasm::disNULL,  // 04
    &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL,  // 08
    &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL,  // 0c
    &Disasm::disRFE,  &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL,  // 10
    &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL,  // 14
    &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL,  // 18
    &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL,  // 1c
};

declare(disCOP0) {
    cTdisR3000AF ptr = s_disR3000A_COP0[_Rs_];
    (*this.*ptr)(code, nextCode, pc, skipNext);
}

const PCSX::Disasm::TdisR3000AF PCSX::Disasm::s_disR3000A_BASIC[] = {
    // Subset of disBASIC (based on rs)
    &Disasm::disMFC2, &Disasm::disNULL, &Disasm::disCFC2, &Disasm::disNULL,  // 00
    &Disasm::disMTC2, &Disasm::disNULL, &Disasm::disCTC2, &Disasm::disNULL,  // 04
    &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL,  // 08
    &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL,  // 0c
    &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL,  // 10
    &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL,  // 14
    &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL,  // 18
    &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL, &Disasm::disNULL,  // 1c
};

declare(disBASIC) {
    cTdisR3000AF ptr = s_disR3000A_BASIC[_Rs_];
    (*this.*ptr)(code, nextCode, pc, skipNext);
}

const PCSX::Disasm::TdisR3000AF PCSX::Disasm::s_disR3000A_COP2[] = {
    // Subset of disR3000F_COP2 (based on funct)
    &Disasm::disBASIC, &Disasm::disRTPS,  &Disasm::disNULL,  &Disasm::disNULL,  // 00
    &Disasm::disNULL,  &Disasm::disNULL,  &Disasm::disNCLIP, &Disasm::disNULL,  // 04
    &Disasm::disNULL,  &Disasm::disNULL,  &Disasm::disNULL,  &Disasm::disNULL,  // 08
    &Disasm::disOP,    &Disasm::disNULL,  &Disasm::disNULL,  &Disasm::disNULL,  // 0c
    &Disasm::disDPCS,  &Disasm::disINTPL, &Disasm::disMVMVA, &Disasm::disNCDS,  // 10
    &Disasm::disCDP,   &Disasm::disNULL,  &Disasm::disNCDT,  &Disasm::disNULL,  // 14
    &Disasm::disNULL,  &Disasm::disNULL,  &Disasm::disNULL,  &Disasm::disNCCS,  // 18
    &Disasm::disCC,    &Disasm::disNULL,  &Disasm::disNCS,   &Disasm::disNULL,  // 1c
    &Disasm::disNCT,   &Disasm::disNULL,  &Disasm::disNULL,  &Disasm::disNULL,  // 20
    &Disasm::disNULL,  &Disasm::disNULL,  &Disasm::disNULL,  &Disasm::disNULL,  // 24
    &Disasm::disSQR,   &Disasm::disDCPL,  &Disasm::disDPCT,  &Disasm::disNULL,  // 28
    &Disasm::disNULL,  &Disasm::disAVSZ3, &Disasm::disAVSZ4, &Disasm::disNULL,  // 2c
    &Disasm::disRTPT,  &Disasm::disNULL,  &Disasm::disNULL,  &Disasm::disNULL,  // 30
    &Disasm::disNULL,  &Disasm::disNULL,  &Disasm::disNULL,  &Disasm::disNULL,  // 34
    &Disasm::disNULL,  &Disasm::disNULL,  &Disasm::disNULL,  &Disasm::disNULL,  // 38
    &Disasm::disNULL,  &Disasm::disGPF,   &Disasm::disGPL,   &Disasm::disNCCT,  // 3c
};

declare(disCOP2) {
    cTdisR3000AF ptr = s_disR3000A_COP2[_Funct_];
    (*this.*ptr)(code, nextCode, pc, skipNext);
}

const PCSX::Disasm::TdisR3000AF PCSX::Disasm::s_disR3000A[] = {
    &Disasm::disSPECIAL, &Disasm::disBCOND, &Disasm::disJ,    &Disasm::disJAL,    // 00
    &Disasm::disBEQ,     &Disasm::disBNE,   &Disasm::disBLEZ, &Disasm::disBGTZ,   // 04
    &Disasm::disADDI,    &Disasm::disADDIU, &Disasm::disSLTI, &Disasm::disSLTIU,  // 08
    &Disasm::disANDI,    &Disasm::disORI,   &Disasm::disXORI, &Disasm::disLUI,    // 0c
    &Disasm::disCOP0,    &Disasm::disNULL,  &Disasm::disCOP2, &Disasm::disNULL,   // 10
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disNULL, &Disasm::disNULL,   // 14
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disNULL, &Disasm::disNULL,   // 18
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disNULL, &Disasm::disNULL,   // 1c
    &Disasm::disLB,      &Disasm::disLH,    &Disasm::disLWL,  &Disasm::disLW,     // 20
    &Disasm::disLBU,     &Disasm::disLHU,   &Disasm::disLWR,  &Disasm::disNULL,   // 24
    &Disasm::disSB,      &Disasm::disSH,    &Disasm::disSWL,  &Disasm::disSW,     // 28
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disSWR,  &Disasm::disNULL,   // 2c
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disLWC2, &Disasm::disNULL,   // 30
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disNULL, &Disasm::disNULL,   // 34
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disSWC2, &Disasm::disHLE,    // 38
    &Disasm::disNULL,    &Disasm::disNULL,  &Disasm::disNULL, &Disasm::disNULL,   // 3c
};

std::string PCSX::Disasm::asString(uint32_t code, uint32_t nextCode, uint32_t pc, bool *skipNext) {
    StringDisasm strd;
    strd.process(code, nextCode, pc, skipNext);
    char buf[64];
    snprintf(buf, 64, "%8.8x %8.8x: ", pc, code);
    std::string ret = buf + strd.get();
    strd.reset();
    return ret;
}
