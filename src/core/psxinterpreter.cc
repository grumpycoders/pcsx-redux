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
 * PSX assembly interpreter.
 */

#include "core/debug.h"
#include "core/disr3000a.h"
#include "core/gte.h"
#include "core/pgxp_cpu.h"
#include "core/pgxp_debug.h"
#include "core/pgxp_gte.h"
#include "core/psxemulator.h"
#include "core/r3000a.h"
#include "tracy/Tracy.hpp"

#undef _PC_
#undef _Op_
#undef _Funct_
#undef _Rd_
#undef _Rt_
#undef _Rs_
#undef _Sa_
#undef _Im_
#undef _Target_
#undef _Imm_
#undef _Target_
#undef _ImmU_
#undef _ImmLU_
#undef _rRs_
#undef _rRt_
#undef _rRd_
#undef _rSa_
#undef _rFs_
#undef _c2dRs_
#undef _c2dRt_
#undef _c2dRd_
#undef _c2dSa_
#undef _rHi_
#undef _rLo_
#undef _JumpTarget_
#undef _BranchTarget_
#undef _SetLink

#define _PC_ m_psxRegs.pc  // The next PC to be executed

#define _Op_ _fOp_(m_psxRegs.code)
#define _Funct_ _fFunct_(m_psxRegs.code)
#define _Rd_ _fRd_(m_psxRegs.code)
#define _Rt_ _fRt_(m_psxRegs.code)
#define _Rs_ _fRs_(m_psxRegs.code)
#define _Sa_ _fSa_(m_psxRegs.code)
#define _Im_ _fIm_(m_psxRegs.code)
#define _Target_ _fTarget_(m_psxRegs.code)

#define _Imm_ _fImm_(m_psxRegs.code)
#define _ImmU_ _fImmU_(m_psxRegs.code)
#define _ImmLU_ _fImmLU_(m_psxRegs.code)

#define _rRs_ m_psxRegs.GPR.r[_Rs_]  // Rs register
#define _rRt_ m_psxRegs.GPR.r[_Rt_]  // Rt register
#define _rRd_ m_psxRegs.GPR.r[_Rd_]  // Rd register
#define _rSa_ m_psxRegs.GPR.r[_Sa_]  // Sa register
#define _rFs_ m_psxRegs.CP0.r[_Rd_]  // Fs register

#define _c2dRs_ m_psxRegs.CP2D.r[_Rs_]  // Rs cop2 data register
#define _c2dRt_ m_psxRegs.CP2D.r[_Rt_]  // Rt cop2 data register
#define _c2dRd_ m_psxRegs.CP2D.r[_Rd_]  // Rd cop2 data register
#define _c2dSa_ m_psxRegs.CP2D.r[_Sa_]  // Sa cop2 data register

#define _rHi_ m_psxRegs.GPR.n.hi  // The HI register
#define _rLo_ m_psxRegs.GPR.n.lo  // The LO register

#define _JumpTarget_ ((_Target_ * 4) + (_PC_ & 0xf0000000))  // Calculates the target during a jump instruction
#define _BranchTarget_ ((int16_t)_Im_ * 4 + _PC_)            // Calculates the target during a branch instruction
#define _SetLink(x) delayedLoad(x, _PC_ + 4);                // Sets the return address in the link register

enum Exceptions {
    Interrupt = 0,
    LoadAddressError = 0x10,
    StoreAddressError = 0x14,
    InstructionBusError = 0x18,
    DataBusError = 0x1C,
    Syscall = 0x20,
    Break = 0x24,
    ReservedInstruction = 0x28,
    CoprocessorUnusable = 0x2C,
    ArithmeticOverflow = 0x30
};

class InterpretedCPU : public PCSX::R3000Acpu {
  public:
    InterpretedCPU() : R3000Acpu("Interpreted") {}

  private:
    virtual bool Implemented() final { return true; }
    virtual bool Init() override;
    virtual void Reset() override;
    virtual void Execute() override;
    virtual void Clear(uint32_t Addr, uint32_t Size) override;
    virtual void Shutdown() override;
    virtual void SetPGXPMode(uint32_t pgxpMode) override;
    virtual bool isDynarec() override { return false; }

    void maybeCancelDelayedLoad(uint32_t index) {
        unsigned other = m_currentDelayedLoad ^ 1;
        if (m_delayedLoadInfo[other].index == index) m_delayedLoadInfo[other].active = false;
    }

    void psxTestSWInts();

    typedef void (InterpretedCPU::*intFunc_t)();
    typedef const intFunc_t cIntFunc_t;

    cIntFunc_t *s_pPsxBSC = NULL;
    cIntFunc_t *s_pPsxSPC = NULL;
    cIntFunc_t *s_pPsxREG = NULL;
    cIntFunc_t *s_pPsxCP0 = NULL;
    cIntFunc_t *s_pPsxCP2 = NULL;
    cIntFunc_t *s_pPsxCP2BSC = NULL;

    template <bool debug>
    void execBlock();
    void doBranch(uint32_t tar);

    void MTC0(int reg, uint32_t val);

    /* Arithmetic with immediate operand */
    void psxADDI();
    void psxADDIU();
    void psxANDI();
    void psxORI();
    void psxXORI();
    void psxSLTI();
    void psxSLTIU();

    /* Register arithmetic */
    void psxADD();
    void psxADDU();
    void psxSUB();
    void psxSUBU();
    void psxAND();
    void psxOR();
    void psxXOR();
    void psxNOR();
    void psxSLT();
    void psxSLTU();

    /* Register mult/div & Register trap logic */
    void psxDIV();
    void psxDIVU();
    void psxMULT();
    void psxMULTU();

    /* Register branch logic */
    void psxBGEZ();
    void psxBGEZAL();
    void psxBGTZ();
    void psxBLEZ();
    void psxBLTZ();
    void psxBLTZAL();

    /* Shift arithmetic with constant shift */
    void psxSLL();
    void psxSRA();
    void psxSRL();

    /* Shift arithmetic with variant register shift */
    void psxSLLV();
    void psxSRAV();
    void psxSRLV();

    /* Load higher 16 bits of the first word in GPR with imm */
    void psxLUI();

    /* Move from HI/LO to GPR */
    void psxMFHI();
    void psxMFLO();

    /* Move to GPR to HI/LO & Register jump */
    void psxMTHI();
    void psxMTLO();

    /* Special purpose instructions */
    void psxBREAK();
    void psxSYSCALL();
    void psxRFE();

    /* Register branch logic */
    void psxBEQ();
    void psxBNE();

    /* Jump to target */
    void psxJ();
    void psxJAL();

    /* Register jump */
    void psxJR();
    void psxJALR();

    /* Load and store for GPR */
    void psxLB();
    void psxLBU();
    void psxLH();
    void psxLHU();
    void psxLW();

  private:
    void psxLWL();
    void psxLWR();
    void psxSB();
    void psxSH();
    void psxSW();
    void psxSWL();
    void psxSWR();

    /* Moves between GPR and COPx */
    void psxMFC0();
    void psxCFC0();
    void psxMTC0();
    void psxCTC0();
    void psxMFC2();
    void psxCFC2();

    /* Misc */
    void psxNULL();
    void psxSPECIAL();
    void psxREGIMM();
    void psxCOP0();
    void psxCOP1();
    void psxCOP2();
    void psxCOP3();
    void psxBASIC();

    /* GTE wrappers */
#define GTE_WR(n) void gte##n();
    GTE_WR(LWC2);
    GTE_WR(SWC2);
    GTE_WR(RTPS);
    GTE_WR(NCLIP);
    GTE_WR(OP);
    GTE_WR(DPCS);
    GTE_WR(INTPL);
    GTE_WR(MVMVA);
    GTE_WR(NCDS);
    GTE_WR(CDP);
    GTE_WR(NCDT);
    GTE_WR(NCCS);
    GTE_WR(CC);
    GTE_WR(NCS);
    GTE_WR(NCT);
    GTE_WR(SQR);
    GTE_WR(DCPL);
    GTE_WR(DPCT);
    GTE_WR(AVSZ3);
    GTE_WR(AVSZ4);
    GTE_WR(RTPT);
    GTE_WR(GPF);
    GTE_WR(GPL);
    GTE_WR(NCCT);
    GTE_WR(MTC2);
    GTE_WR(CTC2);
#undef GTE_WR

    static const intFunc_t s_psxBSC[64];
    static const intFunc_t s_psxSPC[64];
    static const intFunc_t s_psxREG[32];
    static const intFunc_t s_psxCP0[32];
    static const intFunc_t s_psxCP2[64];
    static const intFunc_t s_psxCP2BSC[32];

    void pgxpPsxNULL();
    void pgxpPsxADDI();
    void pgxpPsxADDIU();
    void pgxpPsxANDI();
    void pgxpPsxORI();
    void pgxpPsxXORI();
    void pgxpPsxSLTI();
    void pgxpPsxSLTIU();
    void pgxpPsxLUI();
    void pgxpPsxADD();
    void pgxpPsxADDU();
    void pgxpPsxSUB();
    void pgxpPsxSUBU();
    void pgxpPsxAND();
    void pgxpPsxOR();
    void pgxpPsxXOR();
    void pgxpPsxNOR();
    void pgxpPsxSLT();
    void pgxpPsxSLTU();
    void pgxpPsxMULT();
    void pgxpPsxMULTU();
    void pgxpPsxDIV();
    void pgxpPsxDIVU();
    void pgxpPsxSB();
    void pgxpPsxSH();
    void pgxpPsxSW();
    void pgxpPsxSWL();
    void pgxpPsxSWR();
    void pgxpPsxLWL();
    void pgxpPsxLW();
    void pgxpPsxLWR();
    void pgxpPsxLH();
    void pgxpPsxLHU();
    void pgxpPsxLB();
    void pgxpPsxLBU();
    void pgxpPsxSLL();
    void pgxpPsxSRL();
    void pgxpPsxSRA();
    void pgxpPsxSLLV();
    void pgxpPsxSRLV();
    void pgxpPsxSRAV();
    void pgxpPsxMFHI();
    void pgxpPsxMTHI();
    void pgxpPsxMFLO();
    void pgxpPsxMTLO();
    void pgxpPsxMFC2();
    void pgxpPsxCFC2();
    void pgxpPsxMTC2();
    void pgxpPsxCTC2();
    void pgxpPsxLWC2();
    void pgxpPsxSWC2();
    void pgxpPsxMFC0();
    void pgxpPsxCFC0();
    void pgxpPsxMTC0();
    void pgxpPsxCTC0();
    void pgxpPsxRFE();

    static const intFunc_t s_pgxpPsxBSC[64];
    static const intFunc_t s_pgxpPsxSPC[64];
    static const intFunc_t s_pgxpPsxCP0[32];
    static const intFunc_t s_pgxpPsxCP2BSC[32];
    static const intFunc_t s_pgxpPsxBSCMem[64];
};

/* GTE wrappers */
#define GTE_WR(n) \
    void InterpretedCPU::gte##n() { PCSX::g_emulator->m_gte->n(); }
GTE_WR(LWC2);
GTE_WR(SWC2);
GTE_WR(RTPS);
GTE_WR(NCLIP);
GTE_WR(OP);
GTE_WR(DPCS);
GTE_WR(INTPL);
GTE_WR(MVMVA);
GTE_WR(NCDS);
GTE_WR(CDP);
GTE_WR(NCDT);
GTE_WR(NCCS);
GTE_WR(CC);
GTE_WR(NCS);
GTE_WR(NCT);
GTE_WR(SQR);
GTE_WR(DCPL);
GTE_WR(DPCT);
GTE_WR(AVSZ3);
GTE_WR(AVSZ4);
GTE_WR(RTPT);
GTE_WR(GPF);
GTE_WR(GPL);
GTE_WR(NCCT);
GTE_WR(MTC2);
GTE_WR(CTC2);
#undef GTE_WR

// These macros are used to assemble the repassembler functions

inline void InterpretedCPU::doBranch(uint32_t tar) {
    m_nextIsDelaySlot = true;
    delayedPCLoad(tar);
}

/*********************************************************
 * Arithmetic with immediate operand                      *
 * Format:  OP rt, rs, immediate                          *
 *********************************************************/
void InterpretedCPU::psxADDI() {
    if (!_Rt_) return;

    auto rs = _rRs_;
    auto imm = _Imm_;
    uint32_t res = rs + imm;

    if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebug>()) {
        bool overflow = ((rs ^ res) & (imm ^ res)) >> 31;  // fast signed overflow calculation algorithm
        if (overflow) {                                    // if an overflow occurs, throw an exception
            m_psxRegs.pc -= 4;
            PCSX::g_system->printf(_("Signed overflow in ADDI instruction from 0x%08x!\n"), m_psxRegs.pc);
            psxException(Exceptions::ArithmeticOverflow, m_inDelaySlot);
            return;
        }
    }

    maybeCancelDelayedLoad(_Rt_);
    _rRt_ = res;
}  // Rt = Rs + Im      (Exception on Integer Overflow)
void InterpretedCPU::psxADDIU() {
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);
    _rRt_ = _u32(_rRs_) + _Imm_;
}  // Rt = Rs + Im
void InterpretedCPU::psxANDI() {
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);
    _rRt_ = _u32(_rRs_) & _ImmU_;
}  // Rt = Rs And Im
void InterpretedCPU::psxORI() {
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);
    _rRt_ = _u32(_rRs_) | _ImmU_;
}  // Rt = Rs Or  Im
void InterpretedCPU::psxXORI() {
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);
    _rRt_ = _u32(_rRs_) ^ _ImmU_;
}  // Rt = Rs Xor Im
void InterpretedCPU::psxSLTI() {
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);
    _rRt_ = _i32(_rRs_) < _Imm_;
}  // Rt = Rs < Im              (Signed)
void InterpretedCPU::psxSLTIU() {
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);
    _rRt_ = _u32(_rRs_) < ((uint32_t)_Imm_);
}  // Rt = Rs < Im              (Unsigned)

/*********************************************************
 * Register arithmetic                                    *
 * Format:  OP rd, rs, rt                                 *
 *********************************************************/
void InterpretedCPU::psxADD() {
    if (!_Rd_) return;

    auto rs = _rRs_;
    auto rt = _rRt_;
    uint32_t res = rs + rt;

    if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebug>()) {
        bool overflow = ((rs ^ res) & (rt ^ res)) >> 31;  // fast signed overflow calculation algorithm
        if (overflow) {                                   // if an overflow occurs, throw an exception
            m_psxRegs.pc -= 4;
            PCSX::g_system->printf(_("Signed overflow in ADD instruction from 0x%08x!\n"), m_psxRegs.pc);
            psxException(Exceptions::ArithmeticOverflow, m_inDelaySlot);
            return;
        }
    }

    maybeCancelDelayedLoad(_Rd_);
    _rRd_ = res;
}  // Rd = Rs + Rt              (Exception on Integer Overflow)
void InterpretedCPU::psxADDU() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _rRd_ = _u32(_rRs_) + _u32(_rRt_);
}  // Rd = Rs + Rt
void InterpretedCPU::psxSUB() {
    if (!_Rd_) return;

    auto rs = _rRs_;
    auto rt = _rRt_;
    uint32_t res = rs - rt;

    if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebug>()) {
        bool overflow = ((rs ^ res) & (~rt ^ res)) >> 31;  // fast signed overflow calculation algorithm
        if (overflow) {                                    // if an overflow occurs, throw an exception
            m_psxRegs.pc -= 4;
            PCSX::g_system->printf(_("Signed overflow in SUB instruction from 0x%08x!\n"), m_psxRegs.pc);
            psxException(Exceptions::ArithmeticOverflow, m_inDelaySlot);
            return;
        }
    }
    maybeCancelDelayedLoad(_Rd_);
    _rRd_ = res;
}  // Rd = Rs - Rt              (Exception on Integer Overflow)
void InterpretedCPU::psxSUBU() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _rRd_ = _u32(_rRs_) - _u32(_rRt_);
}  // Rd = Rs - Rt
void InterpretedCPU::psxAND() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _rRd_ = _u32(_rRs_) & _u32(_rRt_);
}  // Rd = Rs And Rt
void InterpretedCPU::psxOR() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _rRd_ = _u32(_rRs_) | _u32(_rRt_);
}  // Rd = Rs Or  Rt
void InterpretedCPU::psxXOR() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _rRd_ = _u32(_rRs_) ^ _u32(_rRt_);
}  // Rd = Rs Xor Rt
void InterpretedCPU::psxNOR() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _rRd_ = ~(_u32(_rRs_) | _u32(_rRt_));
}  // Rd = Rs Nor Rt
void InterpretedCPU::psxSLT() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _rRd_ = _i32(_rRs_) < _i32(_rRt_);
}  // Rd = Rs < Rt              (Signed)
void InterpretedCPU::psxSLTU() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _rRd_ = _u32(_rRs_) < _u32(_rRt_);
}  // Rd = Rs < Rt              (Unsigned)

/*********************************************************
 * Register mult/div & Register trap logic                *
 * Format:  OP rs, rt                                     *
 *********************************************************/
void InterpretedCPU::psxDIV() {
    if (!_i32(_rRt_)) {
        _i32(_rHi_) = _i32(_rRs_);
        if (_i32(_rRs_) & 0x80000000) {
            _i32(_rLo_) = 1;
        } else {
            _i32(_rLo_) = 0xFFFFFFFF;
        }
    } else if (_i32(_rRs_) == 0x80000000 && _i32(_rRt_) == 0xFFFFFFFF) {
        _i32(_rLo_) = 0x80000000;
        _i32(_rHi_) = 0;
    } else {
        _i32(_rLo_) = _i32(_rRs_) / _i32(_rRt_);
        _i32(_rHi_) = _i32(_rRs_) % _i32(_rRt_);
    }
}

void InterpretedCPU::psxDIVU() {
    if (_rRt_ != 0) {
        _rLo_ = _rRs_ / _rRt_;
        _rHi_ = _rRs_ % _rRt_;
    } else {
        _rLo_ = 0xffffffff;
        _rHi_ = _rRs_;
    }
}

void InterpretedCPU::psxMULT() {
    uint64_t res = (int64_t)((int64_t)_i32(_rRs_) * (int64_t)_i32(_rRt_));

    m_psxRegs.GPR.n.lo = (uint32_t)(res & 0xffffffff);
    m_psxRegs.GPR.n.hi = (uint32_t)((res >> 32) & 0xffffffff);
}

void InterpretedCPU::psxMULTU() {
    uint64_t res = (uint64_t)((uint64_t)_u32(_rRs_) * (uint64_t)_u32(_rRt_));

    m_psxRegs.GPR.n.lo = (uint32_t)(res & 0xffffffff);
    m_psxRegs.GPR.n.hi = (uint32_t)((res >> 32) & 0xffffffff);
}

/*********************************************************
 * Register branch logic                                  *
 * Format:  OP rs, offset                                 *
 *********************************************************/
#define RepZBranchi32(op) \
    if (_i32(_rRs_) op 0) doBranch(_BranchTarget_);
#define RepZBranchLinki32(op) \
    _SetLink(31) if (_i32(_rRs_) op 0) { doBranch(_BranchTarget_); }

void InterpretedCPU::psxBGEZ() { RepZBranchi32(>=) }  // Branch if Rs >= 0
void InterpretedCPU::psxBGEZAL() {                    // Branch if Rs >= 0 and link
    maybeCancelDelayedLoad(31);
    RepZBranchLinki32(>=)
}
void InterpretedCPU::psxBGTZ() { RepZBranchi32(>) }   // Branch if Rs >  0
void InterpretedCPU::psxBLEZ() { RepZBranchi32(<=) }  // Branch if Rs <= 0
void InterpretedCPU::psxBLTZ() { RepZBranchi32(<) }   // Branch if Rs <  0
void InterpretedCPU::psxBLTZAL() {                    // Branch if Rs <  0 and link
    maybeCancelDelayedLoad(31);
    RepZBranchLinki32(<)
}
/*********************************************************
 * Shift arithmetic with constant shift                   *
 * Format:  OP rd, rt, sa                                 *
 *********************************************************/
void InterpretedCPU::psxSLL() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _u32(_rRd_) = _u32(_rRt_) << _Sa_;
}  // Rd = Rt << sa
void InterpretedCPU::psxSRA() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _i32(_rRd_) = _i32(_rRt_) >> _Sa_;
}  // Rd = Rt >> sa (arithmetic)
void InterpretedCPU::psxSRL() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _u32(_rRd_) = _u32(_rRt_) >> _Sa_;
}  // Rd = Rt >> sa (logical)

/*********************************************************
 * Shift arithmetic with variant register shift           *
 * Format:  OP rd, rt, rs                                 *
 *********************************************************/
void InterpretedCPU::psxSLLV() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _u32(_rRd_) = _u32(_rRt_) << (_u32(_rRs_) & 0x1f);
}  // Rd = Rt << rs
void InterpretedCPU::psxSRAV() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _i32(_rRd_) = _i32(_rRt_) >> (_u32(_rRs_) & 0x1f);
}  // Rd = Rt >> rs (arithmetic)
void InterpretedCPU::psxSRLV() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _u32(_rRd_) = _u32(_rRt_) >> (_u32(_rRs_) & 0x1f);
}  // Rd = Rt >> rs (logical)

/*********************************************************
 * Load higher 16 bits of the first word in GPR with imm  *
 * Format:  OP rt, immediate                              *
 *********************************************************/
void InterpretedCPU::psxLUI() {
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);
    _u32(_rRt_) = _ImmLU_;
}  // Upper halfword of Rt = Im

/*********************************************************
 * Move from HI/LO to GPR                                 *
 * Format:  OP rd                                         *
 *********************************************************/
void InterpretedCPU::psxMFHI() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _rRd_ = _rHi_;
}  // Rd = Hi
void InterpretedCPU::psxMFLO() {
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);
    _rRd_ = _rLo_;
}  // Rd = Lo

/*********************************************************
 * Move to GPR to HI/LO & Register jump                   *
 * Format:  OP rs                                         *
 *********************************************************/
void InterpretedCPU::psxMTHI() { _rHi_ = _rRs_; }  // Hi = Rs
void InterpretedCPU::psxMTLO() { _rLo_ = _rRs_; }  // Lo = Rs

/*********************************************************
 * Special purpose instructions                           *
 * Format:  OP                                            *
 *********************************************************/
void InterpretedCPU::psxBREAK() {
    m_psxRegs.pc -= 4;
    psxException(Exceptions::Break, m_inDelaySlot);
    if (m_inDelaySlot) {
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        if (!delayedLoad.pcActive) abort();
        delayedLoad.pcActive = false;
    }
}

void InterpretedCPU::psxSYSCALL() {
    m_psxRegs.pc -= 4;
    psxException(Exceptions::Syscall, m_inDelaySlot);
    if (m_inDelaySlot) {
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        if (!delayedLoad.pcActive) abort();
        delayedLoad.pcActive = false;
    }
}

void InterpretedCPU::psxRFE() {
    //  PCSX::g_system->printf("psxRFE\n");
    m_psxRegs.CP0.n.Status = (m_psxRegs.CP0.n.Status & 0xfffffff0) | ((m_psxRegs.CP0.n.Status & 0x3c) >> 2);
    psxTestSWInts();
}

/*********************************************************
 * Register branch logic                                  *
 * Format:  OP rs, rt, offset                             *
 *********************************************************/
#define RepBranchi32(op) \
    if (_i32(_rRs_) op _i32(_rRt_)) doBranch(_BranchTarget_);

void InterpretedCPU::psxBEQ() { RepBranchi32(==) }  // Branch if Rs == Rt
void InterpretedCPU::psxBNE() { RepBranchi32(!=) }  // Branch if Rs != Rt

/*********************************************************
 * Jump to target                                         *
 * Format:  OP target                                     *
 *********************************************************/
void InterpretedCPU::psxJ() { doBranch(_JumpTarget_); }
void InterpretedCPU::psxJAL() {
    _SetLink(31);
    maybeCancelDelayedLoad(31);
    doBranch(_JumpTarget_);
}

/*********************************************************
 * Register jump                                          *
 * Format:  OP rs, rd                                     *
 *********************************************************/
void InterpretedCPU::psxJR() {
    if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebug>()) {  // if in debug mode, check for unaligned jump
        if (_rRs_ & 3) {  // if the jump is unaligned, throw an exception and ret
            m_psxRegs.pc -= 4;
            PCSX::g_system->printf(_("Attempted unaligned JR from 0x%08x, firing exception!\n"), m_psxRegs.pc);
            psxException(Exceptions::LoadAddressError, m_inDelaySlot);
            return;
        }
    }

    doBranch(_rRs_ & ~3);  // the "& ~3" word-aligns the jump address
}

void InterpretedCPU::psxJALR() {
    uint32_t temp = _u32(_rRs_);
    if (_Rd_) {
        maybeCancelDelayedLoad(_Rd_);
        _SetLink(_Rd_);
    }

    if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebug>()) {  // if in debug mode, check for unaligned jump
        if (temp & 3) {  // if the address is unaligned, throw an exception and return
            m_psxRegs.pc -= 4;
            PCSX::g_system->printf(_("Attempted unaligned JALR from 0x%08x, firing exception!\n"), m_psxRegs.pc);
            psxException(Exceptions::LoadAddressError, m_inDelaySlot);
            return;
        }
    }

    doBranch(temp & ~3);  // the "& ~3" force aligns the address
}

/*********************************************************
 * Load and store for GPR                                 *
 * Format:  OP rt, offset(base)                           *
 *********************************************************/

#define _oB_ (_u32(_rRs_) + _Imm_)

void InterpretedCPU::psxLB() {
    // load delay = 1 latency
    if (_Rt_) {
        _i32(delayedLoadRef(_Rt_)) = (signed char)PCSX::g_emulator->m_psxMem->psxMemRead8(_oB_);
    } else {
        PCSX::g_emulator->m_psxMem->psxMemRead8(_oB_);
    }
}

void InterpretedCPU::psxLBU() {
    // load delay = 1 latency
    if (_Rt_) {
        _u32(delayedLoadRef(_Rt_)) = PCSX::g_emulator->m_psxMem->psxMemRead8(_oB_);
    } else {
        PCSX::g_emulator->m_psxMem->psxMemRead8(_oB_);
    }
}

void InterpretedCPU::psxLH() {
    // load delay = 1 latency
    if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebug>()) {
        if (_oB_ & 1) {
            m_psxRegs.pc -= 4;
            PCSX::g_system->printf(_("Unaligned address in LH from 0x%08x\n"), m_psxRegs.pc);
            psxException(Exceptions::LoadAddressError, m_inDelaySlot);
            return;
        }
    }

    if (_Rt_) {
        _i32(delayedLoadRef(_Rt_)) = (short)PCSX::g_emulator->m_psxMem->psxMemRead16(_oB_);
    } else {
        PCSX::g_emulator->m_psxMem->psxMemRead16(_oB_);
    }
}

void InterpretedCPU::psxLHU() {
    // load delay = 1 latency
    if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebug>()) {
        if (_oB_ & 1) {
            m_psxRegs.pc -= 4;
            PCSX::g_system->printf(_("Unaligned address in LHU from 0x%08x\n"), m_psxRegs.pc);
            psxException(Exceptions::LoadAddressError, m_inDelaySlot);
            return;
        }
    }

    if (_Rt_) {
        _u32(delayedLoadRef(_Rt_)) = PCSX::g_emulator->m_psxMem->psxMemRead16(_oB_);
    } else {
        PCSX::g_emulator->m_psxMem->psxMemRead16(_oB_);
    }
}

void InterpretedCPU::psxLW() {
    // load delay = 1 latency
    if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebug>()) {
        if (_oB_ & 3) {
            m_psxRegs.pc -= 4;
            PCSX::g_system->printf(_("Unaligned address in LW from 0x%08x\n"), m_psxRegs.pc);
            psxException(Exceptions::LoadAddressError, m_inDelaySlot);
            return;
        }
    }

    if (_Rt_) {
        _u32(delayedLoadRef(_Rt_)) = PCSX::g_emulator->m_psxMem->psxMemRead32(_oB_);
    } else {
        PCSX::g_emulator->m_psxMem->psxMemRead32(_oB_);
    }
}

void InterpretedCPU::psxLWL() {
    uint32_t addr = _oB_;
    uint32_t shift = addr & 3;
    uint32_t mem = PCSX::g_emulator->m_psxMem->psxMemRead32(addr & ~3);

    // load delay = 1 latency
    if (!_Rt_) return;
    _u32(delayedLoadRef(_Rt_, LWL_MASK[shift])) = mem << LWL_SHIFT[shift];

    /*
    Mem = 1234.  Reg = abcd
    0   4bcd   (mem << 24) | (reg & 0x00ffffff)
    1   34cd   (mem << 16) | (reg & 0x0000ffff)
    2   234d   (mem <<  8) | (reg & 0x000000ff)
    3   1234   (mem      ) | (reg & 0x00000000)
    */
}

void InterpretedCPU::psxLWR() {
    uint32_t addr = _oB_;
    uint32_t shift = addr & 3;
    uint32_t mem = PCSX::g_emulator->m_psxMem->psxMemRead32(addr & ~3);

    // load delay = 1 latency
    if (!_Rt_) return;
    _u32(delayedLoadRef(_Rt_, LWR_MASK[shift])) = mem >> LWR_SHIFT[shift];

    /*
    Mem = 1234.  Reg = abcd
    0   1234   (mem      ) | (reg & 0x00000000)
    1   a123   (mem >>  8) | (reg & 0xff000000)
    2   ab12   (mem >> 16) | (reg & 0xffff0000)
    3   abc1   (mem >> 24) | (reg & 0xffffff00)
    */
}

void InterpretedCPU::psxSB() { PCSX::g_emulator->m_psxMem->psxMemWrite8(_oB_, _u8(_rRt_)); }
void InterpretedCPU::psxSH() {
    if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebug>()) {
        if (_oB_ & 1) {
            m_psxRegs.pc -= 4;
            PCSX::g_system->printf(_("Unaligned address in SH from 0x%08x\n"), m_psxRegs.pc);
            psxException(Exceptions::StoreAddressError, m_inDelaySlot);
            return;
        }
    }
    PCSX::g_emulator->m_psxMem->psxMemWrite16(_oB_, _u16(_rRt_));
}

void InterpretedCPU::psxSW() {
    if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebug>()) {
        if (_oB_ & 3) {
            m_psxRegs.pc -= 4;
            PCSX::g_system->printf(_("Unaligned address in SW from 0x%08x\n"), m_psxRegs.pc);
            psxException(Exceptions::StoreAddressError, m_inDelaySlot);
            return;
        }
    }
    PCSX::g_emulator->m_psxMem->psxMemWrite32(_oB_, _u32(_rRt_));
}

void InterpretedCPU::psxSWL() {
    uint32_t addr = _oB_;
    uint32_t shift = addr & 3;
    uint32_t mem = PCSX::g_emulator->m_psxMem->psxMemRead32(addr & ~3);

    PCSX::g_emulator->m_psxMem->psxMemWrite32(addr & ~3, (_u32(_rRt_) >> SWL_SHIFT[shift]) | (mem & SWL_MASK[shift]));
    /*
    Mem = 1234.  Reg = abcd
    0   123a   (reg >> 24) | (mem & 0xffffff00)
    1   12ab   (reg >> 16) | (mem & 0xffff0000)
    2   1abc   (reg >>  8) | (mem & 0xff000000)
    3   abcd   (reg      ) | (mem & 0x00000000)
    */
}

void InterpretedCPU::psxSWR() {
    uint32_t addr = _oB_;
    uint32_t shift = addr & 3;
    uint32_t mem = PCSX::g_emulator->m_psxMem->psxMemRead32(addr & ~3);

    PCSX::g_emulator->m_psxMem->psxMemWrite32(addr & ~3, (_u32(_rRt_) << SWR_SHIFT[shift]) | (mem & SWR_MASK[shift]));

    /*
    Mem = 1234.  Reg = abcd
    0   abcd   (reg      ) | (mem & 0x00000000)
    1   bcd4   (reg <<  8) | (mem & 0x000000ff)
    2   cd34   (reg << 16) | (mem & 0x0000ffff)
    3   d234   (reg << 24) | (mem & 0x00ffffff)
    */
}

/*********************************************************
 * Moves between GPR and COPx                             *
 * Format:  OP rt, fs                                     *
 *********************************************************/
void InterpretedCPU::psxMFC0() {
    // load delay = 1 latency
    if (!_Rt_) return;
    _i32(delayedLoadRef(_Rt_)) = (int)_rFs_;
}

void InterpretedCPU::psxCFC0() {
    // load delay = 1 latency
    if (!_Rt_) return;
    _i32(delayedLoadRef(_Rt_)) = (int)_rFs_;
}

void InterpretedCPU::psxTestSWInts() {
    // the next code is untested, if u know please
    // tell me if it works ok or not (linuzappz)
    if (m_psxRegs.CP0.n.Cause & m_psxRegs.CP0.n.Status & 0x0300 && m_psxRegs.CP0.n.Status & 0x1) {
        bool inDelaySlot = m_inDelaySlot;
        m_inDelaySlot = false;
        psxException(m_psxRegs.CP0.n.Cause, inDelaySlot);
    }
}

inline void InterpretedCPU::MTC0(int reg, uint32_t val) {
    //  PCSX::g_system->printf("MTC0 %d: %x\n", reg, val);
    switch (reg) {
        case 12:  // Status
            m_psxRegs.CP0.n.Status = val;
            psxTestSWInts();
            break;

        case 13:  // Cause
            m_psxRegs.CP0.n.Cause = val & ~(0xfc00);
            psxTestSWInts();
            break;

        default:
            m_psxRegs.CP0.r[reg] = val;
            break;
    }
}

void InterpretedCPU::psxMTC0() { MTC0(_Rd_, _u32(_rRt_)); }
void InterpretedCPU::psxCTC0() { MTC0(_Rd_, _u32(_rRt_)); }

void InterpretedCPU::psxMFC2() {
    // load delay = 1 latency
    if (!_Rt_) return;
    delayedLoadRef(_Rt_) = PCSX::g_emulator->m_gte->MFC2();
}

void InterpretedCPU::psxCFC2() {
    // load delay = 1 latency
    if (!_Rt_) return;
    delayedLoadRef(_Rt_) = PCSX::g_emulator->m_gte->CFC2();
}

/*********************************************************
 * Unknown instruction (would generate an exception)     *
 *********************************************************/
void InterpretedCPU::psxNULL() {
    PSXCPU_LOG("psx: Unimplemented op %x\n", m_psxRegs.code);
    m_psxRegs.pc -= 4;
    PCSX::g_system->printf(_("Encountered reserved opcode from 0x%08x, firing an exception\n"), m_psxRegs.pc);
    psxException(Exceptions::ReservedInstruction, m_inDelaySlot);
}

void InterpretedCPU::psxSPECIAL() { (*this.*(s_pPsxSPC[_Funct_]))(); }

void InterpretedCPU::psxREGIMM() { (*this.*(s_pPsxREG[_Rt_]))(); }

void InterpretedCPU::psxCOP0() { (*this.*(s_pPsxCP0[_Rs_]))(); }

void InterpretedCPU::psxCOP1() {  // Accesses to the (nonexistent) FPU
    // TODO: Verify that COP1 doesn't throw a coprocessor unusable exception
    // Supposedly the COP1/COP3 ops don't fire RI, and they're NOPs
    PCSX::g_system->printf(_("Attempted to use an invalid floating point instruction from 0x%08x. Ignored.\n"),
                           m_psxRegs.pc - 4);
}

void InterpretedCPU::psxCOP2() {
    if ((m_psxRegs.CP0.n.Status & 0x40000000) == 0) return;

    (*this.*(s_pPsxCP2[_Funct_]))();
}

void InterpretedCPU::psxCOP3() {
    PCSX::g_system->printf(_("Attempted to access COP3 from 0x%08x. Ignored\n"), m_psxRegs.pc - 4);
}

void InterpretedCPU::psxBASIC() { (*this.*(s_pPsxCP2BSC[_Rs_]))(); }

const InterpretedCPU::intFunc_t InterpretedCPU::s_psxBSC[64] = {
    &InterpretedCPU::psxSPECIAL, &InterpretedCPU::psxREGIMM, &InterpretedCPU::psxJ,    &InterpretedCPU::psxJAL,    // 00
    &InterpretedCPU::psxBEQ,     &InterpretedCPU::psxBNE,    &InterpretedCPU::psxBLEZ, &InterpretedCPU::psxBGTZ,   // 04
    &InterpretedCPU::psxADDI,    &InterpretedCPU::psxADDIU,  &InterpretedCPU::psxSLTI, &InterpretedCPU::psxSLTIU,  // 08
    &InterpretedCPU::psxANDI,    &InterpretedCPU::psxORI,    &InterpretedCPU::psxXORI, &InterpretedCPU::psxLUI,    // 0c
    &InterpretedCPU::psxCOP0,    &InterpretedCPU::psxCOP1,   &InterpretedCPU::psxCOP2, &InterpretedCPU::psxCOP3,   // 10
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,   // 14
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,   // 18
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,   // 1c
    &InterpretedCPU::psxLB,      &InterpretedCPU::psxLH,     &InterpretedCPU::psxLWL,  &InterpretedCPU::psxLW,     // 20
    &InterpretedCPU::psxLBU,     &InterpretedCPU::psxLHU,    &InterpretedCPU::psxLWR,  &InterpretedCPU::psxNULL,   // 24
    &InterpretedCPU::psxSB,      &InterpretedCPU::psxSH,     &InterpretedCPU::psxSWL,  &InterpretedCPU::psxSW,     // 28
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxSWR,  &InterpretedCPU::psxNULL,   // 2c
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::gteLWC2, &InterpretedCPU::psxNULL,   // 30
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,   // 34
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::gteSWC2, &InterpretedCPU::psxNULL,   // 38
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,   // 3c
};

const InterpretedCPU::intFunc_t InterpretedCPU::s_psxSPC[64] = {
    &InterpretedCPU::psxSLL,     &InterpretedCPU::psxNULL,  &InterpretedCPU::psxSRL,  &InterpretedCPU::psxSRA,   // 00
    &InterpretedCPU::psxSLLV,    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxSRLV, &InterpretedCPU::psxSRAV,  // 04
    &InterpretedCPU::psxJR,      &InterpretedCPU::psxJALR,  &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 08
    &InterpretedCPU::psxSYSCALL, &InterpretedCPU::psxBREAK, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 0c
    &InterpretedCPU::psxMFHI,    &InterpretedCPU::psxMTHI,  &InterpretedCPU::psxMFLO, &InterpretedCPU::psxMTLO,  // 10
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 14
    &InterpretedCPU::psxMULT,    &InterpretedCPU::psxMULTU, &InterpretedCPU::psxDIV,  &InterpretedCPU::psxDIVU,  // 18
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 1c
    &InterpretedCPU::psxADD,     &InterpretedCPU::psxADDU,  &InterpretedCPU::psxSUB,  &InterpretedCPU::psxSUBU,  // 20
    &InterpretedCPU::psxAND,     &InterpretedCPU::psxOR,    &InterpretedCPU::psxXOR,  &InterpretedCPU::psxNOR,   // 24
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxSLT,  &InterpretedCPU::psxSLTU,  // 28
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 2c
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 30
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 34
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 38
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 3c
};

const InterpretedCPU::intFunc_t InterpretedCPU::s_psxREG[32] = {
    &InterpretedCPU::psxBLTZ,   &InterpretedCPU::psxBGEZ,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 00
    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 04
    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 08
    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 0c
    &InterpretedCPU::psxBLTZAL, &InterpretedCPU::psxBGEZAL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 10
    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 14
    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 18
    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 1c
};

const InterpretedCPU::intFunc_t InterpretedCPU::s_psxCP0[32] = {
    &InterpretedCPU::psxMFC0, &InterpretedCPU::psxNULL, &InterpretedCPU::psxCFC0, &InterpretedCPU::psxNULL,  // 00
    &InterpretedCPU::psxMTC0, &InterpretedCPU::psxNULL, &InterpretedCPU::psxCTC0, &InterpretedCPU::psxNULL,  // 04
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 08
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 0c
    &InterpretedCPU::psxRFE,  &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 10
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 14
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 18
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 1c
};

const InterpretedCPU::intFunc_t InterpretedCPU::s_psxCP2[64] = {
    &InterpretedCPU::psxBASIC, &InterpretedCPU::gteRTPS,  &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  // 00
    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  &InterpretedCPU::gteNCLIP, &InterpretedCPU::psxNULL,  // 04
    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  // 08
    &InterpretedCPU::gteOP,    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  // 0c
    &InterpretedCPU::gteDPCS,  &InterpretedCPU::gteINTPL, &InterpretedCPU::gteMVMVA, &InterpretedCPU::gteNCDS,  // 10
    &InterpretedCPU::gteCDP,   &InterpretedCPU::psxNULL,  &InterpretedCPU::gteNCDT,  &InterpretedCPU::psxNULL,  // 14
    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  &InterpretedCPU::gteNCCS,  // 18
    &InterpretedCPU::gteCC,    &InterpretedCPU::psxNULL,  &InterpretedCPU::gteNCS,   &InterpretedCPU::psxNULL,  // 1c
    &InterpretedCPU::gteNCT,   &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  // 20
    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  // 24
    &InterpretedCPU::gteSQR,   &InterpretedCPU::gteDCPL,  &InterpretedCPU::gteDPCT,  &InterpretedCPU::psxNULL,  // 28
    &InterpretedCPU::psxNULL,  &InterpretedCPU::gteAVSZ3, &InterpretedCPU::gteAVSZ4, &InterpretedCPU::psxNULL,  // 2c
    &InterpretedCPU::gteRTPT,  &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  // 30
    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  // 34
    &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  &InterpretedCPU::psxNULL,  // 38
    &InterpretedCPU::psxNULL,  &InterpretedCPU::gteGPF,   &InterpretedCPU::gteGPL,   &InterpretedCPU::gteNCCT,  // 3c
};

const InterpretedCPU::intFunc_t InterpretedCPU::s_psxCP2BSC[32] = {
    &InterpretedCPU::psxMFC2, &InterpretedCPU::psxNULL, &InterpretedCPU::psxCFC2, &InterpretedCPU::psxNULL,  // 00
    &InterpretedCPU::gteMTC2, &InterpretedCPU::psxNULL, &InterpretedCPU::gteCTC2, &InterpretedCPU::psxNULL,  // 04
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 08
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 0c
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 10
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 14
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 18
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 1c
};

/////////////////////////////////////////////
// PGXP wrapper functions
/////////////////////////////////////////////

void InterpretedCPU::pgxpPsxNULL() {}

#define psxMTC2 gteMTC2
#define psxCTC2 gteCTC2
#define psxLWC2 gteLWC2
#define psxSWC2 gteSWC2

// Choose between debug and direct function
#ifdef PGXP_CPU_DEBUG
#define PGXP_PSX_FUNC_OP(pu, op, nReg) PGXP_psxTraceOp##nReg
#define PGXP_DBG_OP_E(op) DBG_E_##op,
#else
#define PGXP_PSX_FUNC_OP(pu, op, nReg) PGXP_##pu##_##op
#define PGXP_DBG_OP_E(op)
#endif

#define PGXP_INT_FUNC(pu, op)                                         \
    void InterpretedCPU::pgxpPsx##op() {                              \
        PGXP_PSX_FUNC_OP(pu, op, )(PGXP_DBG_OP_E(op) m_psxRegs.code); \
        psx##op();                                                    \
    }

#define PGXP_INT_FUNC_0_1(pu, op, test, nReg, reg1)                        \
    void InterpretedCPU::pgxpPsx##op() {                                   \
        if (test) {                                                        \
            psx##op();                                                     \
            return;                                                        \
        }                                                                  \
        uint32_t tempInstr = m_psxRegs.code;                               \
        psx##op();                                                         \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1); \
    }

#define PGXP_INT_FUNC_1_0(pu, op, test, nReg, reg1)                           \
    void InterpretedCPU::pgxpPsx##op() {                                      \
        if (test) {                                                           \
            psx##op();                                                        \
            return;                                                           \
        }                                                                     \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) psxRegs.code, reg1); \
        psx##op();                                                            \
    }

#define PGXP_INT_FUNC_1_1(pu, op, test, nReg, reg1, reg2)                         \
    void InterpretedCPU::pgxpPsx##op() {                                          \
        if (test) {                                                               \
            psx##op();                                                            \
            return;                                                               \
        }                                                                         \
        uint32_t tempInstr = m_psxRegs.code;                                      \
        uint32_t temp2 = reg2;                                                    \
        psx##op();                                                                \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, temp2); \
    }

#define PGXP_INT_FUNC_0_2(pu, op, test, nReg, reg1, reg2)                        \
    void InterpretedCPU::pgxpPsx##op() {                                         \
        if (test) {                                                              \
            psx##op();                                                           \
            return;                                                              \
        }                                                                        \
        uint32_t tempInstr = m_psxRegs.code;                                     \
        psx##op();                                                               \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, reg2); \
    }

#define PGXP_INT_FUNC_2_0(pu, op, test, nReg, reg1, reg2)                          \
    void InterpretedCPU::pgxpPsx##op() {                                           \
        if (test) {                                                                \
            psx##op();                                                             \
            return;                                                                \
        }                                                                          \
        uint32_t tempInstr = m_psxRegs.code;                                       \
        uint32_t temp1 = reg1;                                                     \
        uint32_t temp2 = reg2;                                                     \
        psx##op();                                                                 \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, temp1, temp2); \
    }

#define PGXP_INT_FUNC_2_1(pu, op, test, nReg, reg1, reg2, reg3)                          \
    void InterpretedCPU::pgxpPsx##op() {                                                 \
        if (test) {                                                                      \
            psx##op();                                                                   \
            return;                                                                      \
        }                                                                                \
        uint32_t tempInstr = m_psxRegs.code;                                             \
        uint32_t temp2 = reg2;                                                           \
        uint32_t temp3 = reg3;                                                           \
        psx##op();                                                                       \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, temp2, temp3); \
    }

#define PGXP_INT_FUNC_2_2(pu, op, test, nReg, reg1, reg2, reg3, reg4)                          \
    void InterpretedCPU::pgxpPsx##op() {                                                       \
        if (test) {                                                                            \
            psx##op();                                                                         \
            return;                                                                            \
        }                                                                                      \
        uint32_t tempInstr = m_psxRegs.code;                                                   \
        uint32_t temp3 = reg3;                                                                 \
        uint32_t temp4 = reg4;                                                                 \
        psx##op();                                                                             \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, reg2, temp3, temp4); \
    }

// Rt = Rs op imm
PGXP_INT_FUNC_1_1(CPU, ADDI, !_Rt_, 2, m_psxRegs.GPR.r[_Rt_], m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, ADDIU, !_Rt_, 2, m_psxRegs.GPR.r[_Rt_], m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, ANDI, !_Rt_, 2, m_psxRegs.GPR.r[_Rt_], m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, ORI, !_Rt_, 2, m_psxRegs.GPR.r[_Rt_], m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, XORI, !_Rt_, 2, m_psxRegs.GPR.r[_Rt_], m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, SLTI, !_Rt_, 2, m_psxRegs.GPR.r[_Rt_], m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, SLTIU, !_Rt_, 2, m_psxRegs.GPR.r[_Rt_], m_psxRegs.GPR.r[_Rs_])

// Rt = imm
PGXP_INT_FUNC_0_1(CPU, LUI, !_Rt_, 1, m_psxRegs.GPR.r[_Rt_])

// Rd = Rs op Rt
PGXP_INT_FUNC_2_1(CPU, ADD, !_Rd_, 3, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rs_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, ADDU, !_Rd_, 3, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rs_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SUB, !_Rd_, 3, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rs_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SUBU, !_Rd_, 3, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rs_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, AND, !_Rd_, 3, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rs_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, OR, !_Rd_, 3, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rs_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, XOR, !_Rd_, 3, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rs_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, NOR, !_Rd_, 3, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rs_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SLT, !_Rd_, 3, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rs_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SLTU, !_Rd_, 3, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rs_], m_psxRegs.GPR.r[_Rt_])

// Hi/Lo = Rs op Rt
PGXP_INT_FUNC_2_2(CPU, MULT, 0, 4, m_psxRegs.GPR.n.hi, m_psxRegs.GPR.n.lo, m_psxRegs.GPR.r[_Rs_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_2(CPU, MULTU, 0, 4, m_psxRegs.GPR.n.hi, m_psxRegs.GPR.n.lo, m_psxRegs.GPR.r[_Rs_],
                  m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_2(CPU, DIV, 0, 4, m_psxRegs.GPR.n.hi, m_psxRegs.GPR.n.lo, m_psxRegs.GPR.r[_Rs_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_2(CPU, DIVU, 0, 4, m_psxRegs.GPR.n.hi, m_psxRegs.GPR.n.lo, m_psxRegs.GPR.r[_Rs_], m_psxRegs.GPR.r[_Rt_])

// Mem[addr] = Rt
PGXP_INT_FUNC_1_1(CPU, SB, 0, 2, m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SH, 0, 2, m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SW, 0, 2, m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SWL, 0, 2, m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SWR, 0, 2, m_psxRegs.GPR.r[_Rt_], _oB_)

// Rt = Mem[addr]
PGXP_INT_FUNC_1_1(CPU, LWL, 0, 2, m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LW, 0, 2, m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LWR, 0, 2, m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LH, 0, 2, m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LHU, 0, 2, m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LB, 0, 2, m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LBU, 0, 2, m_psxRegs.GPR.r[_Rt_], _oB_)

// Rd = Rt op Sa
PGXP_INT_FUNC_1_1(CPU, SLL, !_Rd_, 2, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(CPU, SRL, !_Rd_, 2, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(CPU, SRA, !_Rd_, 2, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rt_])

// Rd = Rt op Rs
PGXP_INT_FUNC_2_1(CPU, SLLV, !_Rd_, 3, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rt_], m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_2_1(CPU, SRLV, !_Rd_, 3, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rt_], m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_2_1(CPU, SRAV, !_Rd_, 3, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.r[_Rt_], m_psxRegs.GPR.r[_Rs_])

PGXP_INT_FUNC_1_1(CPU, MFHI, !_Rd_, 2, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.n.hi)
PGXP_INT_FUNC_1_1(CPU, MTHI, 0, 2, m_psxRegs.GPR.n.hi, m_psxRegs.GPR.r[_Rd_])
PGXP_INT_FUNC_1_1(CPU, MFLO, !_Rd_, 2, m_psxRegs.GPR.r[_Rd_], m_psxRegs.GPR.n.lo)
PGXP_INT_FUNC_1_1(CPU, MTLO, 0, 2, m_psxRegs.GPR.n.lo, m_psxRegs.GPR.r[_Rd_])

// COP2 (GTE)
PGXP_INT_FUNC_1_1(GTE, MFC2, !_Rt_, 2, m_psxRegs.GPR.r[_Rt_], m_psxRegs.CP2D.r[_Rd_])
PGXP_INT_FUNC_1_1(GTE, CFC2, !_Rt_, 2, m_psxRegs.GPR.r[_Rt_], m_psxRegs.CP2C.r[_Rd_])
PGXP_INT_FUNC_1_1(GTE, MTC2, 0, 2, m_psxRegs.CP2D.r[_Rd_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(GTE, CTC2, 0, 2, m_psxRegs.CP2C.r[_Rd_], m_psxRegs.GPR.r[_Rt_])

PGXP_INT_FUNC_1_1(GTE, LWC2, 0, 2, m_psxRegs.CP2D.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(GTE, SWC2, 0, 2, m_psxRegs.CP2D.r[_Rt_], _oB_)

// COP0
PGXP_INT_FUNC_1_1(CP0, MFC0, !_Rd_, 2, m_psxRegs.GPR.r[_Rt_], m_psxRegs.CP0.r[_Rd_])
PGXP_INT_FUNC_1_1(CP0, CFC0, !_Rd_, 2, m_psxRegs.GPR.r[_Rt_], m_psxRegs.CP0.r[_Rd_])
PGXP_INT_FUNC_1_1(CP0, MTC0, !_Rt_, 2, m_psxRegs.CP0.r[_Rd_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(CP0, CTC0, !_Rt_, 2, m_psxRegs.CP0.r[_Rd_], m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC(CP0, RFE)

// end of PGXP

// Trace all functions using PGXP
const InterpretedCPU::intFunc_t InterpretedCPU::s_pgxpPsxBSC[64] = {
    &InterpretedCPU::psxSPECIAL,  &InterpretedCPU::psxREGIMM,     // 00
    &InterpretedCPU::psxJ,        &InterpretedCPU::psxJAL,        // 02
    &InterpretedCPU::psxBEQ,      &InterpretedCPU::psxBNE,        // 04
    &InterpretedCPU::psxBLEZ,     &InterpretedCPU::psxBGTZ,       // 06
    &InterpretedCPU::pgxpPsxADDI, &InterpretedCPU::pgxpPsxADDIU,  // 08
    &InterpretedCPU::pgxpPsxSLTI, &InterpretedCPU::pgxpPsxSLTIU,  // 0a
    &InterpretedCPU::pgxpPsxANDI, &InterpretedCPU::pgxpPsxORI,    // 0c
    &InterpretedCPU::pgxpPsxXORI, &InterpretedCPU::pgxpPsxLUI,    // 0e
    &InterpretedCPU::psxCOP0,     &InterpretedCPU::psxNULL,       // 10
    &InterpretedCPU::psxCOP2,     &InterpretedCPU::psxNULL,       // 12
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 14
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 16
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 18
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 1a
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 1c
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 1e
    &InterpretedCPU::pgxpPsxLB,   &InterpretedCPU::pgxpPsxLH,     // 20
    &InterpretedCPU::pgxpPsxLWL,  &InterpretedCPU::pgxpPsxLW,     // 22
    &InterpretedCPU::pgxpPsxLBU,  &InterpretedCPU::pgxpPsxLHU,    // 24
    &InterpretedCPU::pgxpPsxLWR,  &InterpretedCPU::pgxpPsxNULL,   // 26
    &InterpretedCPU::pgxpPsxSB,   &InterpretedCPU::pgxpPsxSH,     // 28
    &InterpretedCPU::pgxpPsxSWL,  &InterpretedCPU::pgxpPsxSW,     // 2a
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 2c
    &InterpretedCPU::pgxpPsxSWR,  &InterpretedCPU::pgxpPsxNULL,   // 2e
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 30
    &InterpretedCPU::pgxpPsxLWC2, &InterpretedCPU::psxNULL,       // 32
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 34
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 36
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 38
    &InterpretedCPU::pgxpPsxSWC2, &InterpretedCPU::psxNULL,       // 3a
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 3c
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 3e
};

const InterpretedCPU::intFunc_t InterpretedCPU::s_pgxpPsxSPC[64] = {
    &InterpretedCPU::pgxpPsxSLL,  &InterpretedCPU::pgxpPsxNULL,   // 00
    &InterpretedCPU::pgxpPsxSRL,  &InterpretedCPU::pgxpPsxSRA,    // 02
    &InterpretedCPU::pgxpPsxSLLV, &InterpretedCPU::pgxpPsxNULL,   // 04
    &InterpretedCPU::pgxpPsxSRLV, &InterpretedCPU::pgxpPsxSRAV,   // 06
    &InterpretedCPU::psxJR,       &InterpretedCPU::psxJALR,       // 08
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 0a
    &InterpretedCPU::psxSYSCALL,  &InterpretedCPU::psxBREAK,      // 0c
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 0e
    &InterpretedCPU::pgxpPsxMFHI, &InterpretedCPU::pgxpPsxMTHI,   // 10
    &InterpretedCPU::pgxpPsxMFLO, &InterpretedCPU::pgxpPsxMTLO,   // 12
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 14
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 16
    &InterpretedCPU::pgxpPsxMULT, &InterpretedCPU::pgxpPsxMULTU,  // 18
    &InterpretedCPU::pgxpPsxDIV,  &InterpretedCPU::pgxpPsxDIVU,   // 1a
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 1c
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 1e
    &InterpretedCPU::pgxpPsxADD,  &InterpretedCPU::pgxpPsxADDU,   // 20
    &InterpretedCPU::pgxpPsxSUB,  &InterpretedCPU::pgxpPsxSUBU,   // 22
    &InterpretedCPU::pgxpPsxAND,  &InterpretedCPU::pgxpPsxOR,     // 24
    &InterpretedCPU::pgxpPsxXOR,  &InterpretedCPU::pgxpPsxNOR,    // 26
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 28
    &InterpretedCPU::pgxpPsxSLT,  &InterpretedCPU::pgxpPsxSLTU,   // 2a
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 2c
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 2e
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 30
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 32
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 34
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 36
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 38
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 3a
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 3c
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,   // 3e
};

const InterpretedCPU::intFunc_t InterpretedCPU::s_pgxpPsxCP0[32] = {
    &InterpretedCPU::pgxpPsxMFC0, &InterpretedCPU::pgxpPsxNULL,  // 00
    &InterpretedCPU::pgxpPsxCFC0, &InterpretedCPU::pgxpPsxNULL,  // 02
    &InterpretedCPU::pgxpPsxMTC0, &InterpretedCPU::pgxpPsxNULL,  // 04
    &InterpretedCPU::pgxpPsxCTC0, &InterpretedCPU::pgxpPsxNULL,  // 06
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 08
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 0a
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 0c
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 0e
    &InterpretedCPU::pgxpPsxRFE,  &InterpretedCPU::pgxpPsxNULL,  // 10
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 12
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 14
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 16
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 18
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 1a
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 1c
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 1e
};

const InterpretedCPU::intFunc_t InterpretedCPU::s_pgxpPsxCP2BSC[32] = {
    &InterpretedCPU::pgxpPsxMFC2, &InterpretedCPU::pgxpPsxNULL,  // 00
    &InterpretedCPU::pgxpPsxCFC2, &InterpretedCPU::pgxpPsxNULL,  // 02
    &InterpretedCPU::pgxpPsxMTC2, &InterpretedCPU::pgxpPsxNULL,  // 04
    &InterpretedCPU::pgxpPsxCTC2, &InterpretedCPU::pgxpPsxNULL,  // 06
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 08
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 0a
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 0c
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 0e
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 10
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 12
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 14
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 16
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 18
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 1a
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 1c
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 1e
};

// Trace memory functions only
const InterpretedCPU::intFunc_t InterpretedCPU::s_pgxpPsxBSCMem[64] = {
    &InterpretedCPU::psxSPECIAL,  &InterpretedCPU::psxREGIMM,    // 00
    &InterpretedCPU::psxJ,        &InterpretedCPU::psxJAL,       // 02
    &InterpretedCPU::psxBEQ,      &InterpretedCPU::psxBNE,       // 04
    &InterpretedCPU::psxBLEZ,     &InterpretedCPU::psxBGTZ,      // 06
    &InterpretedCPU::psxADDI,     &InterpretedCPU::psxADDIU,     // 08
    &InterpretedCPU::psxSLTI,     &InterpretedCPU::psxSLTIU,     // 0a
    &InterpretedCPU::psxANDI,     &InterpretedCPU::psxORI,       // 0c
    &InterpretedCPU::psxXORI,     &InterpretedCPU::psxLUI,       // 0e
    &InterpretedCPU::psxCOP0,     &InterpretedCPU::psxNULL,      // 10
    &InterpretedCPU::psxCOP2,     &InterpretedCPU::psxNULL,      // 12
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,      // 14
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,      // 16
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,      // 18
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,      // 1a
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,      // 1c
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,      // 1e
    &InterpretedCPU::pgxpPsxLB,   &InterpretedCPU::pgxpPsxLH,    // 20
    &InterpretedCPU::pgxpPsxLWL,  &InterpretedCPU::pgxpPsxLW,    // 22
    &InterpretedCPU::pgxpPsxLBU,  &InterpretedCPU::pgxpPsxLHU,   // 24
    &InterpretedCPU::pgxpPsxLWR,  &InterpretedCPU::pgxpPsxNULL,  // 26
    &InterpretedCPU::pgxpPsxSB,   &InterpretedCPU::pgxpPsxSH,    // 28
    &InterpretedCPU::pgxpPsxSWL,  &InterpretedCPU::pgxpPsxSW,    // 2a
    &InterpretedCPU::pgxpPsxNULL, &InterpretedCPU::pgxpPsxNULL,  // 2c
    &InterpretedCPU::pgxpPsxSWR,  &InterpretedCPU::pgxpPsxNULL,  // 2e
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,      // 30
    &InterpretedCPU::pgxpPsxLWC2, &InterpretedCPU::psxNULL,      // 32
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,      // 34
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,      // 36
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,      // 38
    &InterpretedCPU::pgxpPsxSWC2, &InterpretedCPU::psxNULL,      // 3a
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,      // 3c
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,      // 3e
};

///////////////////////////////////////////

bool InterpretedCPU::Init() { return true; }
void InterpretedCPU::Reset() {
    R3000Acpu::Reset();
    m_nextIsDelaySlot = false;
    m_inDelaySlot = false;
    m_delayedLoadInfo[0].active = false;
    m_delayedLoadInfo[1].active = false;
    m_delayedLoadInfo[0].pcActive = false;
    m_delayedLoadInfo[1].pcActive = false;
}
void InterpretedCPU::Execute() {
    ZoneScoped;
    while (hasToRun()) {
        const bool &debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebug>();
        if (debug) {
            execBlock<true>();
        } else {
            execBlock<false>();
        }
    }
}
void InterpretedCPU::Clear(uint32_t Addr, uint32_t Size) {}
void InterpretedCPU::Shutdown() {}
// interpreter execution
template <bool debug>
inline void InterpretedCPU::execBlock() {
    bool ranDelaySlot = false;
    while (!ranDelaySlot) {
        if (m_nextIsDelaySlot) {
            m_inDelaySlot = true;
            m_nextIsDelaySlot = false;
        }
        uint32_t *code = Read_ICache(m_psxRegs.pc);
        m_psxRegs.code = ((code == NULL) ? 0 : SWAP_LE32(*code));

        if (PCSX::PSXCPU_LOGGER::c_enabled && PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVerbose>()) {
            std::string ins = PCSX::Disasm::asString(m_psxRegs.code, 0, m_psxRegs.pc, nullptr, true);
            PSXCPU_LOG("%s\n", ins.c_str());
        }

        if (debug) PCSX::g_emulator->m_debug->processBefore();

        m_psxRegs.pc += 4;
        m_psxRegs.cycle += PCSX::Emulator::BIAS;

        cIntFunc_t func = s_pPsxBSC[m_psxRegs.code >> 26];
        (*this.*func)();

        m_currentDelayedLoad ^= 1;
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        if (delayedLoad.active) {
            m_psxRegs.GPR.r[delayedLoad.index] &= delayedLoad.mask;
            m_psxRegs.GPR.r[delayedLoad.index] |= delayedLoad.value;
            delayedLoad.active = false;
        }
        if (delayedLoad.pcActive) {
            m_psxRegs.pc = delayedLoad.pcValue;
            delayedLoad.pcActive = false;
        }
        if (m_inDelaySlot) {
            m_inDelaySlot = false;
            ranDelaySlot = true;
            InterceptBIOS();
            psxBranchTest();
        }
        if (debug) PCSX::g_emulator->m_debug->processAfter();
    }
}

void InterpretedCPU::SetPGXPMode(uint32_t pgxpMode) {
    switch (pgxpMode) {
        case 0:  // PGXP_MODE_DISABLED:
            s_pPsxBSC = s_psxBSC;
            s_pPsxSPC = s_psxSPC;
            s_pPsxREG = s_psxREG;
            s_pPsxCP0 = s_psxCP0;
            s_pPsxCP2 = s_psxCP2;
            s_pPsxCP2BSC = s_psxCP2BSC;
            break;
        case 1:  // PGXP_MODE_MEM:
            s_pPsxBSC = s_pgxpPsxBSCMem;
            s_pPsxSPC = s_psxSPC;
            s_pPsxREG = s_psxREG;
            s_pPsxCP0 = s_pgxpPsxCP0;
            s_pPsxCP2 = s_psxCP2;
            s_pPsxCP2BSC = s_pgxpPsxCP2BSC;
            break;
        case 2:  // PGXP_MODE_FULL:
            s_pPsxBSC = s_pgxpPsxBSC;
            s_pPsxSPC = s_pgxpPsxSPC;
            s_pPsxREG = s_psxREG;
            s_pPsxCP0 = s_pgxpPsxCP0;
            s_pPsxCP2 = s_psxCP2;
            s_pPsxCP2BSC = s_pgxpPsxCP2BSC;
            break;
    }

    // reset to ensure new func tables are used
    InterpretedCPU::Reset();
}

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::getInterpreted() {
    return std::unique_ptr<PCSX::R3000Acpu>(new InterpretedCPU());
}
