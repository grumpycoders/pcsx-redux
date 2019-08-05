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
#include "core/psxhle.h"
#include "core/r3000a.h"

/* GTE wrappers */
#define GTE_WR(n) \
    void PCSX::InterpretedCPU::gte##n() { PCSX::g_emulator.m_gte->n(); }
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

#define debugI()                                                                                                      \
    if (PCSX::g_emulator.settings.get<PCSX::Emulator::SettingVerbose>()) {                                            \
        std::string ins = Disasm::asString(g_emulator.m_psxCpu->m_psxRegs.code, 0, g_emulator.m_psxCpu->m_psxRegs.pc, \
                                           nullptr, true);                                                            \
        PSXCPU_LOG("%s\n", ins.c_str());                                                                              \
    }

inline void PCSX::InterpretedCPU::doBranch(uint32_t tar) {
    m_nextIsDelaySlot = true;
    delayedPCLoad(tar);
}

/*********************************************************
 * Arithmetic with immediate operand                      *
 * Format:  OP rt, rs, immediate                          *
 *********************************************************/
void PCSX::InterpretedCPU::psxADDI() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) + _Imm_;
}  // Rt = Rs + Im      (Exception on Integer Overflow)
void PCSX::InterpretedCPU::psxADDIU() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) + _Imm_;
}  // Rt = Rs + Im
void PCSX::InterpretedCPU::psxANDI() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) & _ImmU_;
}  // Rt = Rs And Im
void PCSX::InterpretedCPU::psxORI() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) | _ImmU_;
}  // Rt = Rs Or  Im
void PCSX::InterpretedCPU::psxXORI() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) ^ _ImmU_;
}  // Rt = Rs Xor Im
void PCSX::InterpretedCPU::psxSLTI() {
    if (!_Rt_) return;
    _rRt_ = _i32(_rRs_) < _Imm_;
}  // Rt = Rs < Im              (Signed)
void PCSX::InterpretedCPU::psxSLTIU() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) < ((uint32_t)_Imm_);
}  // Rt = Rs < Im              (Unsigned)

/*********************************************************
 * Register arithmetic                                    *
 * Format:  OP rd, rs, rt                                 *
 *********************************************************/
void PCSX::InterpretedCPU::psxADD() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) + _u32(_rRt_);
}  // Rd = Rs + Rt              (Exception on Integer Overflow)
void PCSX::InterpretedCPU::psxADDU() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) + _u32(_rRt_);
}  // Rd = Rs + Rt
void PCSX::InterpretedCPU::psxSUB() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) - _u32(_rRt_);
}  // Rd = Rs - Rt              (Exception on Integer Overflow)
void PCSX::InterpretedCPU::psxSUBU() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) - _u32(_rRt_);
}  // Rd = Rs - Rt
void PCSX::InterpretedCPU::psxAND() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) & _u32(_rRt_);
}  // Rd = Rs And Rt
void PCSX::InterpretedCPU::psxOR() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) | _u32(_rRt_);
}  // Rd = Rs Or  Rt
void PCSX::InterpretedCPU::psxXOR() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) ^ _u32(_rRt_);
}  // Rd = Rs Xor Rt
void PCSX::InterpretedCPU::psxNOR() {
    if (!_Rd_) return;
    _rRd_ = ~(_u32(_rRs_) | _u32(_rRt_));
}  // Rd = Rs Nor Rt
void PCSX::InterpretedCPU::psxSLT() {
    if (!_Rd_) return;
    _rRd_ = _i32(_rRs_) < _i32(_rRt_);
}  // Rd = Rs < Rt              (Signed)
void PCSX::InterpretedCPU::psxSLTU() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) < _u32(_rRt_);
}  // Rd = Rs < Rt              (Unsigned)

/*********************************************************
 * Register mult/div & Register trap logic                *
 * Format:  OP rs, rt                                     *
 *********************************************************/
void PCSX::InterpretedCPU::psxDIV() {
    if (!_i32(_rRt_)) {
        if (_i32(_rRs_) & 0x80000000) {
            _i32(_rLo_) = 1;
        } else {
            _i32(_rLo_) = 0xFFFFFFFF;
            _i32(_rHi_) = _i32(_rRs_);
        }
    } else if (_i32(_rRs_) == 0x80000000 && _i32(_rRt_) == 0xFFFFFFFF) {
        _i32(_rLo_) = 0x80000000;
        _i32(_rHi_) = 0;
    } else {
        _i32(_rLo_) = _i32(_rRs_) / _i32(_rRt_);
        _i32(_rHi_) = _i32(_rRs_) % _i32(_rRt_);
    }
}

void PCSX::InterpretedCPU::psxDIVU() {
    if (_rRt_ != 0) {
        _rLo_ = _rRs_ / _rRt_;
        _rHi_ = _rRs_ % _rRt_;
    } else {
        _rLo_ = 0xffffffff;
        _rHi_ = _rRs_;
    }
}

void PCSX::InterpretedCPU::psxMULT() {
    uint64_t res = (int64_t)((int64_t)_i32(_rRs_) * (int64_t)_i32(_rRt_));

    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.lo = (uint32_t)(res & 0xffffffff);
    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.hi = (uint32_t)((res >> 32) & 0xffffffff);
}

void PCSX::InterpretedCPU::psxMULTU() {
    uint64_t res = (uint64_t)((uint64_t)_u32(_rRs_) * (uint64_t)_u32(_rRt_));

    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.lo = (uint32_t)(res & 0xffffffff);
    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.hi = (uint32_t)((res >> 32) & 0xffffffff);
}

/*********************************************************
 * Register branch logic                                  *
 * Format:  OP rs, offset                                 *
 *********************************************************/
#define RepZBranchi32(op) if (_i32(_rRs_) op 0) doBranch(_BranchTarget_);                                     
#define RepZBranchLinki32(op)     \
    if (_i32(_rRs_) op 0) {       \
        _SetLink(31);             \
        doBranch(_BranchTarget_); \
    }

void PCSX::InterpretedCPU::psxBGEZ() { RepZBranchi32(>=) }        // Branch if Rs >= 0
void PCSX::InterpretedCPU::psxBGEZAL() { RepZBranchLinki32(>=) }  // Branch if Rs >= 0 and link
void PCSX::InterpretedCPU::psxBGTZ() { RepZBranchi32(>) }         // Branch if Rs >  0
void PCSX::InterpretedCPU::psxBLEZ() { RepZBranchi32(<=) }        // Branch if Rs <= 0
void PCSX::InterpretedCPU::psxBLTZ() { RepZBranchi32(<) }         // Branch if Rs <  0
void PCSX::InterpretedCPU::psxBLTZAL() { RepZBranchLinki32(<) }   // Branch if Rs <  0 and link

/*********************************************************
 * Shift arithmetic with constant shift                   *
 * Format:  OP rd, rt, sa                                 *
 *********************************************************/
void PCSX::InterpretedCPU::psxSLL() {
    if (!_Rd_) return;
    _u32(_rRd_) = _u32(_rRt_) << _Sa_;
}  // Rd = Rt << sa
void PCSX::InterpretedCPU::psxSRA() {
    if (!_Rd_) return;
    _i32(_rRd_) = _i32(_rRt_) >> _Sa_;
}  // Rd = Rt >> sa (arithmetic)
void PCSX::InterpretedCPU::psxSRL() {
    if (!_Rd_) return;
    _u32(_rRd_) = _u32(_rRt_) >> _Sa_;
}  // Rd = Rt >> sa (logical)

/*********************************************************
 * Shift arithmetic with variant register shift           *
 * Format:  OP rd, rt, rs                                 *
 *********************************************************/
void PCSX::InterpretedCPU::psxSLLV() {
    if (!_Rd_) return;
    _u32(_rRd_) = _u32(_rRt_) << _u32(_rRs_);
}  // Rd = Rt << rs
void PCSX::InterpretedCPU::psxSRAV() {
    if (!_Rd_) return;
    _i32(_rRd_) = _i32(_rRt_) >> _u32(_rRs_);
}  // Rd = Rt >> rs (arithmetic)
void PCSX::InterpretedCPU::psxSRLV() {
    if (!_Rd_) return;
    _u32(_rRd_) = _u32(_rRt_) >> _u32(_rRs_);
}  // Rd = Rt >> rs (logical)

/*********************************************************
 * Load higher 16 bits of the first word in GPR with imm  *
 * Format:  OP rt, immediate                              *
 *********************************************************/
void PCSX::InterpretedCPU::psxLUI() {
    if (!_Rt_) return;
    _u32(_rRt_) = _ImmLU_;
}  // Upper halfword of Rt = Im

/*********************************************************
 * Move from HI/LO to GPR                                 *
 * Format:  OP rd                                         *
 *********************************************************/
void PCSX::InterpretedCPU::psxMFHI() {
    if (!_Rd_) return;
    _rRd_ = _rHi_;
}  // Rd = Hi
void PCSX::InterpretedCPU::psxMFLO() {
    if (!_Rd_) return;
    _rRd_ = _rLo_;
}  // Rd = Lo

/*********************************************************
 * Move to GPR to HI/LO & Register jump                   *
 * Format:  OP rs                                         *
 *********************************************************/
void PCSX::InterpretedCPU::psxMTHI() { _rHi_ = _rRs_; }  // Hi = Rs
void PCSX::InterpretedCPU::psxMTLO() { _rLo_ = _rRs_; }  // Lo = Rs

/*********************************************************
 * Special purpose instructions                           *
 * Format:  OP                                            *
 *********************************************************/
void PCSX::InterpretedCPU::psxBREAK() {
    // Break exception - psx rom doens't handles this
}

void PCSX::InterpretedCPU::psxSYSCALL() {
    PCSX::g_emulator.m_psxCpu->m_psxRegs.pc -= 4;
    PCSX::g_emulator.m_psxCpu->psxException(0x20, m_inDelaySlot);
    if (m_inDelaySlot) {
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        if (!delayedLoad.pcActive) abort();
        delayedLoad.pcActive = false;
    }
}

void PCSX::InterpretedCPU::psxRFE() {
    //  PCSX::g_system->printf("psxRFE\n");
    PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status =
        (PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status & 0xfffffff0) |
        ((PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status & 0x3c) >> 2);
    psxTestSWInts();
}

/*********************************************************
 * Register branch logic                                  *
 * Format:  OP rs, rt, offset                             *
 *********************************************************/
#define RepBranchi32(op) if (_i32(_rRs_) op _i32(_rRt_)) doBranch(_BranchTarget_);                                     

void PCSX::InterpretedCPU::psxBEQ() { RepBranchi32(==) }  // Branch if Rs == Rt
void PCSX::InterpretedCPU::psxBNE() { RepBranchi32(!=) }  // Branch if Rs != Rt

/*********************************************************
 * Jump to target                                         *
 * Format:  OP target                                     *
 *********************************************************/
void PCSX::InterpretedCPU::psxJ() { doBranch(_JumpTarget_); }
void PCSX::InterpretedCPU::psxJAL() {
    _SetLink(31);
    doBranch(_JumpTarget_);
}

/*********************************************************
 * Register jump                                          *
 * Format:  OP rs, rd                                     *
 *********************************************************/
void PCSX::InterpretedCPU::psxJR() {
    doBranch(_u32(_rRs_));
}

void PCSX::InterpretedCPU::psxJALR() {
    uint32_t temp = _u32(_rRs_);
    if (_Rd_) {
        _SetLink(_Rd_);
    }
    doBranch(temp);
}

/*********************************************************
 * Load and store for GPR                                 *
 * Format:  OP rt, offset(base)                           *
 *********************************************************/

#define _oB_ (_u32(_rRs_) + _Imm_)

void PCSX::InterpretedCPU::psxLB() {
    // load delay = 1 latency
    if (_Rt_) {
        _i32(delayedLoad(_Rt_)) = (signed char)PCSX::g_emulator.m_psxMem->psxMemRead8(_oB_);
    } else {
        PCSX::g_emulator.m_psxMem->psxMemRead8(_oB_);
    }
}

void PCSX::InterpretedCPU::psxLBU() {
    // load delay = 1 latency
    if (_Rt_) {
        _u32(delayedLoad(_Rt_)) = PCSX::g_emulator.m_psxMem->psxMemRead8(_oB_);
    } else {
        PCSX::g_emulator.m_psxMem->psxMemRead8(_oB_);
    }
}

void PCSX::InterpretedCPU::psxLH() {
    // load delay = 1 latency
    if (_Rt_) {
        _i32(delayedLoad(_Rt_)) = (short)PCSX::g_emulator.m_psxMem->psxMemRead16(_oB_);
    } else {
        PCSX::g_emulator.m_psxMem->psxMemRead16(_oB_);
    }
}

void PCSX::InterpretedCPU::psxLHU() {
    // load delay = 1 latency
    if (_Rt_) {
        _u32(delayedLoad(_Rt_)) = PCSX::g_emulator.m_psxMem->psxMemRead16(_oB_);
    } else {
        PCSX::g_emulator.m_psxMem->psxMemRead16(_oB_);
    }
}

void PCSX::InterpretedCPU::psxLW() {
    // load delay = 1 latency
    if (_Rt_) {
        _u32(delayedLoad(_Rt_)) = PCSX::g_emulator.m_psxMem->psxMemRead32(_oB_);
    } else {
        PCSX::g_emulator.m_psxMem->psxMemRead32(_oB_);
    }
}

void PCSX::InterpretedCPU::psxLWL() {
    uint32_t addr = _oB_;
    uint32_t shift = addr & 3;
    uint32_t mem = PCSX::g_emulator.m_psxMem->psxMemRead32(addr & ~3);

    // load delay = 1 latency
    if (!_Rt_) return;
    _u32(delayedLoad(_Rt_)) = (_u32(_rRt_) & g_LWL_MASK[shift]) | (mem << g_LWL_SHIFT[shift]);

    /*
    Mem = 1234.  Reg = abcd

    0   4bcd   (mem << 24) | (reg & 0x00ffffff)
    1   34cd   (mem << 16) | (reg & 0x0000ffff)
    2   234d   (mem <<  8) | (reg & 0x000000ff)
    3   1234   (mem      ) | (reg & 0x00000000)
    */
}

void PCSX::InterpretedCPU::psxLWR() {
    uint32_t addr = _oB_;
    uint32_t shift = addr & 3;
    uint32_t mem = PCSX::g_emulator.m_psxMem->psxMemRead32(addr & ~3);

    // load delay = 1 latency
    if (!_Rt_) return;
    _u32(delayedLoad(_Rt_)) = (_u32(_rRt_) & g_LWR_MASK[shift]) | (mem >> g_LWR_SHIFT[shift]);

    /*
    Mem = 1234.  Reg = abcd

    0   1234   (mem      ) | (reg & 0x00000000)
    1   a123   (mem >>  8) | (reg & 0xff000000)
    2   ab12   (mem >> 16) | (reg & 0xffff0000)
    3   abc1   (mem >> 24) | (reg & 0xffffff00)
    */
}

void PCSX::InterpretedCPU::psxSB() { PCSX::g_emulator.m_psxMem->psxMemWrite8(_oB_, _u8(_rRt_)); }
void PCSX::InterpretedCPU::psxSH() { PCSX::g_emulator.m_psxMem->psxMemWrite16(_oB_, _u16(_rRt_)); }
void PCSX::InterpretedCPU::psxSW() { PCSX::g_emulator.m_psxMem->psxMemWrite32(_oB_, _u32(_rRt_)); }

void PCSX::InterpretedCPU::psxSWL() {
    uint32_t addr = _oB_;
    uint32_t shift = addr & 3;
    uint32_t mem = PCSX::g_emulator.m_psxMem->psxMemRead32(addr & ~3);

    PCSX::g_emulator.m_psxMem->psxMemWrite32(addr & ~3,
                                             (_u32(_rRt_) >> g_SWL_SHIFT[shift]) | (mem & g_SWL_MASK[shift]));
    /*
    Mem = 1234.  Reg = abcd

    0   123a   (reg >> 24) | (mem & 0xffffff00)
    1   12ab   (reg >> 16) | (mem & 0xffff0000)
    2   1abc   (reg >>  8) | (mem & 0xff000000)
    3   abcd   (reg      ) | (mem & 0x00000000)
    */
}

void PCSX::InterpretedCPU::psxSWR() {
    uint32_t addr = _oB_;
    uint32_t shift = addr & 3;
    uint32_t mem = PCSX::g_emulator.m_psxMem->psxMemRead32(addr & ~3);

    PCSX::g_emulator.m_psxMem->psxMemWrite32(addr & ~3,
                                             (_u32(_rRt_) << g_SWR_SHIFT[shift]) | (mem & g_SWR_MASK[shift]));

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
void PCSX::InterpretedCPU::psxMFC0() {
    // load delay = 1 latency
    if (!_Rt_) return;
    _i32(delayedLoad(_Rt_)) = (int)_rFs_;
}

void PCSX::InterpretedCPU::psxCFC0() {
    // load delay = 1 latency
    if (!_Rt_) return;
    _i32(delayedLoad(_Rt_)) = (int)_rFs_;
}

void PCSX::InterpretedCPU::psxTestSWInts() {
    // the next code is untested, if u know please
    // tell me if it works ok or not (linuzappz)
    if (m_psxRegs.CP0.n.Cause & m_psxRegs.CP0.n.Status & 0x0300 && m_psxRegs.CP0.n.Status & 0x1) {
        bool inDelaySlot = m_inDelaySlot;
        m_inDelaySlot = false;
        psxException(m_psxRegs.CP0.n.Cause, inDelaySlot);
    }
}

inline void PCSX::InterpretedCPU::MTC0(int reg, uint32_t val) {
    //  PCSX::g_system->printf("MTC0 %d: %x\n", reg, val);
    switch (reg) {
        case 12:  // Status
            PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status = val;
            psxTestSWInts();
            break;

        case 13:  // Cause
            PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Cause = val & ~(0xfc00);
            psxTestSWInts();
            break;

        default:
            PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.r[reg] = val;
            break;
    }
}

void PCSX::InterpretedCPU::psxMTC0() { MTC0(_Rd_, _u32(_rRt_)); }
void PCSX::InterpretedCPU::psxCTC0() { MTC0(_Rd_, _u32(_rRt_)); }

void PCSX::InterpretedCPU::psxMFC2() {
    // load delay = 1 latency
    if (!_Rt_) return;
    delayedLoad(_Rt_) = PCSX::g_emulator.m_gte->MFC2();
}

void PCSX::InterpretedCPU::psxCFC2() {
    // load delay = 1 latency
    if (!_Rt_) return;
    delayedLoad(_Rt_) = PCSX::g_emulator.m_gte->CFC2();
}

/*********************************************************
 * Unknow instruction (would generate an exception)       *
 * Format:  ?                                             *
 *********************************************************/
void PCSX::InterpretedCPU::psxNULL() {
    PSXCPU_LOG("psx: Unimplemented op %x\n", PCSX::g_emulator.m_psxCpu->m_psxRegs.code);
}

void PCSX::InterpretedCPU::psxSPECIAL() { (*this.*(s_pPsxSPC[_Funct_]))(); }

void PCSX::InterpretedCPU::psxREGIMM() { (*this.*(s_pPsxREG[_Rt_]))(); }

void PCSX::InterpretedCPU::psxCOP0() { (*this.*(s_pPsxCP0[_Rs_]))(); }

void PCSX::InterpretedCPU::psxCOP2() {
    if ((PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status & 0x40000000) == 0) return;

    (*this.*(s_pPsxCP2[_Funct_]))();
}

void PCSX::InterpretedCPU::psxBASIC() { (*this.*(s_pPsxCP2BSC[_Rs_]))(); }

void PCSX::InterpretedCPU::psxHLE() {
    uint32_t hleCode = PCSX::g_emulator.m_psxCpu->m_psxRegs.code & 0x03ffffff;
    if (hleCode >= (sizeof(psxHLEt) / sizeof(psxHLEt[0]))) {
        psxNULL();
    } else {
        psxHLEt[hleCode]();
    }
}

const PCSX::InterpretedCPU::intFunc_t PCSX::InterpretedCPU::s_psxBSC[64] = {
    &InterpretedCPU::psxSPECIAL, &InterpretedCPU::psxREGIMM, &InterpretedCPU::psxJ,    &InterpretedCPU::psxJAL,    // 00
    &InterpretedCPU::psxBEQ,     &InterpretedCPU::psxBNE,    &InterpretedCPU::psxBLEZ, &InterpretedCPU::psxBGTZ,   // 04
    &InterpretedCPU::psxADDI,    &InterpretedCPU::psxADDIU,  &InterpretedCPU::psxSLTI, &InterpretedCPU::psxSLTIU,  // 08
    &InterpretedCPU::psxANDI,    &InterpretedCPU::psxORI,    &InterpretedCPU::psxXORI, &InterpretedCPU::psxLUI,    // 0c
    &InterpretedCPU::psxCOP0,    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxCOP2, &InterpretedCPU::psxNULL,   // 10
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,   // 14
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,   // 18
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,   // 1c
    &InterpretedCPU::psxLB,      &InterpretedCPU::psxLH,     &InterpretedCPU::psxLWL,  &InterpretedCPU::psxLW,     // 20
    &InterpretedCPU::psxLBU,     &InterpretedCPU::psxLHU,    &InterpretedCPU::psxLWR,  &InterpretedCPU::psxNULL,   // 24
    &InterpretedCPU::psxSB,      &InterpretedCPU::psxSH,     &InterpretedCPU::psxSWL,  &InterpretedCPU::psxSW,     // 28
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxSWR,  &InterpretedCPU::psxNULL,   // 2c
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::gteLWC2, &InterpretedCPU::psxNULL,   // 30
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,   // 34
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::gteSWC2, &InterpretedCPU::psxHLE,    // 38
    &InterpretedCPU::psxNULL,    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,   // 3c
};

const PCSX::InterpretedCPU::intFunc_t PCSX::InterpretedCPU::s_psxSPC[64] = {
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

const PCSX::InterpretedCPU::intFunc_t PCSX::InterpretedCPU::s_psxREG[32] = {
    &InterpretedCPU::psxBLTZ,   &InterpretedCPU::psxBGEZ,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 00
    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 04
    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 08
    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 0c
    &InterpretedCPU::psxBLTZAL, &InterpretedCPU::psxBGEZAL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 10
    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 14
    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 18
    &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL,   &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 1c
};

const PCSX::InterpretedCPU::intFunc_t PCSX::InterpretedCPU::s_psxCP0[32] = {
    &InterpretedCPU::psxMFC0, &InterpretedCPU::psxNULL, &InterpretedCPU::psxCFC0, &InterpretedCPU::psxNULL,  // 00
    &InterpretedCPU::psxMTC0, &InterpretedCPU::psxNULL, &InterpretedCPU::psxCTC0, &InterpretedCPU::psxNULL,  // 04
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 08
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 0c
    &InterpretedCPU::psxRFE,  &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 10
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 14
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 18
    &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL, &InterpretedCPU::psxNULL,  // 1c
};

const PCSX::InterpretedCPU::intFunc_t PCSX::InterpretedCPU::s_psxCP2[64] = {
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

const PCSX::InterpretedCPU::intFunc_t PCSX::InterpretedCPU::s_psxCP2BSC[32] = {
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

void PCSX::InterpretedCPU::pgxpPsxNULL() {}

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

#define PGXP_INT_FUNC(pu, op)                                                                    \
    void PCSX::InterpretedCPU::pgxpPsx##op() {                                                   \
        PGXP_PSX_FUNC_OP(pu, op, )(PGXP_DBG_OP_E(op) PCSX::g_emulator.m_psxCpu->m_psxRegs.code); \
        psx##op();                                                                               \
    }

#define PGXP_INT_FUNC_0_1(pu, op, test, nReg, reg1)                        \
    void PCSX::InterpretedCPU::pgxpPsx##op() {                             \
        if (test) {                                                        \
            psx##op();                                                     \
            return;                                                        \
        }                                                                  \
        uint32_t tempInstr = PCSX::g_emulator.m_psxCpu->m_psxRegs.code;    \
        psx##op();                                                         \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1); \
    }

#define PGXP_INT_FUNC_1_0(pu, op, test, nReg, reg1)                           \
    void PCSX::InterpretedCPU::pgxpPsx##op() {                                \
        if (test) {                                                           \
            psx##op();                                                        \
            return;                                                           \
        }                                                                     \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) psxRegs.code, reg1); \
        psx##op();                                                            \
    }

#define PGXP_INT_FUNC_1_1(pu, op, test, nReg, reg1, reg2)                         \
    void PCSX::InterpretedCPU::pgxpPsx##op() {                                    \
        if (test) {                                                               \
            psx##op();                                                            \
            return;                                                               \
        }                                                                         \
        uint32_t tempInstr = PCSX::g_emulator.m_psxCpu->m_psxRegs.code;           \
        uint32_t temp2 = reg2;                                                    \
        psx##op();                                                                \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, temp2); \
    }

#define PGXP_INT_FUNC_0_2(pu, op, test, nReg, reg1, reg2)                        \
    void PCSX::InterpretedCPU::pgxpPsx##op() {                                   \
        if (test) {                                                              \
            psx##op();                                                           \
            return;                                                              \
        }                                                                        \
        uint32_t tempInstr = PCSX::g_emulator.m_psxCpu->m_psxRegs.code;          \
        psx##op();                                                               \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, reg2); \
    }

#define PGXP_INT_FUNC_2_0(pu, op, test, nReg, reg1, reg2)                          \
    void PCSX::InterpretedCPU::pgxpPsx##op() {                                     \
        if (test) {                                                                \
            psx##op();                                                             \
            return;                                                                \
        }                                                                          \
        uint32_t tempInstr = PCSX::g_emulator.m_psxCpu->m_psxRegs.code;            \
        uint32_t temp1 = reg1;                                                     \
        uint32_t temp2 = reg2;                                                     \
        psx##op();                                                                 \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, temp1, temp2); \
    }

#define PGXP_INT_FUNC_2_1(pu, op, test, nReg, reg1, reg2, reg3)                          \
    void PCSX::InterpretedCPU::pgxpPsx##op() {                                           \
        if (test) {                                                                      \
            psx##op();                                                                   \
            return;                                                                      \
        }                                                                                \
        uint32_t tempInstr = PCSX::g_emulator.m_psxCpu->m_psxRegs.code;                  \
        uint32_t temp2 = reg2;                                                           \
        uint32_t temp3 = reg3;                                                           \
        psx##op();                                                                       \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, temp2, temp3); \
    }

#define PGXP_INT_FUNC_2_2(pu, op, test, nReg, reg1, reg2, reg3, reg4)                          \
    void PCSX::InterpretedCPU::pgxpPsx##op() {                                                 \
        if (test) {                                                                            \
            psx##op();                                                                         \
            return;                                                                            \
        }                                                                                      \
        uint32_t tempInstr = PCSX::g_emulator.m_psxCpu->m_psxRegs.code;                        \
        uint32_t temp3 = reg3;                                                                 \
        uint32_t temp4 = reg4;                                                                 \
        psx##op();                                                                             \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, reg2, temp3, temp4); \
    }

// Rt = Rs op imm
PGXP_INT_FUNC_1_1(CPU, ADDI, !_Rt_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, ADDIU, !_Rt_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, ANDI, !_Rt_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, ORI, !_Rt_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, XORI, !_Rt_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, SLTI, !_Rt_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, SLTIU, !_Rt_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_])

// Rt = imm
PGXP_INT_FUNC_0_1(CPU, LUI, !_Rt_, 1, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])

// Rd = Rs op Rt
PGXP_INT_FUNC_2_1(CPU, ADD, !_Rd_, 3, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_], PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, ADDU, !_Rd_, 3, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_], PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SUB, !_Rd_, 3, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_], PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SUBU, !_Rd_, 3, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_], PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, AND, !_Rd_, 3, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_], PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, OR, !_Rd_, 3, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_], PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, XOR, !_Rd_, 3, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_], PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, NOR, !_Rd_, 3, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_], PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SLT, !_Rd_, 3, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_], PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SLTU, !_Rd_, 3, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_], PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])

// Hi/Lo = Rs op Rt
PGXP_INT_FUNC_2_2(CPU, MULT, 0, 4, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.hi,
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.lo, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_2(CPU, MULTU, 0, 4, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.hi,
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.lo, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_2(CPU, DIV, 0, 4, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.hi,
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.lo, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_2(CPU, DIVU, 0, 4, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.hi,
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.lo, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])

// Mem[addr] = Rt
PGXP_INT_FUNC_1_1(CPU, SB, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SH, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SW, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SWL, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SWR, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], _oB_)

// Rt = Mem[addr]
PGXP_INT_FUNC_1_1(CPU, LWL, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LW, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LWR, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LH, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LHU, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LB, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LBU, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], _oB_)

// Rd = Rt op Sa
PGXP_INT_FUNC_1_1(CPU, SLL, !_Rd_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(CPU, SRL, !_Rd_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(CPU, SRA, !_Rd_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])

// Rd = Rt op Rs
PGXP_INT_FUNC_2_1(CPU, SLLV, !_Rd_, 3, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_2_1(CPU, SRLV, !_Rd_, 3, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_2_1(CPU, SRAV, !_Rd_, 3, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_])

PGXP_INT_FUNC_1_1(CPU, MFHI, !_Rd_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.hi)
PGXP_INT_FUNC_1_1(CPU, MTHI, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.hi,
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_])
PGXP_INT_FUNC_1_1(CPU, MFLO, !_Rd_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.lo)
PGXP_INT_FUNC_1_1(CPU, MTLO, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.lo,
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_])

// COP2 (GTE)
PGXP_INT_FUNC_1_1(GTE, MFC2, !_Rt_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2D.r[_Rd_])
PGXP_INT_FUNC_1_1(GTE, CFC2, !_Rt_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2C.r[_Rd_])
PGXP_INT_FUNC_1_1(GTE, MTC2, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2D.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(GTE, CTC2, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2C.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])

PGXP_INT_FUNC_1_1(GTE, LWC2, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2D.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(GTE, SWC2, 0, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2D.r[_Rt_], _oB_)

// COP0
PGXP_INT_FUNC_1_1(CP0, MFC0, !_Rd_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.r[_Rd_])
PGXP_INT_FUNC_1_1(CP0, CFC0, !_Rd_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.r[_Rd_])
PGXP_INT_FUNC_1_1(CP0, MTC0, !_Rt_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(CP0, CTC0, !_Rt_, 2, PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.r[_Rd_],
                  PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC(CP0, RFE)

// end of PGXP

// Trace all functions using PGXP
const PCSX::InterpretedCPU::intFunc_t PCSX::InterpretedCPU::s_pgxpPsxBSC[64] = {
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
    &InterpretedCPU::pgxpPsxSWC2, &InterpretedCPU::psxHLE,        // 3a
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 3c
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,       // 3e
};

const PCSX::InterpretedCPU::intFunc_t PCSX::InterpretedCPU::s_pgxpPsxSPC[64] = {
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

const PCSX::InterpretedCPU::intFunc_t PCSX::InterpretedCPU::s_pgxpPsxCP0[32] = {
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

const PCSX::InterpretedCPU::intFunc_t PCSX::InterpretedCPU::s_pgxpPsxCP2BSC[32] = {
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
const PCSX::InterpretedCPU::intFunc_t PCSX::InterpretedCPU::s_pgxpPsxBSCMem[64] = {
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
    &InterpretedCPU::pgxpPsxSWC2, &InterpretedCPU::psxHLE,       // 3a
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,      // 3c
    &InterpretedCPU::psxNULL,     &InterpretedCPU::psxNULL,      // 3e
};

///////////////////////////////////////////

bool PCSX::InterpretedCPU::Init() { return true; }
void PCSX::InterpretedCPU::Reset() {
    PCSX::g_emulator.m_psxCpu->m_psxRegs.ICache_valid = false;
    m_nextIsDelaySlot = false;
    m_inDelaySlot = false;
    m_delayedLoadInfo[0].active = false;
    m_delayedLoadInfo[1].active = false;
    m_delayedLoadInfo[0].pcActive = false;
    m_delayedLoadInfo[1].pcActive = false;
}
void PCSX::InterpretedCPU::Execute() {
    while (hasToRun()) execI();
}
void PCSX::InterpretedCPU::ExecuteHLEBlock() {
    while (!execI())
        ;
}
void PCSX::InterpretedCPU::Clear(uint32_t Addr, uint32_t Size) {}
void PCSX::InterpretedCPU::Shutdown() {}
// interpreter execution
inline bool PCSX::InterpretedCPU::execI() {
    bool ranDelaySlot = false;
    if (m_nextIsDelaySlot) {
        m_inDelaySlot = true;
        m_nextIsDelaySlot = false;
    }
    InterceptBIOS();
    uint32_t *code = PCSX::g_emulator.m_psxCpu->Read_ICache(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc, false);
    PCSX::g_emulator.m_psxCpu->m_psxRegs.code = ((code == NULL) ? 0 : SWAP_LE32(*code));
    const bool &debug = g_emulator.settings.get<PCSX::Emulator::SettingDebug>();

    debugI();

    if (debug) g_emulator.m_debug->processBefore();

    PCSX::g_emulator.m_psxCpu->m_psxRegs.pc += 4;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle += PCSX::Emulator::BIAS;

    cIntFunc_t func = s_pPsxBSC[PCSX::g_emulator.m_psxCpu->m_psxRegs.code >> 26];
    (*this.*func)();

    m_currentDelayedLoad ^= 1;
    auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
    if (delayedLoad.active) {
        if (delayedLoad.index >= 32) abort();
        m_psxRegs.GPR.r[delayedLoad.index] = delayedLoad.value;
        delayedLoad.active = false;
    }
    if (delayedLoad.pcActive) {
        m_psxRegs.pc = delayedLoad.pcValue;
        delayedLoad.pcActive = false;
    }
    if (m_inDelaySlot) {
        m_inDelaySlot = false;
        ranDelaySlot = true;
        psxBranchTest();
    }
    if (debug) g_emulator.m_debug->processAfter();
    return ranDelaySlot;
}

void PCSX::InterpretedCPU::SetPGXPMode(uint32_t pgxpMode) {
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
