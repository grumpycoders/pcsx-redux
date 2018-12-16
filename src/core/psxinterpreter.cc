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

#include "core/gte.h"
#include "core/pgxp_cpu.h"
#include "core/pgxp_debug.h"
#include "core/pgxp_gte.h"
#include "core/psxcommon.h"
#include "core/psxhle.h"
#include "core/r3000a.h"

static int s_branch = 0;
static int s_branch2 = 0;
static u32 s_branchPC;

// These macros are used to assemble the repassembler functions

#ifdef PSXCPU_LOG
#define debugI()                                                  \
    if (g_config.PsxOut) {                                          \
        PSXCPU_LOG("%s\n", disR3000AF(g_psxRegs.code, g_psxRegs.pc)); \
    }
#else
#define debugI()
#endif

static inline void execI();

static void (**s_pPsxBSC)() = NULL;
static void (**s_pPsxSPC)() = NULL;
static void (**s_pPsxREG)() = NULL;
static void (**s_pPsxCP0)() = NULL;
static void (**s_pPsxCP2)() = NULL;
static void (**s_pPsxCP2BSC)() = NULL;

static void delayRead(int reg, u32 bpc) {
    u32 rold, rnew;

    //	SysPrintf("delayRead at %x!\n", g_psxRegs.pc);

    rold = g_psxRegs.GPR.r[reg];
    s_pPsxBSC[g_psxRegs.code >> 26]();  // branch delay load
    rnew = g_psxRegs.GPR.r[reg];

    g_psxRegs.pc = bpc;

    s_branch = 0;

    g_psxRegs.GPR.r[reg] = rold;
    execI();  // first branch opcode
    g_psxRegs.GPR.r[reg] = rnew;

    psxBranchTest();
}

static void delayWrite(int reg, u32 bpc) {
    /*	SysPrintf("delayWrite at %x!\n", g_psxRegs.pc);

            SysPrintf("%s\n", disR3000AF(g_psxRegs.code, g_psxRegs.pc-4));
            SysPrintf("%s\n", disR3000AF(PSXMu32(bpc), bpc));*/

    // no changes from normal behavior

    s_pPsxBSC[g_psxRegs.code >> 26]();

    s_branch = 0;
    g_psxRegs.pc = bpc;

    psxBranchTest();
}

static void delayReadWrite(int reg, u32 bpc) {
    //	SysPrintf("delayReadWrite at %x!\n", g_psxRegs.pc);

    // the branch delay load is skipped

    s_branch = 0;
    g_psxRegs.pc = bpc;

    psxBranchTest();
}

// this defines shall be used with the tmp
// of the next func (instead of _Funct_...)
#define _tFunct_ ((tmp)&0x3F)       // The funct part of the instruction register
#define _tRd_ ((tmp >> 11) & 0x1F)  // The rd part of the instruction register
#define _tRt_ ((tmp >> 16) & 0x1F)  // The rt part of the instruction register
#define _tRs_ ((tmp >> 21) & 0x1F)  // The rs part of the instruction register
#define _tSa_ ((tmp >> 6) & 0x1F)   // The sa part of the instruction register

int psxTestLoadDelay(int reg, u32 tmp) {
    if (tmp == 0) return 0;  // NOP
    switch (tmp >> 26) {
        case 0x00:  // SPECIAL
            switch (_tFunct_) {
                case 0x00:  // SLL
                case 0x02:
                case 0x03:  // SRL/SRA
                    if (_tRd_ == reg && _tRt_ == reg)
                        return 1;
                    else if (_tRt_ == reg)
                        return 2;
                    else if (_tRd_ == reg)
                        return 3;
                    break;

                case 0x08:  // JR
                    if (_tRs_ == reg) return 2;
                    break;
                case 0x09:  // JALR
                    if (_tRd_ == reg && _tRs_ == reg)
                        return 1;
                    else if (_tRs_ == reg)
                        return 2;
                    else if (_tRd_ == reg)
                        return 3;
                    break;

                    // SYSCALL/BREAK just a break;

                case 0x20:
                case 0x21:
                case 0x22:
                case 0x23:
                case 0x24:
                case 0x25:
                case 0x26:
                case 0x27:
                case 0x2a:
                case 0x2b:  // ADD/ADDU...
                case 0x04:
                case 0x06:
                case 0x07:  // SLLV...
                    if (_tRd_ == reg && (_tRt_ == reg || _tRs_ == reg))
                        return 1;
                    else if (_tRt_ == reg || _tRs_ == reg)
                        return 2;
                    else if (_tRd_ == reg)
                        return 3;
                    break;

                case 0x10:
                case 0x12:  // MFHI/MFLO
                    if (_tRd_ == reg) return 3;
                    break;
                case 0x11:
                case 0x13:  // MTHI/MTLO
                    if (_tRs_ == reg) return 2;
                    break;

                case 0x18:
                case 0x19:
                case 0x1a:
                case 0x1b:  // MULT/DIV...
                    if (_tRt_ == reg || _tRs_ == reg) return 2;
                    break;
            }
            break;

        case 0x01:  // REGIMM
            switch (_tRt_) {
                case 0x00:
                case 0x01:
                case 0x10:
                case 0x11:  // BLTZ/BGEZ...
                    // Xenogears - lbu v0 / beq v0
                    // - no load delay (fixes battle loading)
                    break;

                    if (_tRs_ == reg) return 2;
                    break;
            }
            break;

        // J would be just a break;
        case 0x03:  // JAL
            if (31 == reg) return 3;
            break;

        case 0x04:
        case 0x05:  // BEQ/BNE
            // Xenogears - lbu v0 / beq v0
            // - no load delay (fixes battle loading)
            break;

            if (_tRs_ == reg || _tRt_ == reg) return 2;
            break;

        case 0x06:
        case 0x07:  // BLEZ/BGTZ
            // Xenogears - lbu v0 / beq v0
            // - no load delay (fixes battle loading)
            break;

            if (_tRs_ == reg) return 2;
            break;

        case 0x08:
        case 0x09:
        case 0x0a:
        case 0x0b:
        case 0x0c:
        case 0x0d:
        case 0x0e:  // ADDI/ADDIU...
            if (_tRt_ == reg && _tRs_ == reg)
                return 1;
            else if (_tRs_ == reg)
                return 2;
            else if (_tRt_ == reg)
                return 3;
            break;

        case 0x0f:  // LUI
            if (_tRt_ == reg) return 3;
            break;

        case 0x10:  // COP0
            switch (_tFunct_) {
                case 0x00:  // MFC0
                    if (_tRt_ == reg) return 3;
                    break;
                case 0x02:  // CFC0
                    if (_tRt_ == reg) return 3;
                    break;
                case 0x04:  // MTC0
                    if (_tRt_ == reg) return 2;
                    break;
                case 0x06:  // CTC0
                    if (_tRt_ == reg) return 2;
                    break;
                    // RFE just a break;
            }
            break;

        case 0x12:  // COP2
            switch (_tFunct_) {
                case 0x00:
                    switch (_tRs_) {
                        case 0x00:  // MFC2
                            if (_tRt_ == reg) return 3;
                            break;
                        case 0x02:  // CFC2
                            if (_tRt_ == reg) return 3;
                            break;
                        case 0x04:  // MTC2
                            if (_tRt_ == reg) return 2;
                            break;
                        case 0x06:  // CTC2
                            if (_tRt_ == reg) return 2;
                            break;
                    }
                    break;
                    // RTPS... break;
            }
            break;

        case 0x22:
        case 0x26:  // LWL/LWR
            if (_tRt_ == reg)
                return 3;
            else if (_tRs_ == reg)
                return 2;
            break;

        case 0x20:
        case 0x21:
        case 0x23:
        case 0x24:
        case 0x25:  // LB/LH/LW/LBU/LHU
            if (_tRt_ == reg && _tRs_ == reg)
                return 1;
            else if (_tRs_ == reg)
                return 2;
            else if (_tRt_ == reg)
                return 3;
            break;

        case 0x28:
        case 0x29:
        case 0x2a:
        case 0x2b:
        case 0x2e:  // SB/SH/SWL/SW/SWR
            if (_tRt_ == reg || _tRs_ == reg) return 2;
            break;

        case 0x32:
        case 0x3a:  // LWC2/SWC2
            if (_tRs_ == reg) return 2;
            break;
    }

    return 0;
}

void psxDelayTest(int reg, u32 bpc) {
    u32 *code;
    u32 tmp;

    // Don't execute yet - just peek
    code = Read_ICache(bpc, TRUE);

    tmp = ((code == NULL) ? 0 : SWAP32(*code));
    s_branch = 1;

    switch (psxTestLoadDelay(reg, tmp)) {
        case 1:
            delayReadWrite(reg, bpc);
            return;
        case 2:
            delayRead(reg, bpc);
            return;
        case 3:
            delayWrite(reg, bpc);
            return;
    }
    s_pPsxBSC[g_psxRegs.code >> 26]();

    s_branch = 0;
    g_psxRegs.pc = bpc;

    psxBranchTest();
}

static u32 psxBranchNoDelay(void) {
    u32 *code;
    u32 temp;

    code = Read_ICache(g_psxRegs.pc, TRUE);
    g_psxRegs.code = ((code == NULL) ? 0 : SWAP32(*code));
    switch (_Op_) {
        case 0x00:  // SPECIAL
            switch (_Funct_) {
                case 0x08:  // JR
                    return _u32(_rRs_);
                case 0x09:  // JALR
                    temp = _u32(_rRs_);
                    if (_Rd_) {
                        _SetLink(_Rd_);
                    }
                    return temp;
            }
            break;
        case 0x01:  // REGIMM
            switch (_Rt_) {
                case 0x00:  // BLTZ
                    if (_i32(_rRs_) < 0) return _BranchTarget_;
                    break;
                case 0x01:  // BGEZ
                    if (_i32(_rRs_) >= 0) return _BranchTarget_;
                    break;
                case 0x08:  // BLTZAL
                    if (_i32(_rRs_) < 0) {
                        _SetLink(31);
                        return _BranchTarget_;
                    }
                    break;
                case 0x09:  // BGEZAL
                    if (_i32(_rRs_) >= 0) {
                        _SetLink(31);
                        return _BranchTarget_;
                    }
                    break;
            }
            break;
        case 0x02:  // J
            return _JumpTarget_;
        case 0x03:  // JAL
            _SetLink(31);
            return _JumpTarget_;
        case 0x04:  // BEQ
            if (_i32(_rRs_) == _i32(_rRt_)) return _BranchTarget_;
            break;
        case 0x05:  // BNE
            if (_i32(_rRs_) != _i32(_rRt_)) return _BranchTarget_;
            break;
        case 0x06:  // BLEZ
            if (_i32(_rRs_) <= 0) return _BranchTarget_;
            break;
        case 0x07:  // BGTZ
            if (_i32(_rRs_) > 0) return _BranchTarget_;
            break;
    }

    return (u32)-1;
}

static int psxDelayBranchExec(u32 tar) {
    execI();

    s_branch = 0;
    g_psxRegs.pc = tar;
    g_psxRegs.cycle += BIAS;
    psxBranchTest();
    return 1;
}

static int psxDelayBranchTest(u32 tar1) {
    u32 tar2, tmp1, tmp2;

    tar2 = psxBranchNoDelay();
    if (tar2 == (u32)-1) return 0;

    debugI();

    /*
     * Branch in delay slot:
     * - execute 1 instruction at tar1
     * - jump to tar2 (target of branch in delay slot; this branch
     *   has no normal delay slot, instruction at tar1 was fetched instead)
     */
    g_psxRegs.pc = tar1;
    tmp1 = psxBranchNoDelay();
    if (tmp1 == (u32)-1) {
        return psxDelayBranchExec(tar2);
    }
    debugI();
    g_psxRegs.cycle += BIAS;

    /*
     * Got a branch at tar1:
     * - execute 1 instruction at tar2
     * - jump to target of that branch (tmp1)
     */
    g_psxRegs.pc = tar2;
    tmp2 = psxBranchNoDelay();
    if (tmp2 == (u32)-1) {
        return psxDelayBranchExec(tmp1);
    }
    debugI();
    g_psxRegs.cycle += BIAS;

    /*
     * Got a branch at tar2:
     * - execute 1 instruction at tmp1
     * - jump to target of that branch (tmp2)
     */
    g_psxRegs.pc = tmp1;
    return psxDelayBranchExec(tmp2);
}

static __inline void doBranch(u32 tar) {
    u32 *code;
    u32 tmp;

    s_branch2 = s_branch = 1;
    s_branchPC = tar;

    // notaz: check for branch in delay slot
    if (psxDelayBranchTest(tar)) return;

    // branch delay slot
    code = Read_ICache(g_psxRegs.pc, TRUE);

    g_psxRegs.code = ((code == NULL) ? 0 : SWAP32(*code));

    debugI();

    g_psxRegs.pc += 4;
    g_psxRegs.cycle += BIAS;

    // check for load delay
    tmp = g_psxRegs.code >> 26;
    switch (tmp) {
        case 0x10:  // COP0
            switch (_Rs_) {
                case 0x00:  // MFC0
                case 0x02:  // CFC0
                    psxDelayTest(_Rt_, s_branchPC);
                    return;
            }
            break;
        case 0x12:  // COP2
            switch (_Funct_) {
                case 0x00:
                    switch (_Rs_) {
                        case 0x00:  // MFC2
                        case 0x02:  // CFC2
                            psxDelayTest(_Rt_, s_branchPC);
                            return;
                    }
                    break;
            }
            break;
        case 0x32:  // LWC2
            psxDelayTest(_Rt_, s_branchPC);
            return;
        default:
            if (tmp >= 0x20 && tmp <= 0x26) {  // LB/LH/LWL/LW/LBU/LHU/LWR
                psxDelayTest(_Rt_, s_branchPC);
                return;
            }
            break;
    }

    s_pPsxBSC[g_psxRegs.code >> 26]();

    s_branch = 0;
    g_psxRegs.pc = s_branchPC;

    psxBranchTest();
}

/*********************************************************
 * Arithmetic with immediate operand                      *
 * Format:  OP rt, rs, immediate                          *
 *********************************************************/
static void psxADDI() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) + _Imm_;
}  // Rt = Rs + Im 	(Exception on Integer Overflow)
static void psxADDIU() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) + _Imm_;
}  // Rt = Rs + Im
static void psxANDI() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) & _ImmU_;
}  // Rt = Rs And Im
static void psxORI() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) | _ImmU_;
}  // Rt = Rs Or  Im
static void psxXORI() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) ^ _ImmU_;
}  // Rt = Rs Xor Im
static void psxSLTI() {
    if (!_Rt_) return;
    _rRt_ = _i32(_rRs_) < _Imm_;
}  // Rt = Rs < Im		(Signed)
static void psxSLTIU() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) < ((u32)_Imm_);
}  // Rt = Rs < Im		(Unsigned)

/*********************************************************
 * Register arithmetic                                    *
 * Format:  OP rd, rs, rt                                 *
 *********************************************************/
static void psxADD() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) + _u32(_rRt_);
}  // Rd = Rs + Rt		(Exception on Integer Overflow)
static void psxADDU() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) + _u32(_rRt_);
}  // Rd = Rs + Rt
static void psxSUB() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) - _u32(_rRt_);
}  // Rd = Rs - Rt		(Exception on Integer Overflow)
static void psxSUBU() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) - _u32(_rRt_);
}  // Rd = Rs - Rt
static void psxAND() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) & _u32(_rRt_);
}  // Rd = Rs And Rt
static void psxOR() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) | _u32(_rRt_);
}  // Rd = Rs Or  Rt
static void psxXOR() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) ^ _u32(_rRt_);
}  // Rd = Rs Xor Rt
static void psxNOR() {
    if (!_Rd_) return;
    _rRd_ = ~(_u32(_rRs_) | _u32(_rRt_));
}  // Rd = Rs Nor Rt
static void psxSLT() {
    if (!_Rd_) return;
    _rRd_ = _i32(_rRs_) < _i32(_rRt_);
}  // Rd = Rs < Rt		(Signed)
static void psxSLTU() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) < _u32(_rRt_);
}  // Rd = Rs < Rt		(Unsigned)

/*********************************************************
 * Register mult/div & Register trap logic                *
 * Format:  OP rs, rt                                     *
 *********************************************************/
static void psxDIV() {
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

static void psxDIVU() {
    if (_rRt_ != 0) {
        _rLo_ = _rRs_ / _rRt_;
        _rHi_ = _rRs_ % _rRt_;
    } else {
        _rLo_ = 0xffffffff;
        _rHi_ = _rRs_;
    }
}

static void psxMULT() {
    u64 res = (s64)((s64)_i32(_rRs_) * (s64)_i32(_rRt_));

    g_psxRegs.GPR.n.lo = (u32)(res & 0xffffffff);
    g_psxRegs.GPR.n.hi = (u32)((res >> 32) & 0xffffffff);
}

static void psxMULTU() {
    u64 res = (u64)((u64)_u32(_rRs_) * (u64)_u32(_rRt_));

    g_psxRegs.GPR.n.lo = (u32)(res & 0xffffffff);
    g_psxRegs.GPR.n.hi = (u32)((res >> 32) & 0xffffffff);
}

/*********************************************************
 * Register branch logic                                  *
 * Format:  OP rs, offset                                 *
 *********************************************************/
#define RepZBranchi32(op) \
    if (_i32(_rRs_) op 0) doBranch(_BranchTarget_);
#define RepZBranchLinki32(op)     \
    if (_i32(_rRs_) op 0) {       \
        _SetLink(31);             \
        doBranch(_BranchTarget_); \
    }

static void psxBGEZ() { RepZBranchi32(>=) }  // Branch if Rs >= 0
static void psxBGEZAL() { RepZBranchLinki32(>=) }  // Branch if Rs >= 0 and link
static void psxBGTZ() { RepZBranchi32(>) }         // Branch if Rs >  0
static void psxBLEZ() { RepZBranchi32(<=) }        // Branch if Rs <= 0
static void psxBLTZ() { RepZBranchi32(<) }         // Branch if Rs <  0
static void psxBLTZAL() { RepZBranchLinki32(<) }   // Branch if Rs <  0 and link

/*********************************************************
 * Shift arithmetic with constant shift                   *
 * Format:  OP rd, rt, sa                                 *
 *********************************************************/
static void psxSLL() {
    if (!_Rd_) return;
    _u32(_rRd_) = _u32(_rRt_) << _Sa_;
}  // Rd = Rt << sa
static void psxSRA() {
    if (!_Rd_) return;
    _i32(_rRd_) = _i32(_rRt_) >> _Sa_;
}  // Rd = Rt >> sa (arithmetic)
static void psxSRL() {
    if (!_Rd_) return;
    _u32(_rRd_) = _u32(_rRt_) >> _Sa_;
}  // Rd = Rt >> sa (logical)

/*********************************************************
 * Shift arithmetic with variant register shift           *
 * Format:  OP rd, rt, rs                                 *
 *********************************************************/
static void psxSLLV() {
    if (!_Rd_) return;
    _u32(_rRd_) = _u32(_rRt_) << _u32(_rRs_);
}  // Rd = Rt << rs
static void psxSRAV() {
    if (!_Rd_) return;
    _i32(_rRd_) = _i32(_rRt_) >> _u32(_rRs_);
}  // Rd = Rt >> rs (arithmetic)
static void psxSRLV() {
    if (!_Rd_) return;
    _u32(_rRd_) = _u32(_rRt_) >> _u32(_rRs_);
}  // Rd = Rt >> rs (logical)

/*********************************************************
 * Load higher 16 bits of the first word in GPR with imm  *
 * Format:  OP rt, immediate                              *
 *********************************************************/
static void psxLUI() {
    if (!_Rt_) return;
    _u32(_rRt_) = _ImmLU_;
}  // Upper halfword of Rt = Im

/*********************************************************
 * Move from HI/LO to GPR                                 *
 * Format:  OP rd                                         *
 *********************************************************/
static void psxMFHI() {
    if (!_Rd_) return;
    _rRd_ = _rHi_;
}  // Rd = Hi
static void psxMFLO() {
    if (!_Rd_) return;
    _rRd_ = _rLo_;
}  // Rd = Lo

/*********************************************************
 * Move to GPR to HI/LO & Register jump                   *
 * Format:  OP rs                                         *
 *********************************************************/
static void psxMTHI() { _rHi_ = _rRs_; }  // Hi = Rs
static void psxMTLO() { _rLo_ = _rRs_; }  // Lo = Rs

/*********************************************************
 * Special purpose instructions                           *
 * Format:  OP                                            *
 *********************************************************/
static void psxBREAK() {
    // Break exception - psx rom doens't handles this
}

static void psxSYSCALL() {
    g_psxRegs.pc -= 4;
    psxException(0x20, s_branch);
}

static void psxRFE() {
    //	SysPrintf("psxRFE\n");
    g_psxRegs.CP0.n.Status = (g_psxRegs.CP0.n.Status & 0xfffffff0) | ((g_psxRegs.CP0.n.Status & 0x3c) >> 2);
}

/*********************************************************
 * Register branch logic                                  *
 * Format:  OP rs, rt, offset                             *
 *********************************************************/
#define RepBranchi32(op) \
    if (_i32(_rRs_) op _i32(_rRt_)) doBranch(_BranchTarget_);

static void psxBEQ() { RepBranchi32(==) }  // Branch if Rs == Rt
static void psxBNE() { RepBranchi32(!=) }  // Branch if Rs != Rt

/*********************************************************
 * Jump to target                                         *
 * Format:  OP target                                     *
 *********************************************************/
static void psxJ() { doBranch(_JumpTarget_); }
static void psxJAL() {
    _SetLink(31);
    doBranch(_JumpTarget_);
}

/*********************************************************
 * Register jump                                          *
 * Format:  OP rs, rd                                     *
 *********************************************************/
static void psxJR() {
    doBranch(_u32(_rRs_));
    psxJumpTest();
}

static void psxJALR() {
    u32 temp = _u32(_rRs_);
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

static void psxLB() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        g_psxRegs.pc -= 4;
        doBranch(g_psxRegs.pc + 4);

        return;
    }

    if (_Rt_) {
        _i32(_rRt_) = (signed char)psxMemRead8(_oB_);
    } else {
        psxMemRead8(_oB_);
    }
}

static void psxLBU() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        g_psxRegs.pc -= 4;
        doBranch(g_psxRegs.pc + 4);

        return;
    }

    if (_Rt_) {
        _u32(_rRt_) = psxMemRead8(_oB_);
    } else {
        psxMemRead8(_oB_);
    }
}

static void psxLH() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        g_psxRegs.pc -= 4;
        doBranch(g_psxRegs.pc + 4);

        return;
    }

    if (_Rt_) {
        _i32(_rRt_) = (short)psxMemRead16(_oB_);
    } else {
        psxMemRead16(_oB_);
    }
}

static void psxLHU() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        g_psxRegs.pc -= 4;
        doBranch(g_psxRegs.pc + 4);

        return;
    }

    if (_Rt_) {
        _u32(_rRt_) = psxMemRead16(_oB_);
    } else {
        psxMemRead16(_oB_);
    }
}

static void psxLW() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        g_psxRegs.pc -= 4;
        doBranch(g_psxRegs.pc + 4);

        return;
    }

    if (_Rt_) {
        _u32(_rRt_) = psxMemRead32(_oB_);
    } else {
        psxMemRead32(_oB_);
    }
}

extern "C" const u32 g_LWL_MASK[4] = {0xffffff, 0xffff, 0xff, 0};
extern "C" const u32 g_LWL_SHIFT[4] = {24, 16, 8, 0};

static void psxLWL() {
    u32 addr = _oB_;
    u32 shift = addr & 3;
    u32 mem = psxMemRead32(addr & ~3);

    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        g_psxRegs.pc -= 4;
        doBranch(g_psxRegs.pc + 4);

        return;
    }

    if (!_Rt_) return;
    _u32(_rRt_) = (_u32(_rRt_) & g_LWL_MASK[shift]) | (mem << g_LWL_SHIFT[shift]);

    /*
    Mem = 1234.  Reg = abcd

    0   4bcd   (mem << 24) | (reg & 0x00ffffff)
    1   34cd   (mem << 16) | (reg & 0x0000ffff)
    2   234d   (mem <<  8) | (reg & 0x000000ff)
    3   1234   (mem      ) | (reg & 0x00000000)
    */
}

extern "C" const u32 g_LWR_MASK[4] = {0, 0xff000000, 0xffff0000, 0xffffff00};
extern "C" const u32 g_LWR_SHIFT[4] = {0, 8, 16, 24};

static void psxLWR() {
    u32 addr = _oB_;
    u32 shift = addr & 3;
    u32 mem = psxMemRead32(addr & ~3);

    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        g_psxRegs.pc -= 4;
        doBranch(g_psxRegs.pc + 4);

        return;
    }

    if (!_Rt_) return;
    _u32(_rRt_) = (_u32(_rRt_) & g_LWR_MASK[shift]) | (mem >> g_LWR_SHIFT[shift]);

    /*
    Mem = 1234.  Reg = abcd

    0   1234   (mem      ) | (reg & 0x00000000)
    1   a123   (mem >>  8) | (reg & 0xff000000)
    2   ab12   (mem >> 16) | (reg & 0xffff0000)
    3   abc1   (mem >> 24) | (reg & 0xffffff00)
    */
}

static void psxSB() { psxMemWrite8(_oB_, _u8(_rRt_)); }
static void psxSH() { psxMemWrite16(_oB_, _u16(_rRt_)); }
static void psxSW() { psxMemWrite32(_oB_, _u32(_rRt_)); }

extern "C" const u32 g_SWL_MASK[4] = {0xffffff00, 0xffff0000, 0xff000000, 0};
extern "C" const u32 g_SWL_SHIFT[4] = {24, 16, 8, 0};

static void psxSWL() {
    u32 addr = _oB_;
    u32 shift = addr & 3;
    u32 mem = psxMemRead32(addr & ~3);

    psxMemWrite32(addr & ~3, (_u32(_rRt_) >> g_SWL_SHIFT[shift]) | (mem & g_SWL_MASK[shift]));
    /*
    Mem = 1234.  Reg = abcd

    0   123a   (reg >> 24) | (mem & 0xffffff00)
    1   12ab   (reg >> 16) | (mem & 0xffff0000)
    2   1abc   (reg >>  8) | (mem & 0xff000000)
    3   abcd   (reg      ) | (mem & 0x00000000)
    */
}

extern "C" const u32 g_SWR_MASK[4] = {0, 0xff, 0xffff, 0xffffff};
extern "C" const u32 g_SWR_SHIFT[4] = {0, 8, 16, 24};

static void psxSWR() {
    u32 addr = _oB_;
    u32 shift = addr & 3;
    u32 mem = psxMemRead32(addr & ~3);

    psxMemWrite32(addr & ~3, (_u32(_rRt_) << g_SWR_SHIFT[shift]) | (mem & g_SWR_MASK[shift]));

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
static void psxMFC0() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        g_psxRegs.pc -= 4;
        doBranch(g_psxRegs.pc + 4);

        return;
    }

    if (!_Rt_) return;

    _i32(_rRt_) = (int)_rFs_;
}

static void psxCFC0() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        g_psxRegs.pc -= 4;
        doBranch(g_psxRegs.pc + 4);

        return;
    }

    if (!_Rt_) return;

    _i32(_rRt_) = (int)_rFs_;
}

void psxTestSWInts() {
    // the next code is untested, if u know please
    // tell me if it works ok or not (linuzappz)
    if (g_psxRegs.CP0.n.Cause & g_psxRegs.CP0.n.Status & 0x0300 && g_psxRegs.CP0.n.Status & 0x1) {
        psxException(g_psxRegs.CP0.n.Cause, s_branch);
    }
}

static __inline void MTC0(int reg, u32 val) {
    //	SysPrintf("MTC0 %d: %x\n", reg, val);
    switch (reg) {
        case 12:  // Status
            g_psxRegs.CP0.r[12] = val;
            psxTestSWInts();
            break;

        case 13:  // Cause
            g_psxRegs.CP0.n.Cause = val & ~(0xfc00);
            psxTestSWInts();
            break;

        default:
            g_psxRegs.CP0.r[reg] = val;
            break;
    }
}

static void psxMTC0() { MTC0(_Rd_, _u32(_rRt_)); }
static void psxCTC0() { MTC0(_Rd_, _u32(_rRt_)); }

static void psxMFC2() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        g_psxRegs.pc -= 4;
        doBranch(g_psxRegs.pc + 4);

        return;
    }

    gteMFC2();
}

static void psxCFC2() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        g_psxRegs.pc -= 4;
        doBranch(g_psxRegs.pc + 4);

        return;
    }

    gteCFC2();
}

/*********************************************************
 * Unknow instruction (would generate an exception)       *
 * Format:  ?                                             *
 *********************************************************/
static void psxNULL() {
#ifdef PSXCPU_LOG
    PSXCPU_LOG("psx: Unimplemented op %x\n", g_psxRegs.code);
#endif
}

static void psxSPECIAL() { s_pPsxSPC[_Funct_](); }

static void psxREGIMM() { s_pPsxREG[_Rt_](); }

static void psxCOP0() { s_pPsxCP0[_Rs_](); }

static void psxCOP2() {
    if ((g_psxRegs.CP0.n.Status & 0x40000000) == 0) return;

    s_pPsxCP2[_Funct_]();
}

static void psxBASIC() { s_pPsxCP2BSC[_Rs_](); }

static void psxHLE() {
    //	psxHLEt[g_psxRegs.code & 0xffff]();
    psxHLEt[g_psxRegs.code & 0x07]();  // HDHOSHY experimental patch
}

static void (*s_psxBSC[64])() = {
    psxSPECIAL, psxREGIMM, psxJ,    psxJAL,   psxBEQ,  psxBNE,  psxBLEZ, psxBGTZ,
    psxADDI,    psxADDIU,  psxSLTI, psxSLTIU, psxANDI, psxORI,  psxXORI, psxLUI,
    psxCOP0,    psxNULL,   psxCOP2, psxNULL,  psxNULL, psxNULL, psxNULL, psxNULL,
    psxNULL,    psxNULL,   psxNULL, psxNULL,  psxNULL, psxNULL, psxNULL, psxNULL,
    psxLB,      psxLH,     psxLWL,  psxLW,    psxLBU,  psxLHU,  psxLWR,  psxNULL,
    psxSB,      psxSH,     psxSWL,  psxSW,    psxNULL, psxNULL, psxSWR,  psxNULL,
    psxNULL,    psxNULL,   gteLWC2, psxNULL,  psxNULL, psxNULL, psxNULL, psxNULL,
    psxNULL,    psxNULL,   gteSWC2, psxHLE,   psxNULL, psxNULL, psxNULL, psxNULL
};

static void (*s_psxSPC[64])() = {
    psxSLL,  psxNULL,  psxSRL,  psxSRA,  psxSLLV,    psxNULL,  psxSRLV, psxSRAV,
    psxJR,   psxJALR,  psxNULL, psxNULL, psxSYSCALL, psxBREAK, psxNULL, psxNULL,
    psxMFHI, psxMTHI,  psxMFLO, psxMTLO, psxNULL,    psxNULL,  psxNULL, psxNULL,
    psxMULT, psxMULTU, psxDIV,  psxDIVU, psxNULL,    psxNULL,  psxNULL, psxNULL,
    psxADD,  psxADDU,  psxSUB,  psxSUBU, psxAND,     psxOR,    psxXOR,  psxNOR,
    psxNULL, psxNULL,  psxSLT,  psxSLTU, psxNULL,    psxNULL,  psxNULL, psxNULL,
    psxNULL, psxNULL,  psxNULL, psxNULL, psxNULL,    psxNULL,  psxNULL, psxNULL,
    psxNULL, psxNULL,  psxNULL, psxNULL, psxNULL,    psxNULL,  psxNULL, psxNULL
};

static void (*s_psxREG[32])() = {
    psxBLTZ,   psxBGEZ,   psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,
    psxNULL,   psxNULL,   psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,
    psxBLTZAL, psxBGEZAL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,
    psxNULL,   psxNULL,   psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL
};

static void (*s_psxCP0[32])() = {
    psxMFC0, psxNULL, psxCFC0, psxNULL, psxMTC0, psxNULL, psxCTC0, psxNULL,
    psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,
    psxRFE,  psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,
    psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL
};

void (*s_psxCP2[64])() = {
    psxBASIC, gteRTPS,  psxNULL,  psxNULL, psxNULL, psxNULL,  gteNCLIP, psxNULL,  // 00
    psxNULL,  psxNULL,  psxNULL,  psxNULL, gteOP,   psxNULL,  psxNULL,  psxNULL,  // 08
    gteDPCS,  gteINTPL, gteMVMVA, gteNCDS, gteCDP,  psxNULL,  gteNCDT,  psxNULL,  // 10
    psxNULL,  psxNULL,  psxNULL,  gteNCCS, gteCC,   psxNULL,  gteNCS,   psxNULL,  // 18
    gteNCT,   psxNULL,  psxNULL,  psxNULL, psxNULL, psxNULL,  psxNULL,  psxNULL,  // 20
    gteSQR,   gteDCPL,  gteDPCT,  psxNULL, psxNULL, gteAVSZ3, gteAVSZ4, psxNULL,  // 28
    gteRTPT,  psxNULL,  psxNULL,  psxNULL, psxNULL, psxNULL,  psxNULL,  psxNULL,  // 30
    psxNULL,  psxNULL,  psxNULL,  psxNULL, psxNULL, gteGPF,   gteGPL,   gteNCCT   // 38
};

void (*s_psxCP2BSC[32])() = {
    psxMFC2, psxNULL, psxCFC2, psxNULL, gteMTC2, psxNULL, gteCTC2, psxNULL,
    psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,
    psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,
    psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL
};

/////////////////////////////////////////////
// PGXP wrapper functions
/////////////////////////////////////////////

void pgxpPsxNULL() {}

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
    static void pgxpPsx##op() {                                       \
        PGXP_PSX_FUNC_OP(pu, op, )(PGXP_DBG_OP_E(op) g_psxRegs.code); \
        psx##op();                                                    \
    }

#define PGXP_INT_FUNC_0_1(pu, op, test, nReg, reg1)                        \
    static void pgxpPsx##op() {                                            \
        if (test) {                                                        \
            psx##op();                                                     \
            return;                                                        \
        }                                                                  \
        u32 tempInstr = g_psxRegs.code;                                    \
        psx##op();                                                         \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1); \
    }

#define PGXP_INT_FUNC_1_0(pu, op, test, nReg, reg1)                           \
    static void pgxpPsx##op() {                                               \
        if (test) {                                                           \
            psx##op();                                                        \
            return;                                                           \
        }                                                                     \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) psxRegs.code, reg1); \
        psx##op();                                                            \
    }

#define PGXP_INT_FUNC_1_1(pu, op, test, nReg, reg1, reg2)                         \
    static void pgxpPsx##op() {                                                   \
        if (test) {                                                               \
            psx##op();                                                            \
            return;                                                               \
        }                                                                         \
        u32 tempInstr = g_psxRegs.code;                                           \
        u32 temp2 = reg2;                                                         \
        psx##op();                                                                \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, temp2); \
    }

#define PGXP_INT_FUNC_0_2(pu, op, test, nReg, reg1, reg2)                        \
    static void pgxpPsx##op() {                                                  \
        if (test) {                                                              \
            psx##op();                                                           \
            return;                                                              \
        }                                                                        \
        u32 tempInstr = g_psxRegs.code;                                          \
        psx##op();                                                               \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, reg2); \
    }

#define PGXP_INT_FUNC_2_0(pu, op, test, nReg, reg1, reg2)                          \
    static void pgxpPsx##op() {                                                    \
        if (test) {                                                                \
            psx##op();                                                             \
            return;                                                                \
        }                                                                          \
        u32 tempInstr = g_psxRegs.code;                                            \
        u32 temp1 = reg1;                                                          \
        u32 temp2 = reg2;                                                          \
        psx##op();                                                                 \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, temp1, temp2); \
    }

#define PGXP_INT_FUNC_2_1(pu, op, test, nReg, reg1, reg2, reg3)                          \
    static void pgxpPsx##op() {                                                          \
        if (test) {                                                                      \
            psx##op();                                                                   \
            return;                                                                      \
        }                                                                                \
        u32 tempInstr = g_psxRegs.code;                                                  \
        u32 temp2 = reg2;                                                                \
        u32 temp3 = reg3;                                                                \
        psx##op();                                                                       \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, temp2, temp3); \
    }

#define PGXP_INT_FUNC_2_2(pu, op, test, nReg, reg1, reg2, reg3, reg4)                          \
    static void pgxpPsx##op() {                                                                \
        if (test) {                                                                            \
            psx##op();                                                                         \
            return;                                                                            \
        }                                                                                      \
        u32 tempInstr = g_psxRegs.code;                                                        \
        u32 temp3 = reg3;                                                                      \
        u32 temp4 = reg4;                                                                      \
        psx##op();                                                                             \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, reg2, temp3, temp4); \
    }

// Rt = Rs op imm
PGXP_INT_FUNC_1_1(CPU, ADDI, !_Rt_, 2, g_psxRegs.GPR.r[_Rt_], g_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, ADDIU, !_Rt_, 2, g_psxRegs.GPR.r[_Rt_], g_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, ANDI, !_Rt_, 2, g_psxRegs.GPR.r[_Rt_], g_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, ORI, !_Rt_, 2, g_psxRegs.GPR.r[_Rt_], g_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, XORI, !_Rt_, 2, g_psxRegs.GPR.r[_Rt_], g_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, SLTI, !_Rt_, 2, g_psxRegs.GPR.r[_Rt_], g_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, SLTIU, !_Rt_, 2, g_psxRegs.GPR.r[_Rt_], g_psxRegs.GPR.r[_Rs_])

// Rt = imm
PGXP_INT_FUNC_0_1(CPU, LUI, !_Rt_, 1, g_psxRegs.GPR.r[_Rt_])

// Rd = Rs op Rt
PGXP_INT_FUNC_2_1(CPU, ADD, !_Rd_, 3, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rs_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, ADDU, !_Rd_, 3, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rs_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SUB, !_Rd_, 3, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rs_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SUBU, !_Rd_, 3, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rs_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, AND, !_Rd_, 3, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rs_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, OR, !_Rd_, 3, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rs_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, XOR, !_Rd_, 3, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rs_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, NOR, !_Rd_, 3, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rs_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SLT, !_Rd_, 3, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rs_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SLTU, !_Rd_, 3, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rs_], g_psxRegs.GPR.r[_Rt_])

// Hi/Lo = Rs op Rt
PGXP_INT_FUNC_2_2(CPU, MULT, 0, 4, g_psxRegs.GPR.n.hi, g_psxRegs.GPR.n.lo, g_psxRegs.GPR.r[_Rs_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_2(CPU, MULTU, 0, 4, g_psxRegs.GPR.n.hi, g_psxRegs.GPR.n.lo, g_psxRegs.GPR.r[_Rs_],
                  g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_2(CPU, DIV, 0, 4, g_psxRegs.GPR.n.hi, g_psxRegs.GPR.n.lo, g_psxRegs.GPR.r[_Rs_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_2(CPU, DIVU, 0, 4, g_psxRegs.GPR.n.hi, g_psxRegs.GPR.n.lo, g_psxRegs.GPR.r[_Rs_], g_psxRegs.GPR.r[_Rt_])

// Mem[addr] = Rt
PGXP_INT_FUNC_1_1(CPU, SB, 0, 2, g_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SH, 0, 2, g_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SW, 0, 2, g_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SWL, 0, 2, g_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SWR, 0, 2, g_psxRegs.GPR.r[_Rt_], _oB_)

// Rt = Mem[addr]
PGXP_INT_FUNC_1_1(CPU, LWL, 0, 2, g_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LW, 0, 2, g_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LWR, 0, 2, g_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LH, 0, 2, g_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LHU, 0, 2, g_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LB, 0, 2, g_psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LBU, 0, 2, g_psxRegs.GPR.r[_Rt_], _oB_)

// Rd = Rt op Sa
PGXP_INT_FUNC_1_1(CPU, SLL, !_Rd_, 2, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(CPU, SRL, !_Rd_, 2, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(CPU, SRA, !_Rd_, 2, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rt_])

// Rd = Rt op Rs
PGXP_INT_FUNC_2_1(CPU, SLLV, !_Rd_, 3, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rt_], g_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_2_1(CPU, SRLV, !_Rd_, 3, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rt_], g_psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_2_1(CPU, SRAV, !_Rd_, 3, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.r[_Rt_], g_psxRegs.GPR.r[_Rs_])

PGXP_INT_FUNC_1_1(CPU, MFHI, !_Rd_, 2, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.n.hi)
PGXP_INT_FUNC_1_1(CPU, MTHI, 0, 2, g_psxRegs.GPR.n.hi, g_psxRegs.GPR.r[_Rd_])
PGXP_INT_FUNC_1_1(CPU, MFLO, !_Rd_, 2, g_psxRegs.GPR.r[_Rd_], g_psxRegs.GPR.n.lo)
PGXP_INT_FUNC_1_1(CPU, MTLO, 0, 2, g_psxRegs.GPR.n.lo, g_psxRegs.GPR.r[_Rd_])

// COP2 (GTE)
PGXP_INT_FUNC_1_1(GTE, MFC2, !_Rt_, 2, g_psxRegs.GPR.r[_Rt_], g_psxRegs.CP2D.r[_Rd_])
PGXP_INT_FUNC_1_1(GTE, CFC2, !_Rt_, 2, g_psxRegs.GPR.r[_Rt_], g_psxRegs.CP2C.r[_Rd_])
PGXP_INT_FUNC_1_1(GTE, MTC2, 0, 2, g_psxRegs.CP2D.r[_Rd_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(GTE, CTC2, 0, 2, g_psxRegs.CP2C.r[_Rd_], g_psxRegs.GPR.r[_Rt_])

PGXP_INT_FUNC_1_1(GTE, LWC2, 0, 2, g_psxRegs.CP2D.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(GTE, SWC2, 0, 2, g_psxRegs.CP2D.r[_Rt_], _oB_)

// COP0
PGXP_INT_FUNC_1_1(CP0, MFC0, !_Rd_, 2, g_psxRegs.GPR.r[_Rt_], g_psxRegs.CP0.r[_Rd_])
PGXP_INT_FUNC_1_1(CP0, CFC0, !_Rd_, 2, g_psxRegs.GPR.r[_Rt_], g_psxRegs.CP0.r[_Rd_])
PGXP_INT_FUNC_1_1(CP0, MTC0, !_Rt_, 2, g_psxRegs.CP0.r[_Rd_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(CP0, CTC0, !_Rt_, 2, g_psxRegs.CP0.r[_Rd_], g_psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC(CP0, RFE)

// end of PGXP

// Trace all functions using PGXP
static void (*s_pgxpPsxBSC[64])() = {
    psxSPECIAL,  psxREGIMM,    psxJ,        psxJAL,       psxBEQ,      psxBNE,      psxBLEZ,     psxBGTZ,
    pgxpPsxADDI, pgxpPsxADDIU, pgxpPsxSLTI, pgxpPsxSLTIU, pgxpPsxANDI, pgxpPsxORI,  pgxpPsxXORI, pgxpPsxLUI,
    psxCOP0,     psxNULL,      psxCOP2,     psxNULL,      psxNULL,     psxNULL,     psxNULL,     psxNULL,
    psxNULL,     psxNULL,      psxNULL,     psxNULL,      psxNULL,     psxNULL,     psxNULL,     psxNULL,
    pgxpPsxLB,   pgxpPsxLH,    pgxpPsxLWL,  pgxpPsxLW,    pgxpPsxLBU,  pgxpPsxLHU,  pgxpPsxLWR,  pgxpPsxNULL,
    pgxpPsxSB,   pgxpPsxSH,    pgxpPsxSWL,  pgxpPsxSW,    pgxpPsxNULL, pgxpPsxNULL, pgxpPsxSWR,  pgxpPsxNULL,
    psxNULL,     psxNULL,      pgxpPsxLWC2, psxNULL,      psxNULL,     psxNULL,     psxNULL,     psxNULL,
    psxNULL,     psxNULL,      pgxpPsxSWC2, psxHLE,       psxNULL,     psxNULL,     psxNULL,     psxNULL};

static void (*s_pgxpPsxSPC[64])() = {
    pgxpPsxSLL,  pgxpPsxNULL,  pgxpPsxSRL,  pgxpPsxSRA,  pgxpPsxSLLV, pgxpPsxNULL, pgxpPsxSRLV, pgxpPsxSRAV,
    psxJR,       psxJALR,      psxNULL,     psxNULL,     psxSYSCALL,  psxBREAK,    psxNULL,     psxNULL,
    pgxpPsxMFHI, pgxpPsxMTHI,  pgxpPsxMFLO, pgxpPsxMTLO, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxMULT, pgxpPsxMULTU, pgxpPsxDIV,  pgxpPsxDIVU, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxADD,  pgxpPsxADDU,  pgxpPsxSUB,  pgxpPsxSUBU, pgxpPsxAND,  pgxpPsxOR,   pgxpPsxXOR,  pgxpPsxNOR,
    pgxpPsxNULL, pgxpPsxNULL,  pgxpPsxSLT,  pgxpPsxSLTU, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxNULL, pgxpPsxNULL,  pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxNULL, pgxpPsxNULL,  pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL};

static void (*s_pgxpPsxCP0[32])() = {
    pgxpPsxMFC0, pgxpPsxNULL, pgxpPsxCFC0, pgxpPsxNULL, pgxpPsxMTC0, pgxpPsxNULL, pgxpPsxCTC0, pgxpPsxNULL,
    pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxRFE,  pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL};

static void (*s_pgxpPsxCP2BSC[32])() = {
    pgxpPsxMFC2, pgxpPsxNULL, pgxpPsxCFC2, pgxpPsxNULL, pgxpPsxMTC2, pgxpPsxNULL, pgxpPsxCTC2, pgxpPsxNULL,
    pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL};

// Trace memory functions only
static void (*s_pgxpPsxBSCMem[64])() = {
    psxSPECIAL, psxREGIMM, psxJ,        psxJAL,    psxBEQ,      psxBNE,      psxBLEZ,    psxBGTZ,
    psxADDI,    psxADDIU,  psxSLTI,     psxSLTIU,  psxANDI,     psxORI,      psxXORI,    psxLUI,
    psxCOP0,    psxNULL,   psxCOP2,     psxNULL,   psxNULL,     psxNULL,     psxNULL,    psxNULL,
    psxNULL,    psxNULL,   psxNULL,     psxNULL,   psxNULL,     psxNULL,     psxNULL,    psxNULL,
    pgxpPsxLB,  pgxpPsxLH, pgxpPsxLWL,  pgxpPsxLW, pgxpPsxLBU,  pgxpPsxLHU,  pgxpPsxLWR, pgxpPsxNULL,
    pgxpPsxSB,  pgxpPsxSH, pgxpPsxSWL,  pgxpPsxSW, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxSWR, pgxpPsxNULL,
    psxNULL,    psxNULL,   pgxpPsxLWC2, psxNULL,   psxNULL,     psxNULL,     psxNULL,    psxNULL,
    psxNULL,    psxNULL,   pgxpPsxSWC2, psxHLE,    psxNULL,     psxNULL,     psxNULL,    psxNULL};

///////////////////////////////////////////

static int intInit() { return 0; }

static void intReset() { g_psxRegs.ICache_valid = FALSE; }

static void intExecute() {
    for (;;) execI();
}

static void intExecuteBlock() {
    s_branch2 = 0;
    while (!s_branch2) execI();
}

static void intClear(u32 Addr, u32 Size) {}

static void intShutdown() {}

// interpreter execution
static inline void execI() {
    u32 *code = Read_ICache(g_psxRegs.pc, FALSE);
    g_psxRegs.code = ((code == NULL) ? 0 : SWAP32(*code));

    debugI();

    if (g_config.Debug) ProcessDebug();

    g_psxRegs.pc += 4;
    g_psxRegs.cycle += BIAS;

    s_pPsxBSC[g_psxRegs.code >> 26]();
}

static void intSetPGXPMode(u32 pgxpMode) {
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
    intReset();
}

R3000Acpu g_psxInt = {
    intInit, 
    intReset,
    intExecute,
    intExecuteBlock,
    intClear,
    intShutdown,
    intSetPGXPMode
};
