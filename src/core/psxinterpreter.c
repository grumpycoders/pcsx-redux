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

#include "gte.h"
#include "pgxp_cpu.h"
#include "pgxp_debug.h"
#include "pgxp_gte.h"
#include "psxcommon.h"
#include "psxhle.h"
#include "r3000a.h"

static int s_branch = 0;
static int branch2 = 0;
static u32 branchPC;

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

// Subsets
void (*psxBSC[64])();
void (*psxSPC[64])();
void (*psxREG[32])();
void (*psxCP0[32])();
void (*psxCP2[64])();
void (*psxCP2BSC[32])();

/// PGXP function tables
static void (*pgxpPsxBSC[64])();
static void (*pgxpPsxSPC[64])();
static void (*pgxpPsxCP0[32])();
static void (*pgxpPsxCP2BSC[32])();

static void (*pgxpPsxBSCMem[64])();
///

static void (**pPsxBSC)() = psxBSC;
static void (**pPsxSPC)() = psxSPC;
static void (**pPsxREG)() = psxREG;
static void (**pPsxCP0)() = psxCP0;
static void (**pPsxCP2)() = psxCP2;
static void (**pPsxCP2BSC)() = psxCP2BSC;

static void intReset();
static void intSetPGXPMode(u32 pgxpMode) {
    switch (pgxpMode) {
        case 0:  // PGXP_MODE_DISABLED:
            pPsxBSC = psxBSC;
            pPsxSPC = psxSPC;
            pPsxREG = psxREG;
            pPsxCP0 = psxCP0;
            pPsxCP2 = psxCP2;
            pPsxCP2BSC = psxCP2BSC;
            break;
        case 1:  // PGXP_MODE_MEM:
            pPsxBSC = pgxpPsxBSCMem;
            pPsxSPC = psxSPC;
            pPsxREG = psxREG;
            pPsxCP0 = pgxpPsxCP0;
            pPsxCP2 = psxCP2;
            pPsxCP2BSC = pgxpPsxCP2BSC;
            break;
        case 2:  // PGXP_MODE_FULL:
            pPsxBSC = pgxpPsxBSC;
            pPsxSPC = pgxpPsxSPC;
            pPsxREG = psxREG;
            pPsxCP0 = pgxpPsxCP0;
            pPsxCP2 = psxCP2;
            pPsxCP2BSC = pgxpPsxCP2BSC;
            break;
    }

    // reset to ensure new func tables are used
    intReset();
}

static void delayRead(int reg, u32 bpc) {
    u32 rold, rnew;

    //	SysPrintf("delayRead at %x!\n", g_psxRegs.pc);

    rold = g_psxRegs.GPR.r[reg];
    pPsxBSC[g_psxRegs.code >> 26]();  // branch delay load
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

    pPsxBSC[g_psxRegs.code >> 26]();

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
    pPsxBSC[g_psxRegs.code >> 26]();

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

    branch2 = s_branch = 1;
    branchPC = tar;

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
                    psxDelayTest(_Rt_, branchPC);
                    return;
            }
            break;
        case 0x12:  // COP2
            switch (_Funct_) {
                case 0x00:
                    switch (_Rs_) {
                        case 0x00:  // MFC2
                        case 0x02:  // CFC2
                            psxDelayTest(_Rt_, branchPC);
                            return;
                    }
                    break;
            }
            break;
        case 0x32:  // LWC2
            psxDelayTest(_Rt_, branchPC);
            return;
        default:
            if (tmp >= 0x20 && tmp <= 0x26) {  // LB/LH/LWL/LW/LBU/LHU/LWR
                psxDelayTest(_Rt_, branchPC);
                return;
            }
            break;
    }

    pPsxBSC[g_psxRegs.code >> 26]();

    s_branch = 0;
    g_psxRegs.pc = branchPC;

    psxBranchTest();
}

/*********************************************************
 * Arithmetic with immediate operand                      *
 * Format:  OP rt, rs, immediate                          *
 *********************************************************/
void psxADDI() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) + _Imm_;
}  // Rt = Rs + Im 	(Exception on Integer Overflow)
void psxADDIU() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) + _Imm_;
}  // Rt = Rs + Im
void psxANDI() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) & _ImmU_;
}  // Rt = Rs And Im
void psxORI() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) | _ImmU_;
}  // Rt = Rs Or  Im
void psxXORI() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) ^ _ImmU_;
}  // Rt = Rs Xor Im
void psxSLTI() {
    if (!_Rt_) return;
    _rRt_ = _i32(_rRs_) < _Imm_;
}  // Rt = Rs < Im		(Signed)
void psxSLTIU() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) < ((u32)_Imm_);
}  // Rt = Rs < Im		(Unsigned)

/*********************************************************
 * Register arithmetic                                    *
 * Format:  OP rd, rs, rt                                 *
 *********************************************************/
void psxADD() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) + _u32(_rRt_);
}  // Rd = Rs + Rt		(Exception on Integer Overflow)
void psxADDU() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) + _u32(_rRt_);
}  // Rd = Rs + Rt
void psxSUB() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) - _u32(_rRt_);
}  // Rd = Rs - Rt		(Exception on Integer Overflow)
void psxSUBU() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) - _u32(_rRt_);
}  // Rd = Rs - Rt
void psxAND() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) & _u32(_rRt_);
}  // Rd = Rs And Rt
void psxOR() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) | _u32(_rRt_);
}  // Rd = Rs Or  Rt
void psxXOR() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) ^ _u32(_rRt_);
}  // Rd = Rs Xor Rt
void psxNOR() {
    if (!_Rd_) return;
    _rRd_ = ~(_u32(_rRs_) | _u32(_rRt_));
}  // Rd = Rs Nor Rt
void psxSLT() {
    if (!_Rd_) return;
    _rRd_ = _i32(_rRs_) < _i32(_rRt_);
}  // Rd = Rs < Rt		(Signed)
void psxSLTU() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) < _u32(_rRt_);
}  // Rd = Rs < Rt		(Unsigned)

/*********************************************************
 * Register mult/div & Register trap logic                *
 * Format:  OP rs, rt                                     *
 *********************************************************/
void psxDIV() {
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

void psxDIVU() {
    if (_rRt_ != 0) {
        _rLo_ = _rRs_ / _rRt_;
        _rHi_ = _rRs_ % _rRt_;
    } else {
        _rLo_ = 0xffffffff;
        _rHi_ = _rRs_;
    }
}

void psxMULT() {
    u64 res = (s64)((s64)_i32(_rRs_) * (s64)_i32(_rRt_));

    g_psxRegs.GPR.n.lo = (u32)(res & 0xffffffff);
    g_psxRegs.GPR.n.hi = (u32)((res >> 32) & 0xffffffff);
}

void psxMULTU() {
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

void psxBGEZ() { RepZBranchi32(>=) }        // Branch if Rs >= 0
void psxBGEZAL() { RepZBranchLinki32(>=) }  // Branch if Rs >= 0 and link
void psxBGTZ() { RepZBranchi32(>) }         // Branch if Rs >  0
void psxBLEZ() { RepZBranchi32(<=) }        // Branch if Rs <= 0
void psxBLTZ() { RepZBranchi32(<) }         // Branch if Rs <  0
void psxBLTZAL() { RepZBranchLinki32(<) }   // Branch if Rs <  0 and link

/*********************************************************
 * Shift arithmetic with constant shift                   *
 * Format:  OP rd, rt, sa                                 *
 *********************************************************/
void psxSLL() {
    if (!_Rd_) return;
    _u32(_rRd_) = _u32(_rRt_) << _Sa_;
}  // Rd = Rt << sa
void psxSRA() {
    if (!_Rd_) return;
    _i32(_rRd_) = _i32(_rRt_) >> _Sa_;
}  // Rd = Rt >> sa (arithmetic)
void psxSRL() {
    if (!_Rd_) return;
    _u32(_rRd_) = _u32(_rRt_) >> _Sa_;
}  // Rd = Rt >> sa (logical)

/*********************************************************
 * Shift arithmetic with variant register shift           *
 * Format:  OP rd, rt, rs                                 *
 *********************************************************/
void psxSLLV() {
    if (!_Rd_) return;
    _u32(_rRd_) = _u32(_rRt_) << _u32(_rRs_);
}  // Rd = Rt << rs
void psxSRAV() {
    if (!_Rd_) return;
    _i32(_rRd_) = _i32(_rRt_) >> _u32(_rRs_);
}  // Rd = Rt >> rs (arithmetic)
void psxSRLV() {
    if (!_Rd_) return;
    _u32(_rRd_) = _u32(_rRt_) >> _u32(_rRs_);
}  // Rd = Rt >> rs (logical)

/*********************************************************
 * Load higher 16 bits of the first word in GPR with imm  *
 * Format:  OP rt, immediate                              *
 *********************************************************/
void psxLUI() {
    if (!_Rt_) return;
    _u32(_rRt_) = _ImmLU_;
}  // Upper halfword of Rt = Im

/*********************************************************
 * Move from HI/LO to GPR                                 *
 * Format:  OP rd                                         *
 *********************************************************/
void psxMFHI() {
    if (!_Rd_) return;
    _rRd_ = _rHi_;
}  // Rd = Hi
void psxMFLO() {
    if (!_Rd_) return;
    _rRd_ = _rLo_;
}  // Rd = Lo

/*********************************************************
 * Move to GPR to HI/LO & Register jump                   *
 * Format:  OP rs                                         *
 *********************************************************/
void psxMTHI() { _rHi_ = _rRs_; }  // Hi = Rs
void psxMTLO() { _rLo_ = _rRs_; }  // Lo = Rs

/*********************************************************
 * Special purpose instructions                           *
 * Format:  OP                                            *
 *********************************************************/
void psxBREAK() {
    // Break exception - psx rom doens't handles this
}

void psxSYSCALL() {
    g_psxRegs.pc -= 4;
    psxException(0x20, s_branch);
}

void psxRFE() {
    //	SysPrintf("psxRFE\n");
    g_psxRegs.CP0.n.Status = (g_psxRegs.CP0.n.Status & 0xfffffff0) | ((g_psxRegs.CP0.n.Status & 0x3c) >> 2);
}

/*********************************************************
 * Register branch logic                                  *
 * Format:  OP rs, rt, offset                             *
 *********************************************************/
#define RepBranchi32(op) \
    if (_i32(_rRs_) op _i32(_rRt_)) doBranch(_BranchTarget_);

void psxBEQ() { RepBranchi32(==) }  // Branch if Rs == Rt
void psxBNE() { RepBranchi32(!=) }  // Branch if Rs != Rt

/*********************************************************
 * Jump to target                                         *
 * Format:  OP target                                     *
 *********************************************************/
void psxJ() { doBranch(_JumpTarget_); }
void psxJAL() {
    _SetLink(31);
    doBranch(_JumpTarget_);
}

/*********************************************************
 * Register jump                                          *
 * Format:  OP rs, rd                                     *
 *********************************************************/
void psxJR() {
    doBranch(_u32(_rRs_));
    psxJumpTest();
}

void psxJALR() {
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

void psxLB() {
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

void psxLBU() {
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

void psxLH() {
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

void psxLHU() {
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

void psxLW() {
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

u32 LWL_MASK[4] = {0xffffff, 0xffff, 0xff, 0};
u32 LWL_SHIFT[4] = {24, 16, 8, 0};

void psxLWL() {
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
    _u32(_rRt_) = (_u32(_rRt_) & LWL_MASK[shift]) | (mem << LWL_SHIFT[shift]);

    /*
    Mem = 1234.  Reg = abcd

    0   4bcd   (mem << 24) | (reg & 0x00ffffff)
    1   34cd   (mem << 16) | (reg & 0x0000ffff)
    2   234d   (mem <<  8) | (reg & 0x000000ff)
    3   1234   (mem      ) | (reg & 0x00000000)
    */
}

u32 LWR_MASK[4] = {0, 0xff000000, 0xffff0000, 0xffffff00};
u32 LWR_SHIFT[4] = {0, 8, 16, 24};

void psxLWR() {
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
    _u32(_rRt_) = (_u32(_rRt_) & LWR_MASK[shift]) | (mem >> LWR_SHIFT[shift]);

    /*
    Mem = 1234.  Reg = abcd

    0   1234   (mem      ) | (reg & 0x00000000)
    1   a123   (mem >>  8) | (reg & 0xff000000)
    2   ab12   (mem >> 16) | (reg & 0xffff0000)
    3   abc1   (mem >> 24) | (reg & 0xffffff00)
    */
}

void psxSB() { psxMemWrite8(_oB_, _u8(_rRt_)); }
void psxSH() { psxMemWrite16(_oB_, _u16(_rRt_)); }
void psxSW() { psxMemWrite32(_oB_, _u32(_rRt_)); }

u32 SWL_MASK[4] = {0xffffff00, 0xffff0000, 0xff000000, 0};
u32 SWL_SHIFT[4] = {24, 16, 8, 0};

void psxSWL() {
    u32 addr = _oB_;
    u32 shift = addr & 3;
    u32 mem = psxMemRead32(addr & ~3);

    psxMemWrite32(addr & ~3, (_u32(_rRt_) >> SWL_SHIFT[shift]) | (mem & SWL_MASK[shift]));
    /*
    Mem = 1234.  Reg = abcd

    0   123a   (reg >> 24) | (mem & 0xffffff00)
    1   12ab   (reg >> 16) | (mem & 0xffff0000)
    2   1abc   (reg >>  8) | (mem & 0xff000000)
    3   abcd   (reg      ) | (mem & 0x00000000)
    */
}

u32 SWR_MASK[4] = {0, 0xff, 0xffff, 0xffffff};
u32 SWR_SHIFT[4] = {0, 8, 16, 24};

void psxSWR() {
    u32 addr = _oB_;
    u32 shift = addr & 3;
    u32 mem = psxMemRead32(addr & ~3);

    psxMemWrite32(addr & ~3, (_u32(_rRt_) << SWR_SHIFT[shift]) | (mem & SWR_MASK[shift]));

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
void psxMFC0() {
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

void psxCFC0() {
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

void psxMTC0() { MTC0(_Rd_, _u32(_rRt_)); }
void psxCTC0() { MTC0(_Rd_, _u32(_rRt_)); }

void psxMFC2() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        g_psxRegs.pc -= 4;
        doBranch(g_psxRegs.pc + 4);

        return;
    }

    gteMFC2();
}

void psxCFC2() {
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
void psxNULL() {
#ifdef PSXCPU_LOG
    PSXCPU_LOG("psx: Unimplemented op %x\n", g_psxRegs.code);
#endif
}

void psxSPECIAL() { pPsxSPC[_Funct_](); }

void psxREGIMM() { pPsxREG[_Rt_](); }

void psxCOP0() { pPsxCP0[_Rs_](); }

void psxCOP2() {
    if ((g_psxRegs.CP0.n.Status & 0x40000000) == 0) return;

    pPsxCP2[_Funct_]();
}

void psxBASIC() { pPsxCP2BSC[_Rs_](); }

void psxHLE() {
    //	psxHLEt[g_psxRegs.code & 0xffff]();
    psxHLEt[g_psxRegs.code & 0x07]();  // HDHOSHY experimental patch
}

void (*psxBSC[64])() = {psxSPECIAL, psxREGIMM, psxJ,    psxJAL,  psxBEQ,  psxBNE,  psxBLEZ, psxBGTZ, psxADDI, psxADDIU,
                        psxSLTI,    psxSLTIU,  psxANDI, psxORI,  psxXORI, psxLUI,  psxCOP0, psxNULL, psxCOP2, psxNULL,
                        psxNULL,    psxNULL,   psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,
                        psxNULL,    psxNULL,   psxLB,   psxLH,   psxLWL,  psxLW,   psxLBU,  psxLHU,  psxLWR,  psxNULL,
                        psxSB,      psxSH,     psxSWL,  psxSW,   psxNULL, psxNULL, psxSWR,  psxNULL, psxNULL, psxNULL,
                        gteLWC2,    psxNULL,   psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, gteSWC2, psxHLE,
                        psxNULL,    psxNULL,   psxNULL, psxNULL};

void (*psxSPC[64])() = {psxSLL,  psxNULL, psxSRL,     psxSRA,   psxSLLV, psxNULL,  psxSRLV, psxSRAV, psxJR,   psxJALR,
                        psxNULL, psxNULL, psxSYSCALL, psxBREAK, psxNULL, psxNULL,  psxMFHI, psxMTHI, psxMFLO, psxMTLO,
                        psxNULL, psxNULL, psxNULL,    psxNULL,  psxMULT, psxMULTU, psxDIV,  psxDIVU, psxNULL, psxNULL,
                        psxNULL, psxNULL, psxADD,     psxADDU,  psxSUB,  psxSUBU,  psxAND,  psxOR,   psxXOR,  psxNOR,
                        psxNULL, psxNULL, psxSLT,     psxSLTU,  psxNULL, psxNULL,  psxNULL, psxNULL, psxNULL, psxNULL,
                        psxNULL, psxNULL, psxNULL,    psxNULL,  psxNULL, psxNULL,  psxNULL, psxNULL, psxNULL, psxNULL,
                        psxNULL, psxNULL, psxNULL,    psxNULL};

void (*psxREG[32])() = {psxBLTZ,   psxBGEZ,   psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,
                        psxNULL,   psxNULL,   psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,
                        psxBLTZAL, psxBGEZAL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,
                        psxNULL,   psxNULL,   psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL};

void (*psxCP0[32])() = {psxMFC0, psxNULL, psxCFC0, psxNULL, psxMTC0, psxNULL, psxCTC0, psxNULL,
                        psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,
                        psxRFE,  psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,
                        psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL};

void (*psxCP2[64])() = {
    psxBASIC, gteRTPS,  psxNULL,  psxNULL, psxNULL, psxNULL,  gteNCLIP, psxNULL,  // 00
    psxNULL,  psxNULL,  psxNULL,  psxNULL, gteOP,   psxNULL,  psxNULL,  psxNULL,  // 08
    gteDPCS,  gteINTPL, gteMVMVA, gteNCDS, gteCDP,  psxNULL,  gteNCDT,  psxNULL,  // 10
    psxNULL,  psxNULL,  psxNULL,  gteNCCS, gteCC,   psxNULL,  gteNCS,   psxNULL,  // 18
    gteNCT,   psxNULL,  psxNULL,  psxNULL, psxNULL, psxNULL,  psxNULL,  psxNULL,  // 20
    gteSQR,   gteDCPL,  gteDPCT,  psxNULL, psxNULL, gteAVSZ3, gteAVSZ4, psxNULL,  // 28
    gteRTPT,  psxNULL,  psxNULL,  psxNULL, psxNULL, psxNULL,  psxNULL,  psxNULL,  // 30
    psxNULL,  psxNULL,  psxNULL,  psxNULL, psxNULL, gteGPF,   gteGPL,   gteNCCT   // 38
};

void (*psxCP2BSC[32])() = {psxMFC2, psxNULL, psxCFC2, psxNULL, gteMTC2, psxNULL, gteCTC2, psxNULL,
                           psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,
                           psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,
                           psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL};

#include "psxinterpreter_pgxp.h"
// Trace all functions using PGXP
static void (*pgxpPsxBSC[64])() = {
    psxSPECIAL,  psxREGIMM,    psxJ,        psxJAL,       psxBEQ,      psxBNE,      psxBLEZ,     psxBGTZ,
    pgxpPsxADDI, pgxpPsxADDIU, pgxpPsxSLTI, pgxpPsxSLTIU, pgxpPsxANDI, pgxpPsxORI,  pgxpPsxXORI, pgxpPsxLUI,
    psxCOP0,     psxNULL,      psxCOP2,     psxNULL,      psxNULL,     psxNULL,     psxNULL,     psxNULL,
    psxNULL,     psxNULL,      psxNULL,     psxNULL,      psxNULL,     psxNULL,     psxNULL,     psxNULL,
    pgxpPsxLB,   pgxpPsxLH,    pgxpPsxLWL,  pgxpPsxLW,    pgxpPsxLBU,  pgxpPsxLHU,  pgxpPsxLWR,  pgxpPsxNULL,
    pgxpPsxSB,   pgxpPsxSH,    pgxpPsxSWL,  pgxpPsxSW,    pgxpPsxNULL, pgxpPsxNULL, pgxpPsxSWR,  pgxpPsxNULL,
    psxNULL,     psxNULL,      pgxpPsxLWC2, psxNULL,      psxNULL,     psxNULL,     psxNULL,     psxNULL,
    psxNULL,     psxNULL,      pgxpPsxSWC2, psxHLE,       psxNULL,     psxNULL,     psxNULL,     psxNULL};

static void (*pgxpPsxSPC[64])() = {
    pgxpPsxSLL,  pgxpPsxNULL,  pgxpPsxSRL,  pgxpPsxSRA,  pgxpPsxSLLV, pgxpPsxNULL, pgxpPsxSRLV, pgxpPsxSRAV,
    psxJR,       psxJALR,      psxNULL,     psxNULL,     psxSYSCALL,  psxBREAK,    psxNULL,     psxNULL,
    pgxpPsxMFHI, pgxpPsxMTHI,  pgxpPsxMFLO, pgxpPsxMTLO, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxMULT, pgxpPsxMULTU, pgxpPsxDIV,  pgxpPsxDIVU, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxADD,  pgxpPsxADDU,  pgxpPsxSUB,  pgxpPsxSUBU, pgxpPsxAND,  pgxpPsxOR,   pgxpPsxXOR,  pgxpPsxNOR,
    pgxpPsxNULL, pgxpPsxNULL,  pgxpPsxSLT,  pgxpPsxSLTU, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxNULL, pgxpPsxNULL,  pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxNULL, pgxpPsxNULL,  pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL};

static void (*pgxpPsxCP0[32])() = {
    pgxpPsxMFC0, pgxpPsxNULL, pgxpPsxCFC0, pgxpPsxNULL, pgxpPsxMTC0, pgxpPsxNULL, pgxpPsxCTC0, pgxpPsxNULL,
    pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxRFE,  pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL};

static void (*pgxpPsxCP2BSC[32])() = {
    pgxpPsxMFC2, pgxpPsxNULL, pgxpPsxCFC2, pgxpPsxNULL, pgxpPsxMTC2, pgxpPsxNULL, pgxpPsxCTC2, pgxpPsxNULL,
    pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL,
    pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL, pgxpPsxNULL};

// Trace memory functions only
static void (*pgxpPsxBSCMem[64])() = {
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
    branch2 = 0;
    while (!branch2) execI();
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

    pPsxBSC[g_psxRegs.code >> 26]();
}

R3000Acpu psxInt = {intInit, intReset, intExecute, intExecuteBlock, intClear, intShutdown, intSetPGXPMode};
