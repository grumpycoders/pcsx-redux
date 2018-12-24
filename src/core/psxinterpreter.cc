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
#include "core/gte.h"
#include "core/pgxp_cpu.h"
#include "core/pgxp_debug.h"
#include "core/pgxp_gte.h"
#include "core/psxemulator.h"
#include "core/psxhle.h"
#include "core/r3000a.h"

static int s_branch = 0;
static int s_branch2 = 0;
static uint32_t s_branchPC;

// These macros are used to assemble the repassembler functions

#define debugI()                                                                                                    \
    if (PCSX::g_emulator.config().verbose) {                                                                        \
        PSXCPU_LOG("%s\n",                                                                                          \
                   disR3000AF(PCSX::g_emulator.m_psxCpu->m_psxRegs.code, PCSX::g_emulator.m_psxCpu->m_psxRegs.pc)); \
    }

static inline void execI();

static void (**s_pPsxBSC)() = NULL;
static void (**s_pPsxSPC)() = NULL;
static void (**s_pPsxREG)() = NULL;
static void (**s_pPsxCP0)() = NULL;
static void (**s_pPsxCP2)() = NULL;
static void (**s_pPsxCP2BSC)() = NULL;

static void delayRead(int reg, uint32_t bpc) {
    uint32_t rold, rnew;

    //  PCSX::g_system->SysPrintf("delayRead at %x!\n", PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);

    rold = PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[reg];
    s_pPsxBSC[PCSX::g_emulator.m_psxCpu->m_psxRegs.code >> 26]();  // branch delay load
    rnew = PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[reg];

    PCSX::g_emulator.m_psxCpu->m_psxRegs.pc = bpc;

    s_branch = 0;

    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[reg] = rold;
    execI();  // first branch opcode
    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[reg] = rnew;

    PCSX::g_emulator.m_psxCpu->psxBranchTest();
}

static void delayWrite(int reg, uint32_t bpc) {
    /*  PCSX::g_system->SysPrintf("delayWrite at %x!\n", PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);

            PCSX::g_system->SysPrintf("%s\n", disR3000AF(PCSX::g_emulator.m_psxCpu->m_psxRegs.code,
       PCSX::g_emulator.m_psxCpu->m_psxRegs.pc-4)); PCSX::g_system->SysPrintf("%s\n", disR3000AF(PSXMu32(bpc), bpc));*/

    // no changes from normal behavior

    s_pPsxBSC[PCSX::g_emulator.m_psxCpu->m_psxRegs.code >> 26]();

    s_branch = 0;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.pc = bpc;

    PCSX::g_emulator.m_psxCpu->psxBranchTest();
}

static void delayReadWrite(int reg, uint32_t bpc) {
    //  PCSX::g_system->SysPrintf("delayReadWrite at %x!\n", PCSX::g_emulator.m_psxCpu->m_psxRegs.pc);

    // the branch delay load is skipped

    s_branch = 0;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.pc = bpc;

    PCSX::g_emulator.m_psxCpu->psxBranchTest();
}

// this defines shall be used with the tmp
// of the next func (instead of _Funct_...)
#define _tFunct_ ((tmp)&0x3F)       // The funct part of the instruction register
#define _tRd_ ((tmp >> 11) & 0x1F)  // The rd part of the instruction register
#define _tRt_ ((tmp >> 16) & 0x1F)  // The rt part of the instruction register
#define _tRs_ ((tmp >> 21) & 0x1F)  // The rs part of the instruction register
#define _tSa_ ((tmp >> 6) & 0x1F)   // The sa part of the instruction register

int PCSX::R3000Acpu::psxTestLoadDelay(int reg, uint32_t tmp) {
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

void PCSX::R3000Acpu::psxDelayTest(int reg, uint32_t bpc) {
    uint32_t *code;
    uint32_t tmp;

    // Don't execute yet - just peek
    code = PCSX::g_emulator.m_psxCpu->Read_ICache(bpc, true);

    tmp = ((code == NULL) ? 0 : SWAP_LE32(*code));
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
    s_pPsxBSC[m_psxRegs.code >> 26]();

    s_branch = 0;
    m_psxRegs.pc = bpc;

    psxBranchTest();
}

static uint32_t psxBranchNoDelay(void) {
    uint32_t *code;
    uint32_t temp;

    code = PCSX::g_emulator.m_psxCpu->Read_ICache(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc, true);
    PCSX::g_emulator.m_psxCpu->m_psxRegs.code = ((code == NULL) ? 0 : SWAP_LE32(*code));
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

    return (uint32_t)-1;
}

static int psxDelayBranchExec(uint32_t tar) {
    execI();

    s_branch = 0;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.pc = tar;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle += PCSX::Emulator::BIAS;
    PCSX::g_emulator.m_psxCpu->psxBranchTest();
    return 1;
}

static int psxDelayBranchTest(uint32_t tar1) {
    uint32_t tar2, tmp1, tmp2;

    tar2 = psxBranchNoDelay();
    if (tar2 == (uint32_t)-1) return 0;

    debugI();

    /*
     * Branch in delay slot:
     * - execute 1 instruction at tar1
     * - jump to tar2 (target of branch in delay slot; this branch
     *   has no normal delay slot, instruction at tar1 was fetched instead)
     */
    PCSX::g_emulator.m_psxCpu->m_psxRegs.pc = tar1;
    tmp1 = psxBranchNoDelay();
    if (tmp1 == (uint32_t)-1) {
        return psxDelayBranchExec(tar2);
    }
    debugI();
    PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle += PCSX::Emulator::BIAS;

    /*
     * Got a branch at tar1:
     * - execute 1 instruction at tar2
     * - jump to target of that branch (tmp1)
     */
    PCSX::g_emulator.m_psxCpu->m_psxRegs.pc = tar2;
    tmp2 = psxBranchNoDelay();
    if (tmp2 == (uint32_t)-1) {
        return psxDelayBranchExec(tmp1);
    }
    debugI();
    PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle += PCSX::Emulator::BIAS;

    /*
     * Got a branch at tar2:
     * - execute 1 instruction at tmp1
     * - jump to target of that branch (tmp2)
     */
    PCSX::g_emulator.m_psxCpu->m_psxRegs.pc = tmp1;
    return psxDelayBranchExec(tmp2);
}

static __inline void doBranch(uint32_t tar) {
    uint32_t *code;
    uint32_t tmp;

    s_branch2 = s_branch = 1;
    s_branchPC = tar;

    // notaz: check for branch in delay slot
    if (psxDelayBranchTest(tar)) return;

    // branch delay slot
    code = PCSX::g_emulator.m_psxCpu->Read_ICache(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc, true);

    PCSX::g_emulator.m_psxCpu->m_psxRegs.code = ((code == NULL) ? 0 : SWAP_LE32(*code));

    debugI();

    PCSX::g_emulator.m_psxCpu->m_psxRegs.pc += 4;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle += PCSX::Emulator::BIAS;

    // check for load delay
    tmp = PCSX::g_emulator.m_psxCpu->m_psxRegs.code >> 26;
    switch (tmp) {
        case 0x10:  // COP0
            switch (_Rs_) {
                case 0x00:  // MFC0
                case 0x02:  // CFC0
                    PCSX::g_emulator.m_psxCpu->psxDelayTest(_Rt_, s_branchPC);
                    return;
            }
            break;
        case 0x12:  // COP2
            switch (_Funct_) {
                case 0x00:
                    switch (_Rs_) {
                        case 0x00:  // MFC2
                        case 0x02:  // CFC2
                            PCSX::g_emulator.m_psxCpu->psxDelayTest(_Rt_, s_branchPC);
                            return;
                    }
                    break;
            }
            break;
        case 0x32:  // LWC2
            PCSX::g_emulator.m_psxCpu->psxDelayTest(_Rt_, s_branchPC);
            return;
        default:
            if (tmp >= 0x20 && tmp <= 0x26) {  // LB/LH/LWL/LW/LBU/LHU/LWR
                PCSX::g_emulator.m_psxCpu->psxDelayTest(_Rt_, s_branchPC);
                return;
            }
            break;
    }

    s_pPsxBSC[PCSX::g_emulator.m_psxCpu->m_psxRegs.code >> 26]();

    s_branch = 0;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.pc = s_branchPC;

    PCSX::g_emulator.m_psxCpu->psxBranchTest();
}

/*********************************************************
 * Arithmetic with immediate operand                      *
 * Format:  OP rt, rs, immediate                          *
 *********************************************************/
static void psxADDI() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) + _Imm_;
}  // Rt = Rs + Im      (Exception on Integer Overflow)
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
}  // Rt = Rs < Im              (Signed)
static void psxSLTIU() {
    if (!_Rt_) return;
    _rRt_ = _u32(_rRs_) < ((uint32_t)_Imm_);
}  // Rt = Rs < Im              (Unsigned)

/*********************************************************
 * Register arithmetic                                    *
 * Format:  OP rd, rs, rt                                 *
 *********************************************************/
static void psxADD() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) + _u32(_rRt_);
}  // Rd = Rs + Rt              (Exception on Integer Overflow)
static void psxADDU() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) + _u32(_rRt_);
}  // Rd = Rs + Rt
static void psxSUB() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) - _u32(_rRt_);
}  // Rd = Rs - Rt              (Exception on Integer Overflow)
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
}  // Rd = Rs < Rt              (Signed)
static void psxSLTU() {
    if (!_Rd_) return;
    _rRd_ = _u32(_rRs_) < _u32(_rRt_);
}  // Rd = Rs < Rt              (Unsigned)

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
    uint64_t res = (int64_t)((int64_t)_i32(_rRs_) * (int64_t)_i32(_rRt_));

    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.lo = (uint32_t)(res & 0xffffffff);
    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.hi = (uint32_t)((res >> 32) & 0xffffffff);
}

static void psxMULTU() {
    uint64_t res = (uint64_t)((uint64_t)_u32(_rRs_) * (uint64_t)_u32(_rRt_));

    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.lo = (uint32_t)(res & 0xffffffff);
    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.hi = (uint32_t)((res >> 32) & 0xffffffff);
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

static void psxBGEZ() { RepZBranchi32(>=) }        // Branch if Rs >= 0
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
    PCSX::g_emulator.m_psxCpu->m_psxRegs.pc -= 4;
    PCSX::g_emulator.m_psxCpu->psxException(0x20, s_branch);
}

static void psxRFE() {
    //  PCSX::g_system->SysPrintf("psxRFE\n");
    PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status =
        (PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status & 0xfffffff0) |
        ((PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status & 0x3c) >> 2);
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
    PCSX::g_emulator.m_psxCpu->psxJumpTest();
}

static void psxJALR() {
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

static void psxLB() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        PCSX::g_emulator.m_psxCpu->m_psxRegs.pc -= 4;
        doBranch(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc + 4);

        return;
    }

    if (_Rt_) {
        _i32(_rRt_) = (signed char)PCSX::g_emulator.m_psxMem->psxMemRead8(_oB_);
    } else {
        PCSX::g_emulator.m_psxMem->psxMemRead8(_oB_);
    }
}

static void psxLBU() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        PCSX::g_emulator.m_psxCpu->m_psxRegs.pc -= 4;
        doBranch(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc + 4);

        return;
    }

    if (_Rt_) {
        _u32(_rRt_) = PCSX::g_emulator.m_psxMem->psxMemRead8(_oB_);
    } else {
        PCSX::g_emulator.m_psxMem->psxMemRead8(_oB_);
    }
}

static void psxLH() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        PCSX::g_emulator.m_psxCpu->m_psxRegs.pc -= 4;
        doBranch(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc + 4);

        return;
    }

    if (_Rt_) {
        _i32(_rRt_) = (short)PCSX::g_emulator.m_psxMem->psxMemRead16(_oB_);
    } else {
        PCSX::g_emulator.m_psxMem->psxMemRead16(_oB_);
    }
}

static void psxLHU() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        PCSX::g_emulator.m_psxCpu->m_psxRegs.pc -= 4;
        doBranch(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc + 4);

        return;
    }

    if (_Rt_) {
        _u32(_rRt_) = PCSX::g_emulator.m_psxMem->psxMemRead16(_oB_);
    } else {
        PCSX::g_emulator.m_psxMem->psxMemRead16(_oB_);
    }
}

static void psxLW() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        PCSX::g_emulator.m_psxCpu->m_psxRegs.pc -= 4;
        doBranch(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc + 4);

        return;
    }

    if (_Rt_) {
        _u32(_rRt_) = PCSX::g_emulator.m_psxMem->psxMemRead32(_oB_);
    } else {
        PCSX::g_emulator.m_psxMem->psxMemRead32(_oB_);
    }
}

extern "C" const uint32_t g_LWL_MASK[4] = {0xffffff, 0xffff, 0xff, 0};
extern "C" const uint32_t g_LWL_SHIFT[4] = {24, 16, 8, 0};

static void psxLWL() {
    uint32_t addr = _oB_;
    uint32_t shift = addr & 3;
    uint32_t mem = PCSX::g_emulator.m_psxMem->psxMemRead32(addr & ~3);

    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        PCSX::g_emulator.m_psxCpu->m_psxRegs.pc -= 4;
        doBranch(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc + 4);

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

extern "C" const uint32_t g_LWR_MASK[4] = {0, 0xff000000, 0xffff0000, 0xffffff00};
extern "C" const uint32_t g_LWR_SHIFT[4] = {0, 8, 16, 24};

static void psxLWR() {
    uint32_t addr = _oB_;
    uint32_t shift = addr & 3;
    uint32_t mem = PCSX::g_emulator.m_psxMem->psxMemRead32(addr & ~3);

    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        PCSX::g_emulator.m_psxCpu->m_psxRegs.pc -= 4;
        doBranch(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc + 4);

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

static void psxSB() { PCSX::g_emulator.m_psxMem->psxMemWrite8(_oB_, _u8(_rRt_)); }
static void psxSH() { PCSX::g_emulator.m_psxMem->psxMemWrite16(_oB_, _u16(_rRt_)); }
static void psxSW() { PCSX::g_emulator.m_psxMem->psxMemWrite32(_oB_, _u32(_rRt_)); }

extern "C" const uint32_t g_SWL_MASK[4] = {0xffffff00, 0xffff0000, 0xff000000, 0};
extern "C" const uint32_t g_SWL_SHIFT[4] = {24, 16, 8, 0};

static void psxSWL() {
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

extern "C" const uint32_t g_SWR_MASK[4] = {0, 0xff, 0xffff, 0xffffff};
extern "C" const uint32_t g_SWR_SHIFT[4] = {0, 8, 16, 24};

static void psxSWR() {
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
static void psxMFC0() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        PCSX::g_emulator.m_psxCpu->m_psxRegs.pc -= 4;
        doBranch(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc + 4);

        return;
    }

    if (!_Rt_) return;

    _i32(_rRt_) = (int)_rFs_;
}

static void psxCFC0() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        PCSX::g_emulator.m_psxCpu->m_psxRegs.pc -= 4;
        doBranch(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc + 4);

        return;
    }

    if (!_Rt_) return;

    _i32(_rRt_) = (int)_rFs_;
}

void PCSX::R3000Acpu::psxTestSWInts() {
    // the next code is untested, if u know please
    // tell me if it works ok or not (linuzappz)
    if (m_psxRegs.CP0.n.Cause & m_psxRegs.CP0.n.Status & 0x0300 && m_psxRegs.CP0.n.Status & 0x1) {
        psxException(m_psxRegs.CP0.n.Cause, s_branch);
    }
}

static __inline void MTC0(int reg, uint32_t val) {
    //  PCSX::g_system->SysPrintf("MTC0 %d: %x\n", reg, val);
    switch (reg) {
        case 12:  // Status
            PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.r[12] = val;
            PCSX::g_emulator.m_psxCpu->psxTestSWInts();
            break;

        case 13:  // Cause
            PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Cause = val & ~(0xfc00);
            PCSX::g_emulator.m_psxCpu->psxTestSWInts();
            break;

        default:
            PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.r[reg] = val;
            break;
    }
}

static void psxMTC0() { MTC0(_Rd_, _u32(_rRt_)); }
static void psxCTC0() { MTC0(_Rd_, _u32(_rRt_)); }

static void psxMFC2() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        PCSX::g_emulator.m_psxCpu->m_psxRegs.pc -= 4;
        doBranch(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc + 4);

        return;
    }

    gteMFC2();
}

static void psxCFC2() {
    // load delay = 1 latency
    if (s_branch == 0) {
        // simulate: beq r0,r0,lw+4 / lw / (delay slot)
        PCSX::g_emulator.m_psxCpu->m_psxRegs.pc -= 4;
        doBranch(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc + 4);

        return;
    }

    gteCFC2();
}

/*********************************************************
 * Unknow instruction (would generate an exception)       *
 * Format:  ?                                             *
 *********************************************************/
static void psxNULL() { PSXCPU_LOG("psx: Unimplemented op %x\n", PCSX::g_emulator.m_psxCpu->m_psxRegs.code); }

static void psxSPECIAL() { s_pPsxSPC[_Funct_](); }

static void psxREGIMM() { s_pPsxREG[_Rt_](); }

static void psxCOP0() { s_pPsxCP0[_Rs_](); }

static void psxCOP2() {
    if ((PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status & 0x40000000) == 0) return;

    s_pPsxCP2[_Funct_]();
}

static void psxBASIC() { s_pPsxCP2BSC[_Rs_](); }

static void psxHLE() {
    //  psxHLEt[PCSX::g_emulator.m_psxCpu->m_psxRegs.code & 0xffff]();
    psxHLEt[PCSX::g_emulator.m_psxCpu->m_psxRegs.code & 0x07]();  // HDHOSHY experimental patch
}

static void (*s_psxBSC[64])() = {
    psxSPECIAL, psxREGIMM, psxJ,    psxJAL,   psxBEQ,  psxBNE,  psxBLEZ, psxBGTZ,  // 00
    psxADDI,    psxADDIU,  psxSLTI, psxSLTIU, psxANDI, psxORI,  psxXORI, psxLUI,   // 08
    psxCOP0,    psxNULL,   psxCOP2, psxNULL,  psxNULL, psxNULL, psxNULL, psxNULL,  // 10
    psxNULL,    psxNULL,   psxNULL, psxNULL,  psxNULL, psxNULL, psxNULL, psxNULL,  // 18
    psxLB,      psxLH,     psxLWL,  psxLW,    psxLBU,  psxLHU,  psxLWR,  psxNULL,  // 20
    psxSB,      psxSH,     psxSWL,  psxSW,    psxNULL, psxNULL, psxSWR,  psxNULL,  // 28
    psxNULL,    psxNULL,   gteLWC2, psxNULL,  psxNULL, psxNULL, psxNULL, psxNULL,  // 30
    psxNULL,    psxNULL,   gteSWC2, psxHLE,   psxNULL, psxNULL, psxNULL, psxNULL,  // 38
};

static void (*s_psxSPC[64])() = {
    psxSLL,  psxNULL,  psxSRL,  psxSRA,  psxSLLV,    psxNULL,  psxSRLV, psxSRAV,  // 00
    psxJR,   psxJALR,  psxNULL, psxNULL, psxSYSCALL, psxBREAK, psxNULL, psxNULL,  // 08
    psxMFHI, psxMTHI,  psxMFLO, psxMTLO, psxNULL,    psxNULL,  psxNULL, psxNULL,  // 10
    psxMULT, psxMULTU, psxDIV,  psxDIVU, psxNULL,    psxNULL,  psxNULL, psxNULL,  // 18
    psxADD,  psxADDU,  psxSUB,  psxSUBU, psxAND,     psxOR,    psxXOR,  psxNOR,   // 20
    psxNULL, psxNULL,  psxSLT,  psxSLTU, psxNULL,    psxNULL,  psxNULL, psxNULL,  // 28
    psxNULL, psxNULL,  psxNULL, psxNULL, psxNULL,    psxNULL,  psxNULL, psxNULL,  // 30
    psxNULL, psxNULL,  psxNULL, psxNULL, psxNULL,    psxNULL,  psxNULL, psxNULL,  // 38
};

static void (*s_psxREG[32])() = {
    psxBLTZ,   psxBGEZ,   psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,  // 00
    psxNULL,   psxNULL,   psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,  // 08
    psxBLTZAL, psxBGEZAL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,  // 10
    psxNULL,   psxNULL,   psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,  // 18
};

static void (*s_psxCP0[32])() = {
    psxMFC0, psxNULL, psxCFC0, psxNULL, psxMTC0, psxNULL, psxCTC0, psxNULL,  // 00
    psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,  // 08
    psxRFE,  psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,  // 10
    psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,  // 18
};

void (*s_psxCP2[64])() = {
    psxBASIC, gteRTPS,  psxNULL,  psxNULL, psxNULL, psxNULL,  gteNCLIP, psxNULL,  // 00
    psxNULL,  psxNULL,  psxNULL,  psxNULL, gteOP,   psxNULL,  psxNULL,  psxNULL,  // 08
    gteDPCS,  gteINTPL, gteMVMVA, gteNCDS, gteCDP,  psxNULL,  gteNCDT,  psxNULL,  // 10
    psxNULL,  psxNULL,  psxNULL,  gteNCCS, gteCC,   psxNULL,  gteNCS,   psxNULL,  // 18
    gteNCT,   psxNULL,  psxNULL,  psxNULL, psxNULL, psxNULL,  psxNULL,  psxNULL,  // 20
    gteSQR,   gteDCPL,  gteDPCT,  psxNULL, psxNULL, gteAVSZ3, gteAVSZ4, psxNULL,  // 28
    gteRTPT,  psxNULL,  psxNULL,  psxNULL, psxNULL, psxNULL,  psxNULL,  psxNULL,  // 30
    psxNULL,  psxNULL,  psxNULL,  psxNULL, psxNULL, gteGPF,   gteGPL,   gteNCCT,  // 38
};

void (*s_psxCP2BSC[32])() = {
    psxMFC2, psxNULL, psxCFC2, psxNULL, gteMTC2, psxNULL, gteCTC2, psxNULL,  // 00
    psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,  // 08
    psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,  // 10
    psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL, psxNULL,  // 18
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

#define PGXP_INT_FUNC(pu, op)                                                                    \
    static void pgxpPsx##op() {                                                                  \
        PGXP_PSX_FUNC_OP(pu, op, )(PGXP_DBG_OP_E(op) PCSX::g_emulator.m_psxCpu->m_psxRegs.code); \
        psx##op();                                                                               \
    }

#define PGXP_INT_FUNC_0_1(pu, op, test, nReg, reg1)                        \
    static void pgxpPsx##op() {                                            \
        if (test) {                                                        \
            psx##op();                                                     \
            return;                                                        \
        }                                                                  \
        uint32_t tempInstr = PCSX::g_emulator.m_psxCpu->m_psxRegs.code;    \
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
        uint32_t tempInstr = PCSX::g_emulator.m_psxCpu->m_psxRegs.code;           \
        uint32_t temp2 = reg2;                                                    \
        psx##op();                                                                \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, temp2); \
    }

#define PGXP_INT_FUNC_0_2(pu, op, test, nReg, reg1, reg2)                        \
    static void pgxpPsx##op() {                                                  \
        if (test) {                                                              \
            psx##op();                                                           \
            return;                                                              \
        }                                                                        \
        uint32_t tempInstr = PCSX::g_emulator.m_psxCpu->m_psxRegs.code;          \
        psx##op();                                                               \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, reg2); \
    }

#define PGXP_INT_FUNC_2_0(pu, op, test, nReg, reg1, reg2)                          \
    static void pgxpPsx##op() {                                                    \
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
    static void pgxpPsx##op() {                                                          \
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
    static void pgxpPsx##op() {                                                                \
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

static void intReset() { PCSX::g_emulator.m_psxCpu->m_psxRegs.ICache_valid = false; }

static void intExecute() {
    for (;;) execI();
}

static void intExecuteBlock() {
    s_branch2 = 0;
    while (!s_branch2) execI();
}

static void intClear(uint32_t Addr, uint32_t Size) {}

static void intShutdown() {}

// interpreter execution
static inline void execI() {
    uint32_t *code = PCSX::g_emulator.m_psxCpu->Read_ICache(PCSX::g_emulator.m_psxCpu->m_psxRegs.pc, false);
    PCSX::g_emulator.m_psxCpu->m_psxRegs.code = ((code == NULL) ? 0 : SWAP_LE32(*code));

    debugI();

    if (PCSX::g_emulator.config().Debug) ProcessDebug();

    PCSX::g_emulator.m_psxCpu->m_psxRegs.pc += 4;
    PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle += PCSX::Emulator::BIAS;

    s_pPsxBSC[PCSX::g_emulator.m_psxCpu->m_psxRegs.code >> 26]();
}

static void intSetPGXPMode(uint32_t pgxpMode) {
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

bool PCSX::InterpretedCPU::Init() { return intInit(); }
void PCSX::InterpretedCPU::Reset() { intReset(); }
void PCSX::InterpretedCPU::Execute() { intExecute(); }
void PCSX::InterpretedCPU::ExecuteBlock() { intExecuteBlock(); }
void PCSX::InterpretedCPU::Clear(uint32_t Addr, uint32_t Size) { intClear(Addr, Size); }
void PCSX::InterpretedCPU::Shutdown() { intShutdown(); }
void PCSX::InterpretedCPU::SetPGXPMode(uint32_t pgxpMode) { intSetPGXPMode(pgxpMode); }
