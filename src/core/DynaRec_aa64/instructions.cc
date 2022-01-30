/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include "recompiler.h"
#if defined(DYNAREC_AA64)
#define BAILZERO(x) \
    if (!(x)) {     \
        return;     \
    }

void DynaRecCPU::recUnknown() {
    PCSX::g_system->message("Unknown instruction for dynarec - address %08x, instruction %08x\n", m_pc, m_psxRegs.code);
    recException(Exception::ReservedInstruction);
}
void DynaRecCPU::recSpecial() {
    const auto func = m_recSPC[m_psxRegs.code & 0x3F];  // Look up the opcode in our decoding LUT
    (*this.*func)();                                    // Jump into the handler to recompile it
}

void DynaRecCPU::recADD() { throw std::runtime_error("[Unimplemented] ADD instruction"); }

void DynaRecCPU::recADDIU() {
    BAILZERO(_Rt_);
    maybeCancelDelayedLoad(_Rt_);

    if (_Rs_ == _Rt_) {
        if (m_regs[_Rt_].isConst()) {
            m_regs[_Rt_].val += _Imm_;
        } else {
            allocateReg(_Rt_);
            m_regs[_Rt_].setWriteback(true);
            switch (_Imm_) {
                case 1:
                    gen.Add(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, 1);
                    break;
                case -1:
                    gen.Sub(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, 1);
                    break;
                default:
                    gen.Add(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, _Imm_);
                    break;
            }
        }
    } else {
        if (m_regs[_Rs_].isConst()) {
            markConst(_Rt_, m_regs[_Rs_].val + _Imm_);
        } else {
            alloc_rs_wb_rt();
            gen.moveAndAdd(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg, _Imm_);
        }
    }
}

void DynaRecCPU::recADDU() { throw std::runtime_error("[Unimplemented] ADDU instruction"); }
void DynaRecCPU::recAND() { throw std::runtime_error("[Unimplemented] AND instruction"); }
void DynaRecCPU::recANDI() { throw std::runtime_error("[Unimplemented] ANDI instruction"); }
void DynaRecCPU::recBEQ() { throw std::runtime_error("[Unimplemented] BEQ instruction"); }
void DynaRecCPU::recBGTZ() { throw std::runtime_error("[Unimplemented] BGTZ instruction"); }
void DynaRecCPU::recBLEZ() { throw std::runtime_error("[Unimplemented] BLEZ instruction"); }

void DynaRecCPU::recBNE() {
    const auto target = _Imm_ * 4 + m_pc;
    m_nextIsDelaySlot = true;

    if (target == m_pc + 4) {
        return;
    }

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        if (m_regs[_Rs_].val != m_regs[_Rt_].val) {
            m_pcWrittenBack = true;
            m_stopCompiling = true;
            gen.Mov(scratch, target);
            gen.Str(scratch, MemOperand(contextPointer, PC_OFFSET));
            m_linkedPC = target;
        }
        return;
    } else if (m_regs[_Rs_].isConst()) {
        allocateReg(_Rt_);
        gen.cmpEqImm(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
    } else if (m_regs[_Rt_].isConst()) {
        allocateReg(_Rs_);
        gen.cmpEqImm(m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
    } else {
        alloc_rt_rs();
        gen.Cmp(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
    }

    m_pcWrittenBack = true;
    m_stopCompiling = true;

    gen.Mov(scratch, target); // scratch = addr if jump taken
    gen.Mov(scratch2, m_pc + 4); // scratch2 = addr if jump not taken
    gen.Csel(w0, scratch, scratch2, ne); // if not equal, return the jump addr into w0
    gen.Str(w0, MemOperand(contextPointer, PC_OFFSET));
}

void DynaRecCPU::recBREAK() { throw std::runtime_error("[Unimplemented] BREAK instruction"); }

void DynaRecCPU::recCOP0() {
    switch (_Rs_) {  // figure out the type of COP0 opcode
        case 0:
            recMFC0();
            break;
        case 4:
            recMTC0();
            break;
        case 16:
            recRFE();
            break;
        default:
            fmt::print("Unimplemented cop0 op {}\n", _Rs_);
            recUnknown();
            break;
    }
}

void DynaRecCPU::recDIV() { throw std::runtime_error("[Unimplemented] DIV instruction"); }
void DynaRecCPU::recDIVU() { throw std::runtime_error("[Unimplemented] DIVU instruction"); }

void DynaRecCPU::recJ() {
    const uint32_t target = (m_pc & 0xf0000000) | (_Target_ << 2);
    m_nextIsDelaySlot = true;
    m_stopCompiling = true;
    m_pcWrittenBack = true;

    gen.Mov(scratch, target);
    gen.Str(scratch, MemOperand(contextPointer, PC_OFFSET)); // Write PC
    m_linkedPC = target;
}

void DynaRecCPU::recJAL() { throw std::runtime_error("[Unimplemented] JAL instruction"); }
void DynaRecCPU::recJALR() { throw std::runtime_error("[Unimplemented] JALR instruction"); }
void DynaRecCPU::recJR() { throw std::runtime_error("[Unimplemented] JR instruction"); }
void DynaRecCPU::recLB() { throw std::runtime_error("[Unimplemented] LB instruction"); }
void DynaRecCPU::recLBU() { throw std::runtime_error("[Unimplemented] LBU instruction"); }
void DynaRecCPU::recLH() { throw std::runtime_error("[Unimplemented] LH instruction"); }
void DynaRecCPU::recLHU() { throw std::runtime_error("[Unimplemented] LHU instruction"); }

void DynaRecCPU::recLUI() {
    BAILZERO(_Rt_);

    maybeCancelDelayedLoad(_Rt_);
    markConst(_Rt_, m_psxRegs.code << 16);
}

void DynaRecCPU::recLW() { throw std::runtime_error("[Unimplemented] LW instruction"); }
void DynaRecCPU::recLWL() { throw std::runtime_error("[Unimplemented] LWL instruction"); }
void DynaRecCPU::recLWR() { throw std::runtime_error("[Unimplemented] LWR instruction"); }
void DynaRecCPU::recMFC0() { throw std::runtime_error("[Unimplemented] MFC0 instruction"); }
void DynaRecCPU::recMFHI() { throw std::runtime_error("[Unimplemented] MFHI instruction"); }
void DynaRecCPU::recMFLO() { throw std::runtime_error("[Unimplemented] MFLO instruction"); }
void DynaRecCPU::recMTC0() { throw std::runtime_error("[Unimplemented] MTC0 instruction"); }
void DynaRecCPU::recMTHI() { throw std::runtime_error("[Unimplemented] MTHI instruction"); }
void DynaRecCPU::recMTLO() { throw std::runtime_error("[Unimplemented] MTLP instruction"); }
void DynaRecCPU::recMULT() { throw std::runtime_error("[Unimplemented] MULT instruction"); }
void DynaRecCPU::recMULTU() { throw std::runtime_error("[Unimplemented] MULTU instruction"); }
void DynaRecCPU::recNOR() { throw std::runtime_error("[Unimplemented] NOR instruction"); }

void DynaRecCPU::recOR() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        markConst(_Rd_, m_regs[_Rs_].val | m_regs[_Rt_].val);
    } else if (m_regs[_Rs_].isConst()) {
        alloc_rt_wb_rd();

        gen.orImm(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
    } else if (m_regs[_Rt_].isConst()) {
        alloc_rs_wb_rd();

        gen.orImm(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
    } else {
        alloc_rt_rs_wb_rd();

        if (_Rd_ == _Rs_) {
            gen.Orr(m_regs[_Rd_].allocatedReg, m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        } else if (_Rd_ == _Rt_) {
            gen.Orr(m_regs[_Rd_].allocatedReg, m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
        } else {
            gen.Orr(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
        }
    }
}

void DynaRecCPU::recORI() {
    BAILZERO(_Rt_);
    maybeCancelDelayedLoad(_Rt_);

    if (_Rs_ == _Rt_) {
        if (m_regs[_Rs_].isConst()) {
            m_regs[_Rt_].val |= _ImmU_;
        } else {
            allocateReg(_Rt_);
            m_regs[_Rt_].setWriteback(true);
            gen.Orr(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, _ImmU_);
        }
    } else {
        if (m_regs[_Rs_].isConst()) {
            markConst(_Rt_, m_regs[_Rs_].val | _ImmU_);
        } else {
            alloc_rs_wb_rt();
            gen.orImm(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg, _ImmU_);
        }
    }
}

void DynaRecCPU::recREGIMM() { throw std::runtime_error("[Unimplemented] REGIMM instruction"); }
void DynaRecCPU::recRFE() { throw std::runtime_error("[Unimplemented] RFE instruction"); }
void DynaRecCPU::recSB() { throw std::runtime_error("[Unimplemented] SB instruction"); }
void DynaRecCPU::recSH() { throw std::runtime_error("[Unimplemented] SH instruction"); }

void DynaRecCPU::recSLL() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rt_].isConst()) {
        markConst(_Rd_, m_regs[_Rt_].val << _Sa_);
    } else {
        alloc_rt_wb_rd();
        // Was using shlImm in emitter.h - possible optimization opportunity
        gen.Lsl(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, _Sa_);
    }
}

void DynaRecCPU::recSLLV() { throw std::runtime_error("[Unimplemented] SLLV instruction"); }
void DynaRecCPU::recSLT() { throw std::runtime_error("[Unimplemented] SLT instruction"); }
void DynaRecCPU::recSLTI() { throw std::runtime_error("[Unimplemented] SLTI instruction"); }
void DynaRecCPU::recSLTIU() { throw std::runtime_error("[Unimplemented] SLTIU instruction"); }
void DynaRecCPU::recSLTU() { throw std::runtime_error("[Unimplemented] SLTU instruction"); }
void DynaRecCPU::recSRA() { throw std::runtime_error("[Unimplemented] SRA instruction"); }
void DynaRecCPU::recSRAV() { throw std::runtime_error("[Unimplemented] SRAV instruction"); }
void DynaRecCPU::recSRL() { throw std::runtime_error("[Unimplemented] SRL instruction"); }
void DynaRecCPU::recSRLV() { throw std::runtime_error("[Unimplemented] SRLV instruction"); }
void DynaRecCPU::recSUB() { throw std::runtime_error("[Unimplemented] SUB instruction"); }
void DynaRecCPU::recSUBU() { throw std::runtime_error("[Unimplemented] SUBU instruction"); }

void DynaRecCPU::recSW() {
    if (m_regs[_Rs_].isConst()) {
        const uint32_t addr = m_regs[_Rs_].val + _Imm_;
        const auto pointer = PCSX::g_emulator->m_psxMem->psxMemPointerWrite(addr);
        if (pointer != nullptr) {
            if (m_regs[_Rt_].isConst()) {
                store<32>(m_regs[_Rt_].val, pointer);
            } else {
                allocateReg(_Rt_);
                store<32>(m_regs[_Rt_].allocatedReg, pointer);
            }

            return;
        }

        if (m_regs[_Rt_].isConst()) {  // Value to write in arg2
            gen.Mov(arg2, m_regs[_Rt_].val);
        } else {
            allocateReg(_Rt_);
            gen.Mov(arg2, m_regs[_Rt_].allocatedReg);
        }

        gen.Mov(arg1, addr);  // Address to write to in arg1   TODO: Optimize
        call(psxMemWrite32Wrapper);
    }

    else {
        if (m_regs[_Rt_].isConst()) {  // Value to write in arg2
            gen.Mov(arg2, m_regs[_Rt_].val);
        } else {
            allocateReg(_Rt_);
            gen.Mov(arg2, m_regs[_Rt_].allocatedReg);
        }

        allocateReg(_Rs_);
        gen.moveAndAdd(arg1, m_regs[_Rs_].allocatedReg, _Imm_);  // Address to write to in arg1   TODO: Optimize
        call(psxMemWrite32Wrapper);
    }
}

void DynaRecCPU::recSWL() { throw std::runtime_error("[Unimplemented] SWL instruction"); }
void DynaRecCPU::recSWR() { throw std::runtime_error("[Unimplemented] SWR instruction"); }
void DynaRecCPU::recSYSCALL() { throw std::runtime_error("[Unimplemented] SYSCALL instruction"); }
void DynaRecCPU::recXOR() { throw std::runtime_error("[Unimplemented] XOR instruction"); }
void DynaRecCPU::recXORI() { throw std::runtime_error("[Unimplemented] XORI instruction"); }
void DynaRecCPU::recException(Exception e) { throw std::runtime_error("[Unimplemented] Recompile exception"); }

#undef BAILZERO
#endif  // DYNAREC_AA64
