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

// The Dynarec doesn't currently handle overflow exceptions, so we treat ADD the same as ADDU
void DynaRecCPU::recADD() { recADDU(); }

void DynaRecCPU::recADDU() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        markConst(_Rd_, m_regs[_Rs_].val + m_regs[_Rt_].val);
    } else if (m_regs[_Rs_].isConst()) {
        alloc_rt_wb_rd();
        gen.moveAndAdd(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
    } else if (m_regs[_Rt_].isConst()) {
        alloc_rs_wb_rd();
        gen.moveAndAdd(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
    } else {
        alloc_rt_rs_wb_rd();
        gen.Add(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
    }
}

void DynaRecCPU::recADDIU() {
    BAILZERO(_Rt_);
    maybeCancelDelayedLoad(_Rt_);

    if (_Rs_ == _Rt_) {
        if (m_regs[_Rt_].isConst()) {
            m_regs[_Rt_].val += _Imm_;
        } else {
            allocateReg(_Rt_);
            m_regs[_Rt_].setWriteback(true);
            gen.moveAndAdd(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, _Imm_);
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

void DynaRecCPU::recAND() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        markConst(_Rd_, m_regs[_Rs_].val & m_regs[_Rt_].val);
    } else if (m_regs[_Rs_].isConst()) {
        alloc_rt_wb_rd();
        gen.andImm(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
    } else if (m_regs[_Rt_].isConst()) {
        alloc_rs_wb_rd();
        gen.andImm(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
    } else {
        alloc_rt_rs_wb_rd();
        gen.And(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
    }
}

void DynaRecCPU::recANDI() {
    BAILZERO(_Rt_);
    maybeCancelDelayedLoad(_Rt_);

    if (_Rs_ == _Rt_) {
        if (m_regs[_Rs_].isConst()) {
            m_regs[_Rt_].val &= _ImmU_;
        } else {
            allocateReg(_Rt_);
            m_regs[_Rt_].setWriteback(true);
            gen.andImm(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, _ImmU_);
        }
    } else {
        if (m_regs[_Rs_].isConst()) {
            markConst(_Rt_, m_regs[_Rs_].val & _ImmU_);
        } else {
            alloc_rs_wb_rt();
            gen.andImm(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg, _ImmU_);
        }
    }
}

void DynaRecCPU::recBEQ() {
    const auto target = _Imm_ * 4 + m_pc;
    m_nextIsDelaySlot = true;

    if (target == m_pc + 4) {
        return;
    }

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        if (m_regs[_Rs_].val == m_regs[_Rt_].val) {
            m_pcWrittenBack = true;
            m_stopCompiling = true;
            gen.Mov(w0, target);
            gen.Str(w0, MemOperand(contextPointer, PC_OFFSET));
            m_linkedPC = target;
        }
        return;
    } else if (m_regs[_Rs_].isConst()) {
        allocateReg(_Rt_);
        gen.Cmp(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
    } else if (m_regs[_Rt_].isConst()) {
        allocateReg(_Rs_);
        gen.Cmp(m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
    } else {
        alloc_rt_rs();
        gen.Cmp(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
    }

    m_pcWrittenBack = true;
    m_stopCompiling = true;

    gen.Mov(w0, target);       // w0 = addr if jump taken
    gen.Mov(w1, m_pc + 4);     // w1 = addr if jump not taken
    gen.Csel(w0, w0, w1, eq);  // if taken, return the jump addr into w0
    gen.Str(w0, MemOperand(contextPointer, PC_OFFSET));
}

void DynaRecCPU::recBGTZ() {
    uint32_t target = _Imm_ * 4 + m_pc;

    m_nextIsDelaySlot = true;
    if (target == m_pc + 4) {
        return;
    }

    if (m_regs[_Rs_].isConst()) {
        if ((int32_t)m_regs[_Rs_].val > 0) {
            m_pcWrittenBack = true;
            m_stopCompiling = true;
            gen.Mov(w0, target);
            gen.Str(w0, MemOperand(contextPointer, PC_OFFSET));
            m_linkedPC = target;
        }
        return;
    }

    m_pcWrittenBack = true;
    m_stopCompiling = true;

    if (m_regs[_Rs_].isAllocated()) {  // Don't bother allocating Rs unless it's already allocated
        gen.Cmp(m_regs[_Rs_].allocatedReg, 0);
    } else {
        gen.Ldr(w0, MemOperand(contextPointer, GPR_OFFSET(_Rs_)));
        gen.Cmp(w0, 0);
    }

    gen.Mov(w0, target);       // w0 = addr if jump taken
    gen.Mov(w1, m_pc + 4);     // w1 = addr if jump not taken
    gen.Csel(w0, w0, w1, gt);  // if taken, return the jump addr into w0
    gen.Str(w0, MemOperand(contextPointer, PC_OFFSET));
}

void DynaRecCPU::recBLEZ() {
    uint32_t target = _Imm_ * 4 + m_pc;

    m_nextIsDelaySlot = true;
    if (target == m_pc + 4) {
        return;
    }

    if (m_regs[_Rs_].isConst()) {
        if ((int32_t)m_regs[_Rs_].val <= 0) {
            m_pcWrittenBack = true;
            m_stopCompiling = true;
            gen.Mov(w0, target);
            gen.Str(w0, MemOperand(contextPointer, PC_OFFSET));
            m_linkedPC = target;
        }
        return;
    }

    m_pcWrittenBack = true;
    m_stopCompiling = true;

    if (m_regs[_Rs_].isAllocated()) {  // Don't bother allocating Rs unless it's already allocated
        gen.Cmp(m_regs[_Rs_].allocatedReg, 0);
    } else {
        gen.Ldr(w0, MemOperand(contextPointer, GPR_OFFSET(_Rs_)));
        gen.Cmp(w0, 0);
    }

    gen.Mov(w0, target);       // w0 = addr if jump taken
    gen.Mov(w1, m_pc + 4);     // w1 = addr if jump not taken
    gen.Csel(w0, w0, w1, le);  // if taken, return the jump addr into w0
    gen.Str(w0, MemOperand(contextPointer, PC_OFFSET));
}

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
            gen.Mov(w0, target);
            gen.Str(w0, MemOperand(contextPointer, PC_OFFSET));
            m_linkedPC = target;
        }
        return;
    } else if (m_regs[_Rs_].isConst()) {
        allocateReg(_Rt_);
        gen.Cmp(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
    } else if (m_regs[_Rt_].isConst()) {
        allocateReg(_Rs_);
        gen.Cmp(m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
    } else {
        alloc_rt_rs();
        gen.Cmp(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
    }

    m_pcWrittenBack = true;
    m_stopCompiling = true;

    gen.Mov(w0, target);       // w0 = addr if jump taken
    gen.Mov(w1, m_pc + 4);     // w1 = addr if jump not taken
    gen.Csel(w0, w0, w1, ne);  // if taken, return the jump addr into w0
    gen.Str(w0, MemOperand(contextPointer, PC_OFFSET));
}

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

void DynaRecCPU::recDIV() {
    Label notIntMin, divisionByZero, end;
    bool emitIntMinCheck = true;

    if (m_regs[_Rt_].isConst()) {     // Check divisor if constant
        if (m_regs[_Rt_].val == 0) {  // Handle case where divisor is 0
            if (m_regs[_Rs_].isConst()) {
                gen.Mov(w0, m_regs[_Rs_].val & 0x80000000 ? 1 : -1);  // LO = 1 or -1 depending on the sign of $rs
                gen.Str(w0, MemOperand(contextPointer, LO_OFFSET));
                gen.Mov(w0, m_regs[_Rs_].val);
                gen.Str(w0, MemOperand(contextPointer, HI_OFFSET));  // HI = $rs
            }

            else {
                allocateReg(_Rs_);
                gen.Str(m_regs[_Rs_].allocatedReg, MemOperand(contextPointer, HI_OFFSET));  // Set hi to $rs
                gen.Lsr(w0, m_regs[_Rs_].allocatedReg, 31);
                gen.Sub(w1, w0, 1);
                gen.Add(w0, w0, w1);
                gen.Str(w0, MemOperand(contextPointer, LO_OFFSET));  // Set lo to 1 or -1 depending on the sign of $rs
            }

            return;
        } else if (m_regs[_Rt_].val != 0xffffffff) {
            emitIntMinCheck = false;
        }

        if (m_regs[_Rs_].isConst()) {
            if (m_regs[_Rs_].val == 0x80000000 && m_regs[_Rt_].val == 0xffffffff) {
                gen.Mov(w0, 0x80000000);
                gen.Str(w0, MemOperand(contextPointer, LO_OFFSET));
                gen.Str(wzr, MemOperand(contextPointer, HI_OFFSET));
            } else {
                gen.Mov(w0, (int32_t)m_regs[_Rs_].val / (int32_t)m_regs[_Rt_].val);
                gen.Mov(w1, (int32_t)m_regs[_Rs_].val % (int32_t)m_regs[_Rt_].val);
                gen.Str(w0, MemOperand(contextPointer, LO_OFFSET));
                gen.Str(w1, MemOperand(contextPointer, HI_OFFSET));
            }
            return;
        }

        allocateReg(_Rs_);
        gen.Mov(w0, m_regs[_Rs_].allocatedReg);
        gen.Mov(w1, m_regs[_Rt_].val);  // Divisor in w1
    } else {  // non-constant divisor
        if (m_regs[_Rs_].isConst()) {
            allocateReg(_Rt_);
            gen.Mov(w0, m_regs[_Rs_].val);  // Dividend in w0
            emitIntMinCheck = m_regs[_Rs_].val == 0x80000000;
        }

        else {
            alloc_rt_rs();
            gen.Mov(w0, m_regs[_Rs_].allocatedReg);  // Dividend in w0
        }

        gen.Mov(w1, m_regs[_Rt_].allocatedReg);  // Divisor in w1
        gen.Cmp(w1, 0);                          // Check if divisor is 0
        gen.beq(divisionByZero);                  // Jump to divisionByZero label if so
    }

    if (emitIntMinCheck) {
        gen.Mov(w4, 0x80000000);
        gen.Cmp(w0, w4);     // Check if dividend is INT_MIN
        gen.bne(notIntMin);  // Bail if not
        gen.Mov(w4, 0xffffffff);
        gen.Cmp(w1, w4);     // Check if divisor is -1
        gen.bne(notIntMin);  // Bail if not

        // Handle INT_MIN / -1
        gen.Mov(w0, 0x80000000);  // Set lo to INT_MIN
        gen.Mov(w3, 0);           // Set hi to 0
        gen.B(&end);
    }

    gen.L(notIntMin);
    gen.Sdiv(w2, w0, w1);      // Signed divide
    gen.Msub(w3, w2, w1, w0);  // Get remainder by msub

    if (!m_regs[_Rt_].isConst()) {  // Emit a division by 0 handler if the divisor is unknown at compile time
        gen.B(&end);                // skip to the end if not a div by zero
        gen.L(divisionByZero);      // Here starts our division by 0 handler

        gen.Mov(w3, w0);  // Set hi to $rs
        gen.Lsr(w2, w2, 31);
        gen.Sub(w5, w2, 1);
        gen.Add(w2, w2, w5);  // Set lo to 1 or -1 depending on the sign of $rs
    }

    gen.L(end);

    gen.Str(w2, MemOperand(contextPointer, LO_OFFSET));  // Lo = quotient
    gen.Str(w3, MemOperand(contextPointer, HI_OFFSET));  // Hi = remainder
}

void DynaRecCPU::recDIVU() {
    Label divisionByZero;

    if (m_regs[_Rt_].isConst()) {     // Check divisor if constant
        if (m_regs[_Rt_].val == 0) {  // Handle case where divisor is 0
            gen.Mov(w0, -1);
            gen.Str(w0, MemOperand(contextPointer, LO_OFFSET));  // Set lo to -1

            if (m_regs[_Rs_].isConst()) {
                gen.Mov(w0, m_regs[_Rs_].val);
                gen.Str(w0, MemOperand(contextPointer, HI_OFFSET));  // HI = $rs
            }

            else {
                allocateReg(_Rs_);
                gen.Str(m_regs[_Rs_].allocatedReg, MemOperand(contextPointer, HI_OFFSET));  // Set hi to $rs
            }

            return;
        }

        if (m_regs[_Rs_].isConst()) {
            gen.Mov(w0, m_regs[_Rs_].val / m_regs[_Rt_].val);
            gen.Mov(w1, m_regs[_Rs_].val % m_regs[_Rt_].val);
            gen.Str(w0, MemOperand(contextPointer, LO_OFFSET));
            gen.Str(w1, MemOperand(contextPointer, HI_OFFSET));
            return;
        }

        allocateReg(_Rs_);
        gen.Mov(w0, m_regs[_Rs_].allocatedReg);
        gen.Mov(w1, m_regs[_Rt_].val);  // Divisor in w1

    } else {  // non-constant divisor
        if (m_regs[_Rs_].isConst()) {
            allocateReg(_Rt_);
            gen.Mov(w0, m_regs[_Rs_].val);  // Dividend in w0
        }

        else {
            alloc_rt_rs();
            gen.Mov(w0, m_regs[_Rs_].allocatedReg);  // Dividend in w0
        }

        gen.Mov(w1, m_regs[_Rt_].allocatedReg);  // Divisor in w1
        gen.Cmp(w1, 0);                          // Check if divisor is 0
        gen.beq(divisionByZero);                 // Jump to divisionByZero label if so
    }
    // TODO: This may be able to be optimized with a proper AND depending
    gen.Mov(w3, 0);            // Set top 32 bits of dividend to 0
    gen.Udiv(w2, w0, w1);      // Unsigned division by divisor
    gen.Msub(w3, w2, w1, w0);  // Get remainder by msub

    if (!m_regs[_Rt_].isConst()) {  // Emit a division by 0 handler if the divisor is unknown at compile time
        Label end;
        gen.B(&end);            // skip to the end if not a div by zero
        gen.L(divisionByZero);  // Here starts our division by 0 handler
        gen.Mov(w3, w0);        // Set hi to $rs
        gen.Mov(w2, -1);        // Set lo to -1

        gen.L(end);
    }
    gen.Str(w2, MemOperand(contextPointer, LO_OFFSET));  // Lo = quotient = w2
    gen.Str(w3, MemOperand(contextPointer, HI_OFFSET));  // Hi = remainder = w3
}

void DynaRecCPU::recJ() {
    const uint32_t target = (m_pc & 0xf0000000) | (_Target_ << 2);
    m_nextIsDelaySlot = true;
    m_stopCompiling = true;
    m_pcWrittenBack = true;

    gen.Mov(w0, target);
    gen.Str(w0, MemOperand(contextPointer, PC_OFFSET));  // Write PC
    m_linkedPC = target;
}

void DynaRecCPU::recJAL() {
    maybeCancelDelayedLoad(31);
    markConst(31, m_pc + 4);  // Set $ra to the return value, then treat instruction like a normal J
    recJ();
}

void DynaRecCPU::recJALR() {
    recJR();

    if (_Rd_) {
        maybeCancelDelayedLoad(_Rd_);
        markConst(_Rd_, m_pc + 4);  // Link
    }
}

void DynaRecCPU::recJR() {
    m_nextIsDelaySlot = true;
    m_stopCompiling = true;
    m_pcWrittenBack = true;

    if (m_regs[_Rs_].isConst()) {
        gen.Mov(w0, m_regs[_Rs_].val & ~3);
        gen.Str(w0, MemOperand(contextPointer, PC_OFFSET));  // force align jump address
        m_linkedPC = m_regs[_Rs_].val;
    } else {
        allocateReg(_Rs_);
        // PC will get force aligned in the dispatcher since it discards the 2 lower bits
        gen.Str(m_regs[_Rs_].allocatedReg, MemOperand(contextPointer, PC_OFFSET));
    }
}

void DynaRecCPU::recLUI() {
    BAILZERO(_Rt_);

    maybeCancelDelayedLoad(_Rt_);
    markConst(_Rt_, m_psxRegs.code << 16);
}

void DynaRecCPU::recLB() { recompileLoad<8, true>(); }
void DynaRecCPU::recLBU() { recompileLoad<8, false>(); }
void DynaRecCPU::recLH() { recompileLoad<16, true>(); }
void DynaRecCPU::recLHU() { recompileLoad<16, false>(); }
void DynaRecCPU::recLW() { recompileLoad<32, true>(); }

void DynaRecCPU::recLWL() {
    // The mask to be applied to $rt (top 32 bits) and the shift to be applied to the read memory value (low 32 bits)
    // Depending on the low 3 bits of the unaligned address
    static const uint64_t MASKS_AND_SHIFTS[4] = {0x00FFFFFF00000018, 0x0000FFFF00000010, 0x000000FF00000008, 0};

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {  // Both previous register value and address are constant
        const uint32_t address = m_regs[_Rs_].val + _Imm_;
        const uint32_t alignedAddress = address & ~3;
        const uint32_t mask = LWL_MASK[address & 3];
        const auto shift = LWL_SHIFT[address & 3];
        const uint32_t previousValue = m_regs[_Rt_].val;

        gen.Mov(arg1, alignedAddress);  // Address in arg1
        call(psxMemRead32Wrapper);      // Read value returned in w0

        if (_Rt_) {
            allocateReg(_Rt_);  // Allocate $rt with writeback
            m_regs[_Rt_].setWriteback(true);
            gen.Mov(m_regs[_Rt_].allocatedReg, previousValue & mask);  // Mask the previous $rt value
            gen.Orr(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg,
                    Operand(w0, LSL, shift));  // Or $rt with shifted value in w0
        }
    } else if (m_regs[_Rs_].isConst()) {   // Only address is constant
        const uint32_t address = m_regs[_Rs_].val + _Imm_;
        const uint32_t alignedAddress = address & ~3;
        const uint32_t mask = LWL_MASK[address & 3];
        const auto shift = LWL_SHIFT[address & 3];

        gen.Mov(arg1, alignedAddress);  // Address in arg1
        call(psxMemRead32Wrapper);      // Read value returned in w0

        if (_Rt_) {
            allocateReg(_Rt_);  // Allocate $rt with writeback
            m_regs[_Rt_].setWriteback(true);
            gen.andImm(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, mask);  // Mask the previous $rt value
            gen.Orr(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg,
                    Operand(w0, LSL, shift));  // Or $rt with shifted value in w0
        }
    } else if (m_regs[_Rt_].isConst()) {   // Only previous rt value is constant
        const uint32_t previousValue = m_regs[_Rt_].val;

        allocateReg(_Rs_);                                       // Allocate address reg
        gen.moveAndAdd(arg1, m_regs[_Rs_].allocatedReg, _Imm_);  // Address in arg1
        gen.And(arg1, arg1, ~3);                                 // Force align it
        call(psxMemRead32Wrapper);                               // Read from the aligned address, result in w0

        if (_Rt_) {
            // The call might have flushed $rs, so we need to allocate it again, and also allocate $rt
            alloc_rs_wb_rt();
            gen.Mov(m_regs[_Rt_].allocatedReg, previousValue);     // Flush constant value in $rt
            gen.moveAndAdd(w1, m_regs[_Rs_].allocatedReg, _Imm_);  // Address in w1 again
            gen.And(w1, w1, 3);                                    // Get the low 2 bits
            gen.Mov(x3, (uintptr_t)&MASKS_AND_SHIFTS);  // Form PC-relative address to mask and shift lookup table
            gen.Ldr(x3, MemOperand(x3, x1, LSL, 3));    // Load the mask and shift from LUT by indexing using the bottom 2
                                                    // bits of the unaligned addr.
            gen.Lsr(x4, x3, 32);  // Shift x3 32 places to the right, resulting in mask in x4
            gen.Lsl(w0, w0, w3);  // Shift the read value by the shift amount
            gen.And(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, w4);  // Mask with w4
            gen.Orr(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, w0);  // Merge with shifted value
        }
    } else {                                                     // Nothing is constant
        allocateReg(_Rs_);                                       // Allocate address reg
        gen.moveAndAdd(arg1, m_regs[_Rs_].allocatedReg, _Imm_);  // Address in arg1
        gen.And(arg1, arg1, ~3);                                 // Force align it
        call(psxMemRead32Wrapper);                               // Read from the aligned address, result in w0

        if (_Rt_) {
            // The call might have flushed $rs, so we need to allocate it again, and also allocate $rt
            alloc_rs_wb_rt();
            gen.moveAndAdd(w1, m_regs[_Rs_].allocatedReg, _Imm_);  // Address in w1
            gen.And(w1, w1, 3);                                    // Get the low 2 bits
            gen.Mov(x3, (uintptr_t)&MASKS_AND_SHIFTS);             // Base to mask and shift lookup table in x3
            gen.Ldr(x3, MemOperand(x3, x1, LSL, 3));  // Load the mask and shift from LUT by indexing using the bottom 2
                                                    // bits of the unaligned addr.

            gen.Lsr(x4, x3, 32);  // Shift x3 32 places to the right, resulting in mask in x4
            gen.Lsl(w0, w0, w3);
            gen.And(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, w4);  // Mask with w4
            gen.Orr(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, w0);  // Merge with shifted value
        }
    }
}

void DynaRecCPU::recLWR() {
    // The mask to be applied to $rt (top 32 bits) and the shift to be applied to the read memory value (low 32 bits)
    // Depending on the low 3 bits of the unaligned address
    static const uint64_t MASKS_AND_SHIFTS[4] = {0, 0xFF00000000000008, 0xFFFF000000000010, 0xFFFFFF0000000018};

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {  // Both previous register value and address are constant
        const uint32_t address = m_regs[_Rs_].val + _Imm_;
        const uint32_t alignedAddress = address & ~3;
        const uint32_t mask = LWR_MASK[address & 3];
        const auto shift = LWR_SHIFT[address & 3];
        const uint32_t previousValue = m_regs[_Rt_].val;

        gen.Mov(arg1, alignedAddress);  // Address in arg1 (w0)
        call(psxMemRead32Wrapper);      // Read value returned in w0

        if (_Rt_) {
            allocateReg(_Rt_);  // Allocate $rt with writeback
            m_regs[_Rt_].setWriteback(true);
            gen.Mov(m_regs[_Rt_].allocatedReg, previousValue & mask);  // Mask the previous $rt value
            // Shift the read value from aligned address and Or $re with shifted value
            gen.Orr(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, Operand(w0, LSR, shift));
        }
    } else if (m_regs[_Rs_].isConst()) {  // Only address is constant
        const uint32_t address = m_regs[_Rs_].val + _Imm_;
        const uint32_t alignedAddress = address & ~3;
        const uint32_t mask = LWR_MASK[address & 3];
        const auto shift = LWR_SHIFT[address & 3];

        gen.Mov(arg1, alignedAddress);  // Address in arg1
        call(psxMemRead32Wrapper);      // Read value returned in w0

        if (_Rt_) {
            allocateReg(_Rt_);  // Allocate $rt with writeback
            m_regs[_Rt_].setWriteback(true);
            gen.andImm(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, mask);  // Mask the previous $rt value
            // Shift the read value from aligned address and Or $re with shifted value
            gen.Orr(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, Operand(w0, LSR, shift));
        }
    } else if (m_regs[_Rt_].isConst()) {  // Only previous rt value is constant
        const uint32_t previousValue = m_regs[_Rt_].val;

        allocateReg(_Rs_);                                       // Allocate address reg
        gen.moveAndAdd(arg1, m_regs[_Rs_].allocatedReg, _Imm_);  // Address in arg1
        gen.And(arg1, arg1, ~3);                                 // Force align it
        call(psxMemRead32Wrapper);                               // Read from the aligned address, result in w0

        if (_Rt_) {
            // The call might have flushed $rs, so we need to allocate it again, and also allocate $rt
            alloc_rs_wb_rt();
            gen.Mov(m_regs[_Rt_].allocatedReg, previousValue);     // Flush constant value in $rt
            gen.moveAndAdd(w1, m_regs[_Rs_].allocatedReg, _Imm_);  // Address in w1 again
            gen.And(w1, w1, 3);                                    // Get the low 2 bits
            gen.Mov(x3, (uintptr_t)&MASKS_AND_SHIFTS);  // Form PC-relative address to mask and shift lookup table
            gen.Ldr(x3, MemOperand(x3, x1, LSL, 3));    // Load the mask and shift from LUT by indexing using the bottom 2
                                                    // bits of the unaligned addr.
            gen.Lsr(x4, x3, 32);                                                // Mask now in w4
            gen.Lsr(w0, w0, w3);                                                // Shift the read value by the shift amount
            gen.And(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, w4);  // Mask previous $rt value
            gen.Orr(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, w0);  // Merge with newly read value
        }
    } else {                                                                // Nothing is constant
        allocateReg(_Rs_);                                                  // Allocate address reg
        gen.moveAndAdd(arg1, m_regs[_Rs_].allocatedReg, _Imm_);             // Address in arg1
        gen.And(arg1, arg1, ~3);                                            // Force align it
        call(psxMemRead32Wrapper);  // Read from the aligned address, result in eax

        if (_Rt_) {
            // The call might have flushed $rs, so we need to allocate it again, and also allocate $rt
            alloc_rs_wb_rt();
            gen.moveAndAdd(w1, m_regs[_Rs_].allocatedReg, _Imm_);  // Address in w1 again
            gen.And(w1, w1, 3);                                    // Get the low 2 bits
            gen.Mov(x3, (uintptr_t)&MASKS_AND_SHIFTS);  // Form PC-relative address to mask and shift lookup table
            gen.Ldr(x3, MemOperand(x3, x1, LSL, 3));    // Load the mask and shift from LUT by indexing using the bottom 2
                                                    // bits of the unaligned addr.
            gen.Lsr(x4, x3, 32);                                                // Mask now in w4
            gen.Lsr(w0, w0, w3);                                                // Shift the read value by the shift amount
            gen.And(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, w4);  // Mask previous $rt value
            gen.Orr(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, w0);  // Merge with newly read value
        }
    }
}

void DynaRecCPU::recMFC0() {
    BAILZERO(_Rt_);
    maybeCancelDelayedLoad(_Rt_);
    allocateRegWithoutLoad(_Rt_);
    m_regs[_Rt_].setWriteback(true);
    gen.Ldr(m_regs[_Rt_].allocatedReg, MemOperand(contextPointer, COP0_OFFSET(_Rd_)));
}

// TODO: Constant propagation for MFLO/HI, read the result from register if possible instead of reading memory again
void DynaRecCPU::recMFLO() {
    BAILZERO(_Rd_);

    maybeCancelDelayedLoad(_Rd_);
    allocateRegWithoutLoad(_Rd_);
    m_regs[_Rd_].setWriteback(true);

    gen.Ldr(m_regs[_Rd_].allocatedReg, MemOperand(contextPointer, LO_OFFSET));
}

// TODO: Constant propagation for MFLO/HI, read the result from register if possible instead of reading memory again
void DynaRecCPU::recMFHI() {
    BAILZERO(_Rd_);

    maybeCancelDelayedLoad(_Rd_);
    allocateRegWithoutLoad(_Rd_);
    m_regs[_Rd_].setWriteback(true);

    gen.Ldr(m_regs[_Rd_].allocatedReg, MemOperand(contextPointer, HI_OFFSET));
}

template <int size, bool signExtend>
void DynaRecCPU::recompileLoad() {
    if (m_regs[_Rs_].isConst()) {  // Store the address in first argument register
        const uint32_t addr = m_regs[_Rs_].val + _Imm_;
        const auto pointer = PCSX::g_emulator->m_psxMem->psxMemPointerRead(addr);

        if (pointer != nullptr && (_Rt_) != 0) {
            allocateRegWithoutLoad(_Rt_);
            m_regs[_Rt_].setWriteback(true);
            load<size, signExtend>(m_regs[_Rt_].allocatedReg, pointer);
            return;
        }

        gen.Mov(arg1, addr);
    } else {
        allocateReg(_Rs_);
        gen.moveAndAdd(arg1, m_regs[_Rs_].allocatedReg, _Imm_);
    }

    switch (size) {
        case 8:
            call(psxMemRead8Wrapper);
            break;
        case 16:
            call(psxMemRead16Wrapper);
            break;
        case 32:
            call(psxMemRead32Wrapper);
            break;
        default:
            PCSX::g_system->message("Invalid size for memory load in dynarec. Instruction %08x\n", m_psxRegs.code);
            break;
    }

    if (_Rt_) {
        allocateRegWithoutLoad(_Rt_);  // Allocate $rt after calling the read function, otherwise call() might flush it.
        m_regs[_Rt_].setWriteback(true);

        switch (size) {
            case 8:
                signExtend ? gen.Sxtb(m_regs[_Rt_].allocatedReg, w0) : gen.Uxtb(m_regs[_Rt_].allocatedReg, w0);
                break;
            case 16:
                signExtend ? gen.Sxth(m_regs[_Rt_].allocatedReg, w0) : gen.Uxth(m_regs[_Rt_].allocatedReg, w0);
                break;
            case 32:
                gen.Mov(m_regs[_Rt_].allocatedReg, w0);
                break;
        }
    }
}

// TODO: Handle all COP0 register writes properly. Don't treat read-only field as writeable!
void DynaRecCPU::recMTC0() {
    if (m_regs[_Rt_].isConst()) {
        if (_Rd_ == 13) {
            gen.Mov(w0, m_regs[_Rt_].val & ~0xFC00);
            gen.Str(w0, MemOperand(contextPointer, COP0_OFFSET(_Rd_)));
        } else if (_Rd_ != 6 && _Rd_ != 14 && _Rd_ != 15) {  // Don't write to JUMPDEST, EPC or PRID
            gen.Mov(w0, m_regs[_Rt_].val);
            gen.Str(w0, MemOperand(contextPointer, COP0_OFFSET(_Rd_)));
        }
    }

    else {
        allocateReg(_Rt_);
        if (_Rd_ == 13) {
            gen.And(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, ~0xFC00);
        } else if (_Rd_ != 6 && _Rd_ != 14 && _Rd_ != 15) {  // Don't write to JUMPDEST, EPC or PRID
            gen.Str(m_regs[_Rt_].allocatedReg,
                    MemOperand(contextPointer, COP0_OFFSET(_Rd_)));  // Write rt to the cop0 reg
        }
    }

    // Writing to SR/Cause can sometimes forcefully fire an interrupt. So we need to emit extra code to check.
    if (_Rd_ == 12 || _Rd_ == 13) {
        testSoftwareInterrupt<true>();
    }
}

// Checks if a write to SR/CAUSE forcibly triggered an interrupt
// loadSR: Shows if SR is already in eax or if it should be loaded from memory
template <bool loadSR>
void DynaRecCPU::testSoftwareInterrupt() {
    Label label;
    const auto pc = w3;  // Register to hold temporary PC values in
    const auto sr = w4;  // Register to hold SR in

    if (!m_pcWrittenBack) {
        gen.Mov(pc, m_pc);
        gen.Str(pc, MemOperand(contextPointer, PC_OFFSET));
        m_pcWrittenBack = true;
    }

    m_stopCompiling = true;

    if constexpr (loadSR) {
        gen.Ldr(sr, MemOperand(contextPointer, COP0_OFFSET(12)));  // w4 = SR
    }
    // TODO: Possibly use Tbz or similar here
    gen.Tst(sr, 1);                                              // Check if interrupts are enabled
    gen.bz(label);                                               // If not, skip to the end
    gen.Ldr(arg2, MemOperand(contextPointer, COP0_OFFSET(13)));  // arg2 = CAUSE
    gen.And(sr, sr, arg2);
    gen.Tst(sr, 0x300);  // Check if an interrupt was force-fired
    gen.bz(label);       // Skip to the end if not

    // Fire the interrupt if it was triggered
    // This object in arg1. Exception code is already in arg2 from before (will be masked by exception handler)
    loadThisPointer(arg1.X());
    gen.Mov(arg3, (int32_t)m_inDelaySlot);               // Store whether we're in a delay slot in arg3
    gen.Mov(pc, m_pc - 4);                               // PC for exception handler to use
    gen.Str(pc, MemOperand(contextPointer, PC_OFFSET));  // Store the PC
    call(psxExceptionWrapper);                           // Call the exception wrapper function

    gen.L(label);  // Execution will jump here if interrupts not enabled
}

void DynaRecCPU::recMTHI() {
    if (m_regs[_Rs_].isConst()) {
        gen.Mov(w0, m_regs[_Rs_].val);
        gen.Str(w0, MemOperand(contextPointer, HI_OFFSET));
    } else {
        allocateReg(_Rs_);
        gen.Str(m_regs[_Rs_].allocatedReg, MemOperand(contextPointer, HI_OFFSET));
    }
}

void DynaRecCPU::recMTLO() {
    if (m_regs[_Rs_].isConst()) {
        gen.Mov(w0, m_regs[_Rs_].val);
        gen.Str(w0, MemOperand(contextPointer, LO_OFFSET));
    } else {
        allocateReg(_Rs_);
        gen.Str(m_regs[_Rs_].allocatedReg, MemOperand(contextPointer, LO_OFFSET));
    }
}
// TODO: Add a static_assert that makes sure address_of_hi == address_of_lo + 4
void DynaRecCPU::recMULT() {
    if ((m_regs[_Rs_].isConst() && m_regs[_Rs_].val == 0) || (m_regs[_Rt_].isConst() && m_regs[_Rt_].val == 0)) {
        gen.Str(xzr, MemOperand(contextPointer, LO_OFFSET));  // Set both LO and HI to 0 in a single 64-bit write
        return;
    }

    if (m_regs[_Rs_].isConst()) {
        if (m_regs[_Rt_].isConst()) {
            const uint64_t result = (int64_t)(int32_t)m_regs[_Rt_].val * (int64_t)(int32_t)m_regs[_Rs_].val;
            gen.Mov(w0, (uint32_t)result);
            gen.Mov(w1, (uint32_t)(result >> 32));
            gen.Str(w0, MemOperand(contextPointer, LO_OFFSET));
            gen.Str(w1, MemOperand(contextPointer, HI_OFFSET));
        } else {
            allocateReg(_Rt_);
            gen.Sxtw(x0, m_regs[_Rt_].allocatedReg);
            gen.Mov(w1, m_regs[_Rs_].val);
            gen.Mul(x0, x0, x1);
        }
    } else {
        if (m_regs[_Rt_].isConst()) {
            allocateReg(_Rs_);
            gen.Sxtw(x0, m_regs[_Rs_].allocatedReg);
            gen.Mov(w1, m_regs[_Rt_].val);
            gen.Mul(x0, x0, x1);
        } else {
            alloc_rt_rs();
            gen.Sxtw(x0, m_regs[_Rs_].allocatedReg);
            gen.Sxtw(x1, m_regs[_Rt_].allocatedReg);
            gen.Mul(x0, x0, x1);
        }
    }
    // Write 64-bit result to lo and hi at the same time
    gen.Str(x0, MemOperand(contextPointer, LO_OFFSET));
}

// TODO: Add a static_assert that makes sure address_of_hi == address_of_lo + 4
void DynaRecCPU::recMULTU() {
    if ((m_regs[_Rs_].isConst() && m_regs[_Rs_].val == 0) || (m_regs[_Rt_].isConst() && m_regs[_Rt_].val == 0)) {
        gen.Str(xzr, MemOperand(contextPointer, LO_OFFSET));  // Set both LO and HI to 0 in a single 64-bit write
        return;
    }

    if (m_regs[_Rs_].isConst()) {
        gen.Mov(w0, m_regs[_Rs_].val);

        if (m_regs[_Rt_].isConst()) {
            gen.Mov(w1, m_regs[_Rt_].val);
            gen.Mul(x0, x0, x1);
        } else {
            allocateReg(_Rt_);
            gen.Mul(x0, x0, m_regs[_Rt_].allocatedReg.X());
        }
    } else {
        if (m_regs[_Rt_].isConst()) {
            allocateReg(_Rs_);
            gen.Mov(w0, m_regs[_Rt_].val);
            gen.Mul(x0, x0, m_regs[_Rs_].allocatedReg.X());
        } else {
            alloc_rt_rs();
            gen.Mov(w0, m_regs[_Rs_].allocatedReg);
            gen.Mul(x0, x0, m_regs[_Rt_].allocatedReg.X());
        }
    }
    gen.Lsr(x1, x0, 32);
    gen.Str(w0, MemOperand(contextPointer, LO_OFFSET));
    gen.Str(w1, MemOperand(contextPointer, HI_OFFSET));
}

void DynaRecCPU::recNOR() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        markConst(_Rd_, ~(m_regs[_Rs_].val | m_regs[_Rt_].val));
    } else if (m_regs[_Rs_].isConst()) {
        alloc_rt_wb_rd();
        gen.Orr(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
        gen.Mvn(m_regs[_Rd_].allocatedReg, m_regs[_Rd_].allocatedReg);
    } else if (m_regs[_Rt_].isConst()) {
        alloc_rs_wb_rd();
        gen.Orr(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
        gen.Mvn(m_regs[_Rd_].allocatedReg, m_regs[_Rd_].allocatedReg);
    } else {
        alloc_rt_rs_wb_rd();
        gen.Orr(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
        gen.Mvn(m_regs[_Rd_].allocatedReg, m_regs[_Rd_].allocatedReg);
    }
}

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
        gen.Orr(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
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
            gen.orImm(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, _ImmU_);
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

void DynaRecCPU::recREGIMM() {
    const bool isBGEZ = ((m_psxRegs.code >> 16) & 1) != 0;
    const bool link = ((m_psxRegs.code >> 17) & 0xF) == 8;
    const auto target = _Imm_ * 4 + m_pc;

    m_nextIsDelaySlot = true;

    if (target == m_pc + 4) {
        return;
    }

    if (m_regs[_Rs_].isConst()) {
        if (isBGEZ) {  // BGEZ
            if ((int32_t)m_regs[_Rs_].val >= 0) {
                m_pcWrittenBack = true;
                m_stopCompiling = true;
                gen.Mov(w0, target);
                gen.Str(w0, MemOperand(contextPointer, PC_OFFSET));
                m_linkedPC = target;
            }
        }

        else {  // BLTZ
            if ((int32_t)m_regs[_Rs_].val < 0) {
                m_pcWrittenBack = true;
                m_stopCompiling = true;
                gen.Mov(w0, target);
                gen.Str(w0, MemOperand(contextPointer, PC_OFFSET));
                m_linkedPC = target;
            }
        }

        if (link) {
            maybeCancelDelayedLoad(31);
            markConst(31, m_pc + 4);
        }

        return;
    }

    m_pcWrittenBack = true;
    m_stopCompiling = true;

    allocateReg(_Rs_);
    gen.Cmp(m_regs[_Rs_].allocatedReg, 0);
    gen.Mov(w0, target);    // w0 = addr if jump taken
    gen.Mov(w1, m_pc + 4);  // w1 = addr if jump not taken
    // TODO: Verify Csel below is using proper conditions for signed/unsigned
    if (isBGEZ) {
        gen.Csel(w0, w0, w1, pl);  // if $rs >= 0 unsigned compare, move the jump addr into eax
    } else {
        gen.Csel(w0, w0, w1, mi);  // if $rs < 0 signed compare, move the jump addr into eax
    }
    gen.Str(w0, MemOperand(contextPointer, PC_OFFSET));
    if (link) {
        maybeCancelDelayedLoad(31);
        markConst(31, m_pc + 4);
    }
}

void DynaRecCPU::recRFE() {
    gen.Ldr(w0, MemOperand(contextPointer, COP0_OFFSET(12)));  // w0 = COP0 status register
    gen.And(w1, w0, 0x3c);                                     // mask out the rest of the SR value
    gen.And(w0, w0, ~0xF);                                     // Clear bottom 4 bits of w0
    gen.Orr(w0, w0, Operand(w1, LSR, 2));                      // Shift bits [5:2] of SR two places to the right
                                                               // & merge the shifted bits into w0
    gen.Str(w0, MemOperand(contextPointer, COP0_OFFSET(12)));  // Write w0 back to SR
    testSoftwareInterrupt<false>();
}

void DynaRecCPU::recSB() {
    if (m_regs[_Rs_].isConst()) {
        const uint32_t addr = m_regs[_Rs_].val + _Imm_;
        const auto pointer = PCSX::g_emulator->m_psxMem->psxMemPointerWrite(addr);

        if (pointer != nullptr) {
            if (m_regs[_Rt_].isConst()) {
                store<8>(m_regs[_Rt_].val & 0xFF, pointer);
            } else {
                allocateReg(_Rt_);
                store<8>(m_regs[_Rt_].allocatedReg, pointer);
            }

            return;
        }

        if (m_regs[_Rt_].isConst()) {  // Value to write in arg2
            gen.Mov(arg2, m_regs[_Rt_].val & 0xFF);
        } else {
            allocateReg(_Rt_);
            gen.Uxtb(arg2, m_regs[_Rt_].allocatedReg);
        }

        gen.Mov(arg1, addr);  // Address to write to in arg1 TODO: Optimize
        call(psxMemWrite8Wrapper);
    }

    else {
        if (m_regs[_Rt_].isConst()) {  // Value to write in arg2
            gen.Mov(arg2, m_regs[_Rt_].val & 0xFF);
        } else {
            allocateReg(_Rt_);
            gen.Uxtb(arg2, m_regs[_Rt_].allocatedReg);
        }

        allocateReg(_Rs_);
        gen.moveAndAdd(arg1, m_regs[_Rs_].allocatedReg, _Imm_);  // Address to write to in arg1   TODO: Optimize
        call(psxMemWrite8Wrapper);
    }
}

void DynaRecCPU::recSH() {
    if (m_regs[_Rs_].isConst()) {
        const uint32_t addr = m_regs[_Rs_].val + _Imm_;
        const auto pointer = PCSX::g_emulator->m_psxMem->psxMemPointerWrite(addr);
        if (pointer != nullptr) {
            if (m_regs[_Rt_].isConst()) {
                store<16>(m_regs[_Rt_].val & 0xFFFF, pointer);
            } else {
                allocateReg(_Rt_);
                store<16>(m_regs[_Rt_].allocatedReg, pointer);
            }

            return;
        }

        else if (addr == 0x1f801070) {  // I_STAT
            gen.Mov(x0, (uint64_t)&PCSX::g_emulator->m_psxMem->g_psxH[0x1070]);
            if (m_regs[_Rt_].isConst()) {
                gen.Ldrh(w1, MemOperand(x0));
                gen.Mov(w2, m_regs[_Rt_].val & 0xFFFF);
                gen.And(w1, w1, w2);
                gen.Strh(w1, MemOperand(x0));
            } else {
                allocateReg(_Rt_);
                gen.Ldrh(w1, MemOperand(x0));
                gen.And(w1, w1, m_regs[_Rt_].allocatedReg);
                gen.Strh(w1, MemOperand(x0));
            }

            return;
        }

        else if (addr >= 0x1f801c00 && addr < 0x1f801e00) {  // SPU registers
            gen.Mov(arg1, addr);
            if (m_regs[_Rt_].isConst()) {
                gen.Mov(arg2, m_regs[_Rt_].val & 0xFFFF);
            } else {
                allocateReg(_Rt_);
                gen.Mov(arg2, m_regs[_Rt_].allocatedReg);
            }

            call(SPU_writeRegisterWrapper);
            return;
        }

        if (m_regs[_Rt_].isConst()) {  // Value to write in arg2
            gen.Mov(arg2, m_regs[_Rt_].val & 0xFFFF);
        } else {
            allocateReg(_Rt_);
            gen.Uxth(arg2, m_regs[_Rt_].allocatedReg);
        }

        gen.Mov(arg1, addr);  // Address to write to in arg1   TODO: Optimize
        call(psxMemWrite16Wrapper);
    }

    else {
        if (m_regs[_Rt_].isConst()) {  // Value to write in arg2
            gen.Mov(arg2, m_regs[_Rt_].val & 0xFFFF);
        } else {
            allocateReg(_Rt_);
            gen.Uxth(arg2, m_regs[_Rt_].allocatedReg);
        }

        allocateReg(_Rs_);
        gen.moveAndAdd(arg1, m_regs[_Rs_].allocatedReg, _Imm_);  // Address to write to in arg1   TODO: Optimize
        call(psxMemWrite16Wrapper);
    }
}

void DynaRecCPU::recSLL() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rt_].isConst()) {
        markConst(_Rd_, m_regs[_Rt_].val << _Sa_);
    } else {
        alloc_rt_wb_rd();
        gen.Lsl(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, _Sa_);
    }
}

void DynaRecCPU::recSLLV() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        markConst(_Rd_, m_regs[_Rt_].val << (m_regs[_Rs_].val & 0x1F));
    } else if (m_regs[_Rs_].isConst()) {
        if (_Rt_ == _Rd_) {
            allocateReg(_Rd_);
            m_regs[_Rd_].setWriteback(true);
            gen.Lsl(m_regs[_Rd_].allocatedReg, m_regs[_Rd_].allocatedReg, m_regs[_Rs_].val & 0x1F);
        } else {
            alloc_rt_wb_rd();
            gen.Lsl(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val & 0x1F);
        }
    } else if (m_regs[_Rt_].isConst()) {
        alloc_rs_wb_rd();
        gen.Mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].val);
        gen.Lsl(m_regs[_Rd_].allocatedReg, m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
    } else {
        alloc_rt_rs_wb_rd();
        gen.Lsl(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
    }
}

void DynaRecCPU::recSLT() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        markConst(_Rd_, (int32_t)m_regs[_Rs_].val < (int32_t)m_regs[_Rt_].val);
    } else if (m_regs[_Rs_].isConst()) {
        alloc_rt_wb_rd();
        gen.Cmp(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
        gen.Cset(m_regs[_Rd_].allocatedReg, gt);
    } else if (m_regs[_Rt_].isConst()) {
        alloc_rs_wb_rd();
        gen.Cmp(m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
        gen.Cset(m_regs[_Rd_].allocatedReg, lt);
    } else {
        alloc_rt_rs_wb_rd();
        gen.Cmp(m_regs[_Rs_].allocatedReg, m_regs[_Rt_].allocatedReg);
        gen.Cset(m_regs[_Rd_].allocatedReg, lt);
    }
}

void DynaRecCPU::recSLTI() {
    BAILZERO(_Rt_);
    maybeCancelDelayedLoad(_Rt_);

    if (m_regs[_Rs_].isConst()) {
        markConst(_Rt_, (int32_t)m_regs[_Rs_].val < _Imm_);
    } else {
        alloc_rs_wb_rt();
        gen.Cmp(m_regs[_Rs_].allocatedReg, _Imm_);
        gen.Cset(m_regs[_Rt_].allocatedReg, lt);
    }
}

void DynaRecCPU::recSLTIU() {
    BAILZERO(_Rt_);
    maybeCancelDelayedLoad(_Rt_);

    if (m_regs[_Rs_].isConst()) {
        markConst(_Rt_, m_regs[_Rs_].val < (uint32_t)_Imm_);
    } else {
        alloc_rs_wb_rt();
        gen.Cmp(m_regs[_Rs_].allocatedReg, _Imm_);
        gen.Cset(m_regs[_Rt_].allocatedReg, cc);
    }
}

void DynaRecCPU::recSLTU() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        markConst(_Rd_, m_regs[_Rs_].val < m_regs[_Rt_].val);
    } else if (m_regs[_Rs_].isConst()) {
        alloc_rt_wb_rd();
        gen.Cmp(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
        gen.Cset(m_regs[_Rd_].allocatedReg, hi);
    } else if (m_regs[_Rt_].isConst()) {
        alloc_rs_wb_rd();
        gen.Cmp(m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
        gen.Cset(m_regs[_Rd_].allocatedReg, lo);
    } else {
        alloc_rt_rs_wb_rd();
        gen.Cmp(m_regs[_Rs_].allocatedReg, m_regs[_Rt_].allocatedReg);
        gen.Cset(m_regs[_Rd_].allocatedReg, lo);
    }
}

void DynaRecCPU::recSRA() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rt_].isConst()) {
        markConst(_Rd_, (int32_t)m_regs[_Rt_].val >> _Sa_);
    } else {
        alloc_rt_wb_rd();
        gen.Asr(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, _Sa_);
    }
}

void DynaRecCPU::recSRAV() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        markConst(_Rd_, (int32_t)m_regs[_Rt_].val >> (m_regs[_Rs_].val & 0x1F));
    } else if (m_regs[_Rs_].isConst()) {
        alloc_rt_wb_rd();
        gen.Asr(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val & 0x1F);
    } else if (m_regs[_Rt_].isConst()) {
        alloc_rs_wb_rd();
        gen.Mov(w0, m_regs[_Rt_].val);
        gen.Asr(m_regs[_Rd_].allocatedReg, w0, m_regs[_Rs_].allocatedReg);
    } else {
        alloc_rt_rs_wb_rd();
        gen.Asr(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
    }
}

void DynaRecCPU::recSRL() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rt_].isConst()) {
        markConst(_Rd_, m_regs[_Rt_].val >> _Sa_);
    } else {
        alloc_rt_wb_rd();
        gen.Lsr(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, _Sa_);
    }
}

void DynaRecCPU::recSRLV() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        markConst(_Rd_, m_regs[_Rt_].val >> (m_regs[_Rs_].val & 0x1F));
    } else if (m_regs[_Rs_].isConst()) {
        if (_Rt_ == _Rd_) {
            allocateReg(_Rd_);
            m_regs[_Rd_].setWriteback(true);
            gen.Lsr(m_regs[_Rd_].allocatedReg, m_regs[_Rd_].allocatedReg, m_regs[_Rs_].val & 0x1F);
        } else {
            alloc_rt_wb_rd();
            gen.Lsr(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val & 0x1F);
        }
    } else if (m_regs[_Rt_].isConst()) {
        alloc_rs_wb_rd();
        gen.Mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].val);
        gen.Lsr(m_regs[_Rd_].allocatedReg, m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
    } else {
        alloc_rt_rs_wb_rd();
        gen.Lsr(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
    }
}

void DynaRecCPU::recSUB() { recSUBU(); }

void DynaRecCPU::recSUBU() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        markConst(_Rd_, m_regs[_Rs_].val - m_regs[_Rt_].val);
    } else if (m_regs[_Rs_].isConst()) {
        alloc_rt_wb_rd();
        gen.reverseSub(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
    } else if (m_regs[_Rt_].isConst()) {
        alloc_rs_wb_rd();
        gen.Sub(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
    } else {
        alloc_rt_rs_wb_rd();
        gen.Sub(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg, m_regs[_Rt_].allocatedReg);
    }
}

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

void DynaRecCPU::recSWL() {
    // The mask to be applied to $rt (top 32 bits) and the shift to be applied to the read memory value (low 32 bits)
    // Depending on the low 3 bits of the unaligned address
    static const uint64_t MASKS_AND_SHIFTS[4] = {0xFFFFFF0000000018, 0xFFFF000000000010, 0xFF00000000000008, 0};

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {  // Both previous register value and address are constant
        const uint32_t address = m_regs[_Rs_].val + _Imm_;
        const uint32_t alignedAddress = address & ~3;
        const uint32_t mask = SWL_MASK[address & 3];
        const auto shift = SWL_SHIFT[address & 3];

        gen.Mov(arg1, alignedAddress);  // Address in arg1 (w0)
        call(psxMemRead32Wrapper);
        gen.andImm(arg2, w0, mask);  // Mask read value
        gen.Mov(w2, m_regs[_Rt_].val >> shift);
        gen.Orr(arg2, arg2, w2);  // Shift $rt and or with read value

        gen.Mov(arg1, alignedAddress);  // Address in arg2 again
        call(psxMemWrite32Wrapper);
    } else if (m_regs[_Rs_].isConst()) {  // Only address is constant
        const uint32_t address = m_regs[_Rs_].val + _Imm_;
        const uint32_t alignedAddress = address & ~3;
        const uint32_t mask = SWL_MASK[address & 3];
        const auto shift = SWL_SHIFT[address & 3];

        gen.Mov(arg1, alignedAddress);  // Address in arg1 (w0)
        call(psxMemRead32Wrapper);
        gen.andImm(w2, w0, mask);  // Mask read value

        allocateReg(_Rt_);                                       // Allocate $rt
        gen.Mov(arg2, m_regs[_Rt_].allocatedReg);                // Move rt to arg2
        gen.Lsr(arg2, arg2, shift);                              // Shift rt value
        gen.Orr(arg2, arg2, w0);                                 // Or with read value
        gen.Mov(arg1, alignedAddress);                           // Aligned address in arg1 again
        call(psxMemWrite32Wrapper);                              // Write back
    } else if (m_regs[_Rt_].isConst()) {                         // Only previous rt value is constant
        allocateReg(_Rs_);                                       // Allocate address reg
        gen.moveAndAdd(arg1, m_regs[_Rs_].allocatedReg, _Imm_);  // Address in arg1
        gen.And(arg1, arg1, ~3);                                 // Force align it
        call(psxMemRead32Wrapper);                               // Read from the aligned address, result in w0

        // The call might have flushed $rs, so we need to allocate it again, and also allocate $rt
        allocateReg(_Rs_);
        gen.moveAndAdd(w2, m_regs[_Rs_].allocatedReg, _Imm_);  // Address in w2 again

        gen.And(w5, w2, ~3);  // Align address

        gen.And(w2, w2, 3);                         // edx = low 2 bits of address
        gen.Mov(x3, (uintptr_t)&MASKS_AND_SHIFTS);  // Base to mask and shift lookup table in x3
        gen.Ldr(x3, MemOperand(x3, x2, LSL, 3));    // Load the mask and shift from LUT by indexing using the bottom 2
                                                  // bits of the unaligned addr.
        gen.Mov(arg2, m_regs[_Rt_].val);  // arg2 = $rt
        gen.Lsr(x4, x3, 32);              // x4 = mask now
        gen.Lsr(arg2, arg2, w3);          // Shift rt value
        gen.And(w0, w0, w4);              // Mask read value
        gen.Orr(arg2, arg2, w0);
        gen.Mov(arg1, w5);
        call(psxMemWrite32Wrapper);
    } else {                                                     // Nothing is constant
        allocateReg(_Rs_);                                       // Allocate address reg
        gen.moveAndAdd(arg1, m_regs[_Rs_].allocatedReg, _Imm_);  // Address in arg1
        gen.And(arg1, arg1, ~3);                                 // Force align it
        call(psxMemRead32Wrapper);                               // Read from the aligned address, result in w0

        // The call might have flushed $rs, so we need to allocate it again, and also allocate $rt
        alloc_rt_rs();
        gen.moveAndAdd(w2, m_regs[_Rs_].allocatedReg, _Imm_);  // Address in w2 again

        gen.And(w5, w2, ~3);  // Align address

        gen.And(w2, w2, 3);                         // edx = low 2 bits of address
        gen.Mov(x3, (uintptr_t)&MASKS_AND_SHIFTS);  // Base to mask and shift lookup table in x3
        gen.Ldr(x3, MemOperand(x3, x2, LSL, 3));    // Load the mask and shift from LUT by indexing using the bottom 2
                                                  // bits of the unaligned addr.

        gen.Mov(arg2, m_regs[_Rt_].allocatedReg);  // arg2 = $rt
        gen.Lsr(x4, x3, 32);                       // x4 = mask now
        gen.Lsr(arg2, arg2, w3);                   // Shift rt value
        gen.And(w0, w0, w4);                       // Mask read value
        gen.Orr(arg2, arg2, w0);
        gen.Mov(arg1, w5);
        call(psxMemWrite32Wrapper);
    }
}

void DynaRecCPU::recSWR() {
    // The mask to be applied to $rt (top 32 bits) and the shift to be applied to the read memory value (low 32 bits)
    // Depending on the low 3 bits of the unaligned address
    static const uint64_t MASKS_AND_SHIFTS[4] = {0, 0x000000FF00000008, 0x0000FFFF00000010, 0x00FFFFFF00000018};

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {  // Both previous register value and address are constant
        const uint32_t address = m_regs[_Rs_].val + _Imm_;
        const uint32_t alignedAddress = address & ~3;
        const uint32_t mask = SWR_MASK[address & 3];
        const auto shift = SWR_SHIFT[address & 3];

        gen.Mov(arg1, alignedAddress);  // Address in arg1 (w0)
        call(psxMemRead32Wrapper);
        gen.andImm(arg2, w0, mask);  // Mask read value
        gen.Mov(w2, m_regs[_Rt_].val << shift);
        gen.Orr(arg2, arg2, w2);  // Shift $rt and or with read value

        gen.Mov(arg1, alignedAddress);  // Address in arg2 again
        call(psxMemWrite32Wrapper);
    } else if (m_regs[_Rs_].isConst()) {  // Only address is constant
        const uint32_t address = m_regs[_Rs_].val + _Imm_;
        const uint32_t alignedAddress = address & ~3;
        const uint32_t mask = SWR_MASK[address & 3];
        const auto shift = SWR_SHIFT[address & 3];

        gen.Mov(arg1, alignedAddress);  // Address in arg1 (w0)
        call(psxMemRead32Wrapper);
        gen.andImm(w2, w0, mask);  // Mask read value

        allocateReg(_Rt_);                                       // Allocate $rt
        gen.Mov(arg2, m_regs[_Rt_].allocatedReg);                // Move rt to arg2
        gen.Lsl(arg2, arg2, shift);                              // Shift rt value
        gen.Orr(arg2, arg2, w0);                                 // Or with read value
        gen.Mov(arg1, alignedAddress);                           // Aligned address in arg1 again
        call(psxMemWrite32Wrapper);                              // Write back
    } else if (m_regs[_Rt_].isConst()) {                         // Only previous rt value is constant
        allocateReg(_Rs_);                                       // Allocate address reg
        gen.moveAndAdd(arg1, m_regs[_Rs_].allocatedReg, _Imm_);  // Address in arg1
        gen.And(arg1, arg1, ~3);                                 // Force align it
        call(psxMemRead32Wrapper);                               // Read from the aligned address, result in w0

        // The call might have flushed $rs, so we need to allocate it again, and also allocate $rt
        allocateReg(_Rs_);
        gen.moveAndAdd(w2, m_regs[_Rs_].allocatedReg, _Imm_);  // Address in w2 again

        gen.And(w5, w2, ~3);  // Align address

        gen.And(w2, w2, 3);                         // w2 = low 2 bits of address
        gen.Mov(x3, (uintptr_t)&MASKS_AND_SHIFTS);  // Base to mask and shift lookup table in x3
        gen.Ldr(x3, MemOperand(x3, x2, LSL, 3));    // Load the mask and shift from LUT by indexing using the bottom 2
                                                  // bits of the unaligned addr.

        gen.Mov(arg2, m_regs[_Rt_].val);  // arg2 = $rt
        gen.Lsr(x4, x3, 32);              // x4 = mask now
        gen.Lsl(arg2, arg2, w3);          // Shift rt value
        gen.And(w0, w0, w4);              // Mask read value
        gen.Orr(arg2, arg2, w0);
        gen.Mov(arg1, w5);
        call(psxMemWrite32Wrapper);
    } else {                                                     // Nothing is constant
        allocateReg(_Rs_);                                       // Allocate address reg
        gen.moveAndAdd(arg1, m_regs[_Rs_].allocatedReg, _Imm_);  // Address in arg1
        gen.And(arg1, arg1, ~3);                                 // Force align it
        call(psxMemRead32Wrapper);                               // Read from the aligned address, result in w0

        // The call might have flushed $rs, so we need to allocate it again, and also allocate $rt
        alloc_rt_rs();
        gen.moveAndAdd(w2, m_regs[_Rs_].allocatedReg, _Imm_);  // Address in w2 again

        gen.And(w5, w2, ~3);  // Align address

        gen.And(w2, w2, 3);                         // w2 = low 2 bits of address
        gen.Mov(x3, (uintptr_t)&MASKS_AND_SHIFTS);  // Base to mask and shift lookup table in x3
        gen.Ldr(x3, MemOperand(x3, x2, LSL, 3));    // Load the mask and shift from LUT by indexing using the bottom 2
                                                  // bits of the unaligned addr.

        gen.Mov(arg2, m_regs[_Rt_].allocatedReg);  // arg2 = $rt
        gen.Lsr(x4, x3, 32);                       // x4 = mask now
        gen.Lsl(arg2, arg2, w3);                   // Shift rt value
        gen.And(w0, w0, w4);                       // Mask read value
        gen.Orr(arg2, arg2, w0);                   // Or with read value
        gen.Mov(arg1, w5);
        call(psxMemWrite32Wrapper);
    }
}

void DynaRecCPU::recSYSCALL() { recException(Exception::Syscall); }

void DynaRecCPU::recXOR() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        markConst(_Rd_, m_regs[_Rs_].val ^ m_regs[_Rt_].val);
    } else if (m_regs[_Rs_].isConst()) {
        alloc_rt_wb_rd();
        gen.Eor(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
    } else if (m_regs[_Rt_].isConst()) {
        alloc_rs_wb_rd();
        gen.Eor(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
    } else {
        alloc_rt_rs_wb_rd();
        gen.Eor(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
    }
}

void DynaRecCPU::recXORI() {
    BAILZERO(_Rt_);
    maybeCancelDelayedLoad(_Rt_);

    if (_Rs_ == _Rt_) {
        if (m_regs[_Rs_].isConst()) {
            m_regs[_Rt_].val ^= _ImmU_;
        } else {
            allocateReg(_Rt_);
            m_regs[_Rt_].setWriteback(true);
            gen.Eor(m_regs[_Rt_].allocatedReg, m_regs[_Rt_].allocatedReg, _ImmU_);
        }
    } else {
        if (m_regs[_Rs_].isConst()) {
            markConst(_Rt_, m_regs[_Rs_].val ^ _ImmU_);
        } else {
            alloc_rs_wb_rt();
            gen.Eor(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg, _ImmU_);
        }
    }
}

void DynaRecCPU::recException(Exception e) {
    m_pcWrittenBack = true;
    m_stopCompiling = true;

    loadThisPointer(arg1.X());                                                  // Pointer to this object in arg1
    gen.Mov(arg2, static_cast<std::underlying_type<Exception>::type>(e) << 2);  // Exception type in arg2
    gen.Mov(arg3, (int32_t)m_inDelaySlot);  // Store whether we're in a delay slot in arg3
    gen.Mov(w3, m_pc - 4);
    gen.Str(w3, MemOperand(contextPointer, PC_OFFSET));  // PC for exception handler to use

    call(psxExceptionWrapper);  // Call the exception wrapper
}

void DynaRecCPU::recBREAK() {
    flushRegs();  // For PCDRV support, we need to flush all registers before handling the exception.
    recException(Exception::Break);
}

#undef BAILZERO
#endif  // DYNAREC_AA64
