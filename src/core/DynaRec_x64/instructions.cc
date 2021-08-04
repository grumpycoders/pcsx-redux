#include "recompiler.h"
#if defined(DYNAREC_X86_64)
#define BAILZERO(x) if (!(x)) { return; }

void DynaRecCPU::recUnknown() {
    dumpBuffer();
    fmt::print("Unknown instruction for dynarec - address {:08X}, instruction {:08X}\n", m_pc, m_psxRegs.code);
    abort();
    PCSX::g_system->message("Unknown instruction for dynarec - address %08x, instruction %08x\n", m_pc, m_psxRegs.code);
    error();
}

void DynaRecCPU::recLUI() {
    BAILZERO(_Rt_);

    maybeCancelDelayedLoad(_Rt_);
    m_regs[_Rt_].markConst(m_psxRegs.code << 16);
}

void DynaRecCPU::recADDU() {
    // Rd = Rs + Rt
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].markConst(m_regs[_Rs_].val + m_regs[_Rt_].val);
    } else if (m_regs[_Rs_].isConst()) {
        allocateReg(_Rd_, _Rt_);
        m_regs[_Rd_].setWriteback(true);

        if (_Rt_ == _Rd_) {
            switch (m_regs[_Rs_].val) {
                case 1:
                    gen.inc(m_regs[_Rd_].allocatedReg);
                    break;
                case -1:
                    gen.dec(m_regs[_Rd_].allocatedReg);
                    break;
                default:
                    gen.add(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].val);
            }
        } else {
            gen.lea(m_regs[_Rd_].allocatedReg, dword[m_regs[_Rt_].allocatedReg + m_regs[_Rs_].val]);
        }
    } else if (m_regs[_Rt_].isConst()) {
        allocateReg(_Rd_, _Rs_);
        m_regs[_Rd_].setWriteback(true);

        if (_Rs_ == _Rd_) {
            switch (m_regs[_Rt_].val) {
                case 1:
                    gen.inc(m_regs[_Rd_].allocatedReg);
                    break;
                case -1:
                    gen.dec(m_regs[_Rd_].allocatedReg);
                    break;
                default:
                    gen.add(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].val);
            }
        } else {
            gen.lea(m_regs[_Rd_].allocatedReg, dword[m_regs[_Rs_].allocatedReg + m_regs[_Rt_].val]);
        }
    } else {
        allocateReg(_Rd_, _Rs_, _Rt_);
        m_regs[_Rd_].setWriteback(true);

        if (_Rs_ == _Rd_) {  // Rd+= Rt
            gen.add(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        } else if (_Rt_ == _Rd_) {  // Rd+= Rs
            gen.add(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
        } else {  // Rd = Rs + Rt
            gen.lea(m_regs[_Rd_].allocatedReg, dword[m_regs[_Rs_].allocatedReg + m_regs[_Rt_].allocatedReg]);
        }
    }
}

void DynaRecCPU::recADDIU() {
    // Rt = Rs + Im
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
                    gen.inc(m_regs[_Rt_].allocatedReg);
                    break;
                case -1:
                    gen.dec(m_regs[_Rt_].allocatedReg);
                    break;
                default:
                    gen.add(m_regs[_Rt_].allocatedReg, _Imm_);
                    break;
            }
        }
    } else {
        if (m_regs[_Rs_].isConst()) {
            m_regs[_Rt_].markConst(m_regs[_Rs_].val + _Imm_);
        } else {
            allocateReg(_Rt_, _Rs_);
            m_regs[_Rt_].setWriteback(true);

            gen.lea(m_regs[_Rt_].allocatedReg, dword[m_regs[_Rs_].allocatedReg + _Imm_]);
        }
    }
}

void DynaRecCPU::recSLTU() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].markConst(m_regs[_Rs_].val < m_regs[_Rt_].val);
    } else if (m_regs[_Rs_].isConst()) {
        allocateReg(_Rd_, _Rt_);
        m_regs[_Rd_].setWriteback(true);

        gen.xor_(eax, eax);
        gen.cmp(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
        gen.setge(al);
        gen.mov(m_regs[_Rd_].allocatedReg, eax);
    } else if (m_regs[_Rt_].isConst()) {
        allocateReg(_Rd_, _Rs_);
        m_regs[_Rd_].setWriteback(true);

        gen.xor_(eax, eax);
        gen.cmp(m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
        gen.setl(al);
        gen.mov(m_regs[_Rd_].allocatedReg, eax);
    } else {
        allocateReg(_Rd_, _Rs_, _Rt_);
        m_regs[_Rd_].setWriteback(true);

        gen.xor_(eax, eax);
        gen.cmp(m_regs[_Rs_].allocatedReg, m_regs[_Rt_].allocatedReg);
        gen.setl(al);
        gen.mov(m_regs[_Rd_].allocatedReg, eax);
    }
}

void DynaRecCPU::recANDI() {
    BAILZERO(_Rt_);
    maybeCancelDelayedLoad(_Rt_);

    if (_Rs_ == _Rt_) {
        if (m_regs[_Rs_].isConst()) {
            m_regs[_Rt_].val &= _ImmU_;
        } else {
            m_regs[_Rt_].setWriteback(true);
            allocateReg(_Rt_);
            gen.and_(m_regs[_Rt_].allocatedReg, _ImmU_);
        }
    } else {
        if (m_regs[_Rs_].isConst()) {
            m_regs[_Rt_].markConst(m_regs[_Rs_].val & _ImmU_);
        } else {
            m_regs[_Rt_].setWriteback(true);
            allocateReg(_Rt_, _Rs_);
            gen.mov(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
            if (_ImmU_) {
                gen.and_(m_regs[_Rt_].allocatedReg, _ImmU_);
            }
        }
    }
}

void DynaRecCPU::recOR() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].markConst(m_regs[_Rs_].val | m_regs[_Rt_].val);
    } else if (m_regs[_Rs_].isConst()) {
        allocateReg(_Rt_, _Rd_);
        m_regs[_Rd_].setWriteback(true);

        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].val);
        gen.or_(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
    } else if (m_regs[_Rt_].isConst()) {
        allocateReg(_Rs_, _Rd_);
        m_regs[_Rd_].setWriteback(true);

        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].val);
        gen.or_(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
    } else {
        allocateReg(_Rs_, _Rd_, _Rt_);
        m_regs[_Rd_].setWriteback(true);

        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        gen.or_(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
    }
}

void DynaRecCPU::recORI() {
    BAILZERO(_Rt_);
    maybeCancelDelayedLoad(_Rt_);

    if (_Rs_ == _Rt_) {
        if (m_regs[_Rs_].isConst()) {
            m_regs[_Rt_].val |= _ImmU_;
        } else {
            m_regs[_Rt_].setWriteback(true);
            allocateReg(_Rt_);
            gen.or_(m_regs[_Rt_].allocatedReg, _ImmU_);
        }
    } else {
        if (m_regs[_Rs_].isConst()) {
            m_regs[_Rt_].markConst(m_regs[_Rs_].val | _ImmU_);
        } else {
            m_regs[_Rt_].setWriteback(true);
            allocateReg(_Rt_, _Rs_);
            gen.mov(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
            if (_ImmU_) {
                gen.or_(m_regs[_Rt_].allocatedReg, _ImmU_);
            }
        }
    }
}

void DynaRecCPU::recSLL() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].markConst(m_regs[_Rt_].val << _Sa_);
    } else {
        allocateReg(_Rt_, _Rd_);
        m_regs[_Rd_].setWriteback(true);

        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        if (_Sa_) {
            gen.shl(m_regs[_Rd_].allocatedReg, _Sa_);
        }
    }
}

void DynaRecCPU::recSRL() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].markConst(m_regs[_Rt_].val >> _Sa_);
    } else {
        allocateReg(_Rt_, _Rd_);
        m_regs[_Rd_].setWriteback(true);

        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        if (_Sa_) {
            gen.shr(m_regs[_Rd_].allocatedReg, _Sa_);
        }
    }
}

void DynaRecCPU::recLB() {
    if (_Rt_) {
        allocateReg(_Rt_);
        m_regs[_Rt_].setWriteback(true);
    }

    if (m_regs[_Rs_].isConst()) {
        const uint32_t addr = m_regs[_Rs_].val + _Imm_;
        gen.mov(arg1, addr);
    } else {
        allocateReg(_Rs_);
        gen.mov(arg2, m_regs[_Rs_].allocatedReg);
    }

    prepareForCall();
    gen.callFunc(psxMemRead8Wrapper);

    if (_Rt_) {
        gen.movsx(m_regs[_Rt_].allocatedReg, al);
    }
}

void DynaRecCPU::recLBU() {
    if (_Rt_) {
        allocateReg(_Rt_);
        m_regs[_Rt_].setWriteback(true);
    }

    if (m_regs[_Rs_].isConst()) {
        const uint32_t addr = m_regs[_Rs_].val + _Imm_;
        gen.mov(arg1, addr);
    } else {
        allocateReg(_Rs_);
        gen.mov(arg2, m_regs[_Rs_].allocatedReg);
    }

    prepareForCall();
    gen.callFunc(psxMemRead8Wrapper);

    if (_Rt_) {
        gen.movzx(m_regs[_Rt_].allocatedReg, al);
    }
}

void DynaRecCPU::recLW() {
    if (_Rt_) {
        allocateReg(_Rt_);
        m_regs[_Rt_].setWriteback(true);
    }

    if (m_regs[_Rs_].isConst()) {
        const uint32_t addr = m_regs[_Rs_].val + _Imm_;
        gen.mov(arg1, addr);
    } else {
        allocateReg(_Rs_);
        gen.mov(arg2, m_regs[_Rs_].allocatedReg);
    }

    prepareForCall();
    gen.callFunc(psxMemRead32Wrapper);

    if (_Rt_) {
        gen.mov(m_regs[_Rt_].allocatedReg, eax);
    }
}

void DynaRecCPU::recSW() {
    // Hack: The only place where cache isolation should be enabled is the BIOS' flushcache
    // So in that case we don't even compile SWs. This shouldn't break except perhaps with unofficial BIOSes
    if (m_psxRegs.CP0.n.Status & 0x10000) {
        return;
    }

    if (m_regs[_Rs_].isConst()) {
        const uint32_t addr = m_regs[_Rs_].val + _Imm_;
        const auto pointer = PCSX::g_emulator->m_psxMem->psxMemPointer(addr);
        if (pointer != nullptr) {
            gen.mov(rax, (uintptr_t) pointer);
            if (m_regs[_Rt_].isConst()) {
                gen.mov(dword[rax], m_regs[_Rt_].val);
            } else {
                allocateReg(_Rt_);
                gen.mov(dword[rax], m_regs[_Rt_].allocatedReg);
            }

            return;
        }

        if (m_regs[_Rt_].isConst()) { // Value to write in arg2
            gen.mov(arg2, m_regs[_Rt_].val);
        } else {
            allocateReg(_Rt_);
            gen.mov(arg2, m_regs[_Rt_].allocatedReg);
        }

        gen.mov(arg1, addr); // Address to write to in arg1   TODO: Optimize
        prepareForCall();
        gen.callFunc(psxMemWrite32Wrapper);
    }

    else {
        if (m_regs[_Rt_].isConst()) {  // Value to write in arg2
            gen.mov(arg2, m_regs[_Rt_].val);
        } else {
            allocateReg(_Rt_);
            gen.mov(arg2, m_regs[_Rt_].allocatedReg);
        }

        allocateReg(_Rs_);
        gen.mov(arg1, m_regs[_Rs_].allocatedReg);  // Address to write to in arg1   TODO: Optimize
        prepareForCall();
        gen.callFunc(psxMemWrite32Wrapper);
    }
}

void DynaRecCPU::recCOP0() {
    switch (_Rs_) {  // figure out the type of COP0 opcode
        case 4:
            recMTC0();
            break;
        default:
            fmt::print("Unimplemented cop0 op {}\n", _Rs_);
            abort();
            break;
    }
}

// TODO: Handle all COP0 register writes properly. Don't treat read-only field as writeable!
void DynaRecCPU::recMTC0() {
    if (m_regs[_Rt_].isConst()) {
        if (_Rd_ == 13) {
            gen.mov(dword[contextPointer + COP0_OFFSET(_Rd_)], m_regs[_Rt_].val & ~0xFC00);
        } else if (_Rd_ != 6 && _Rd_ != 14 &&_Rd_ != 15) { // Don't write to JUMPDEST, EPC or PRID
            gen.mov(dword[contextPointer + COP0_OFFSET(_Rd_)], m_regs[_Rt_].val);
        }
    }

    else {
        allocateReg(_Rt_);
        if (_Rd_ == 13) {
            gen.and_(m_regs[_Rt_].allocatedReg, ~0xFC00);
        }

        gen.mov(dword[contextPointer + COP0_OFFSET(_Rd_)], m_regs[_Rt_].allocatedReg); // Write rt to the cop0 reg
    }

    // Writing to SR/Cause can sometimes forcefully fire an interrupt. So we need to emit extra code to check.
    if (_Rd_ == 12 || _Rd_ == 13) {
        testSoftwareInterrupt();
    }
}

void DynaRecCPU::testSoftwareInterrupt() { 
    Label label;
    if (!m_pcWrittenBack) {
        gen.mov(dword[contextPointer + PC_OFFSET], m_pc);
        m_pcWrittenBack = true;
    }

    m_stopCompiling = true;
    prepareForCall();

    gen.mov(eax, dword[contextPointer + COP0_OFFSET(12)]); // eax = SR
    gen.test(eax, 1);                                      // Check if interrupts are enabled
    gen.jz(label, CodeGenerator::LabelType::T_NEAR);       // If not, skip to the end

    gen.mov(arg2, dword[contextPointer + COP0_OFFSET(13)]); // arg2 = CAUSE
    gen.and_(eax, arg2);
    gen.and_(eax, 0x300);                             // Check if an interrupt was force-fired
    gen.jz(label, CodeGenerator::LabelType::T_NEAR);  // Skip to the end if not

    // Fire the interrupt if it was triggered
    // This object in arg1. Exception code is already in arg2 from before (will be masked by exception handler)
    gen.lea(arg1.cvt64(), qword[contextPointer - ((uintptr_t) &m_psxRegs - (uintptr_t)this)]);
    gen.mov(arg3, (int32_t) m_inDelaySlot); // Store whether we're in a delay slot in arg3
    gen.mov(dword[contextPointer + PC_OFFSET], m_pc - 4); // PC for exception handler to use
    gen.callFunc(psxExceptionWrapper); // Call the exception wrapper function

    gen.L(label);
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
            gen.mov(dword[contextPointer + PC_OFFSET], target);
        }
        return;
    } else if (m_regs[_Rs_].isConst()) {
        allocateReg(_Rt_);
        gen.cmp(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
    } else if (m_regs[_Rt_].isConst()) {
        allocateReg(_Rs_);
        gen.cmp(m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
    } else {
        allocateReg(_Rt_, _Rs_);
        gen.cmp(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
    }

    m_pcWrittenBack = true;
    m_stopCompiling = true;

    gen.mov(ecx, target);    // ecx = addr if jump taken
    gen.mov(eax, m_pc + 4);  // eax = addr if jump not taken
    gen.cmovne(eax, ecx);    // if not equal, move the jump addr into eax
    gen.mov(dword[contextPointer + PC_OFFSET], eax);
}

void DynaRecCPU::recJ() {
    const uint32_t target = _Target_ * 4 + (m_pc & 0xf0000000);
    m_nextIsDelaySlot = true;
    m_stopCompiling = true;
    m_pcWrittenBack = true;

    gen.mov(dword[contextPointer + PC_OFFSET], target);  // Write PC
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
            gen.mov(dword[contextPointer + PC_OFFSET], target);
        }
        return;
    } else if (m_regs[_Rs_].isConst()) {
        allocateReg(_Rt_);
        gen.cmp(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
    } else if (m_regs[_Rt_].isConst()) {
        allocateReg(_Rs_);
        gen.cmp(m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
    } else {
        allocateReg(_Rt_, _Rs_);
        gen.cmp(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
    }

    m_pcWrittenBack = true;
    m_stopCompiling = true;

    gen.mov(ecx, target);   // ecx = addr if jump taken
    gen.mov(eax, m_pc + 4); // eax = addr if jump not taken
    gen.cmove(eax, ecx);    // if not equal, move the jump addr into eax
    gen.mov(dword[contextPointer + PC_OFFSET], eax);
}

void DynaRecCPU::recBGTZ() {
    uint32_t target = _Imm_ * 4 + m_pc;

    m_nextIsDelaySlot = true;
    if (target == m_pc + 4) {
        return;
    }

    if (m_regs[_Rs_].isConst()) {
        if ((int32_t) m_regs[_Rs_].val > 0) {
            m_pcWrittenBack = true;
            m_stopCompiling = true;
            gen.mov(dword[contextPointer + PC_OFFSET], target);
        }
        return;
    }

    m_pcWrittenBack = true;
    m_stopCompiling = true;

    if (m_regs[_Rs_].isAllocated) { // Don't bother allocating Rs unless it's already allocated
        gen.test(m_regs[_Rs_].allocatedReg, m_regs[_Rs_].allocatedReg);
    } else {
        gen.cmp(dword[contextPointer + GPR_OFFSET(_Rs_)], 0);
    }

    gen.mov(eax, target);   // eax = addr if jump taken
    gen.mov(ecx, m_pc + 4); // ecx = addr if jump not taken
    gen.cmovg(eax, ecx);    // if taken, move the jump addr into eax
    gen.mov(dword[contextPointer + PC_OFFSET], eax);
}

#endif DYNAREC_X86_64
