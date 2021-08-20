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

// The Dynarec doesn't currently handle overflow exceptions, so we treat ADD the same as ADDU
void DynaRecCPU::recADD() { 
    recADDU();
}

void DynaRecCPU::recADDU() {
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

void DynaRecCPU::recSUBU() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].markConst(m_regs[_Rs_].val - m_regs[_Rt_].val);
    } else if (m_regs[_Rs_].isConst()) {
        allocateReg(_Rd_, _Rt_);
        m_regs[_Rd_].setWriteback(true);

        gen.mov(eax, m_regs[_Rs_].val); // Left hand operand in eax
        gen.sub(eax, m_regs[_Rt_].allocatedReg); // Subtract right hand operand
        gen.mov(m_regs[_Rd_].allocatedReg, eax); // Store result
    } else if (m_regs[_Rt_].isConst()) {
        allocateReg(_Rd_, _Rs_);
        m_regs[_Rd_].setWriteback(true);

        if (_Rs_ == _Rd_) {
            switch (m_regs[_Rt_].val) {
                case 1:
                    gen.dec(m_regs[_Rd_].allocatedReg);
                    break;
                case -1:
                    gen.inc(m_regs[_Rd_].allocatedReg);
                    break;
                default:
                    gen.sub(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].val);
            }
        } else {
            gen.lea(m_regs[_Rd_].allocatedReg, dword[m_regs[_Rs_].allocatedReg - m_regs[_Rt_].val]);
        }
    } else {
        allocateReg(_Rd_, _Rs_, _Rt_);
        m_regs[_Rd_].setWriteback(true);

        if (_Rs_ == _Rd_) {  // Rd -= Rt
            gen.sub(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        } else {
            gen.mov(eax, m_regs[_Rs_].allocatedReg);
            gen.sub(eax, m_regs[_Rt_].allocatedReg);
            gen.mov(m_regs[_Rd_].allocatedReg, eax);
        }
    }
}

void DynaRecCPU::recSLTI() {
    BAILZERO(_Rt_);
    maybeCancelDelayedLoad(_Rt_);

    if (m_regs[_Rs_].isConst()) {
        m_regs[_Rt_].markConst((int32_t) m_regs[_Rs_].val < _Imm_);
    } else {
        allocateReg(_Rt_, _Rs_);
        m_regs[_Rt_].setWriteback(true);
        
        gen.cmp(m_regs[_Rs_].allocatedReg, _Imm_);
        gen.setl(al);
        gen.movzx(m_regs[_Rt_].allocatedReg, al);
    }
}

void DynaRecCPU::recSLTIU() {
    BAILZERO(_Rt_);
    maybeCancelDelayedLoad(_Rt_);

    if (m_regs[_Rs_].isConst()) {
        m_regs[_Rt_].markConst(m_regs[_Rs_].val < (uint32_t) _Imm_);
    } else {
        allocateReg(_Rt_, _Rs_);
        m_regs[_Rt_].setWriteback(true);

        gen.cmp(m_regs[_Rs_].allocatedReg, _Imm_);
        gen.setb(al);
        gen.movzx(m_regs[_Rt_].allocatedReg, al);
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

        gen.cmp(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
        gen.setae(al);
        gen.movzx(m_regs[_Rd_].allocatedReg, al);
    } else if (m_regs[_Rt_].isConst()) {
        allocateReg(_Rd_, _Rs_);
        m_regs[_Rd_].setWriteback(true);

        gen.cmp(m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
        gen.setb(al);
        gen.movzx(m_regs[_Rd_].allocatedReg, al);
    } else {
        allocateReg(_Rd_, _Rs_, _Rt_);
        m_regs[_Rd_].setWriteback(true);

        gen.cmp(m_regs[_Rs_].allocatedReg, m_regs[_Rt_].allocatedReg);
        gen.setb(al);
        gen.movzx(m_regs[_Rd_].allocatedReg, al);
    }
}

void DynaRecCPU::recSLT() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].markConst((int32_t) m_regs[_Rs_].val < (int32_t) m_regs[_Rt_].val);
    } else if (m_regs[_Rs_].isConst()) {
        allocateReg(_Rd_, _Rt_);
        m_regs[_Rd_].setWriteback(true);

        gen.cmp(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].val);
        gen.setge(al);
        gen.movzx(m_regs[_Rd_].allocatedReg, al);
    } else if (m_regs[_Rt_].isConst()) {
        allocateReg(_Rd_, _Rs_);
        m_regs[_Rd_].setWriteback(true);

        gen.cmp(m_regs[_Rs_].allocatedReg, m_regs[_Rt_].val);
        gen.setl(al);
        gen.movzx(m_regs[_Rd_].allocatedReg, al);
    } else {
        allocateReg(_Rd_, _Rs_, _Rt_);
        m_regs[_Rd_].setWriteback(true);

        gen.cmp(m_regs[_Rs_].allocatedReg, m_regs[_Rt_].allocatedReg);
        gen.setl(al);
        gen.movzx(m_regs[_Rd_].allocatedReg, al);
    }
}

void DynaRecCPU::recAND() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].markConst(m_regs[_Rs_].val & m_regs[_Rt_].val);
    } else if (m_regs[_Rs_].isConst()) {
        allocateReg(_Rt_, _Rd_);
        m_regs[_Rd_].setWriteback(true);

        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        gen.and_(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].val);
    } else if (m_regs[_Rt_].isConst()) {
        allocateReg(_Rs_, _Rd_);
        m_regs[_Rd_].setWriteback(true);

        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
        gen.and_(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].val);
    } else {
        allocateReg(_Rs_, _Rd_, _Rt_);
        m_regs[_Rd_].setWriteback(true);

        if (_Rd_ == _Rs_) {
            gen.and_(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        } else if (_Rd_ == _Rt_) {
            gen.and_(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
        } else {
            gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
            gen.and_(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
        }
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

void DynaRecCPU::recNOR() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].markConst(~(m_regs[_Rs_].val | m_regs[_Rt_].val));
    } else if (m_regs[_Rs_].isConst()) {
        allocateReg(_Rt_, _Rd_);
        m_regs[_Rd_].setWriteback(true);

        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        gen.or_(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].val);
        gen.not_(m_regs[_Rd_].allocatedReg);
    } else if (m_regs[_Rt_].isConst()) {
        allocateReg(_Rs_, _Rd_);
        m_regs[_Rd_].setWriteback(true);

        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
        gen.or_(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].val);
        gen.not_(m_regs[_Rd_].allocatedReg);
    } else {
        allocateReg(_Rs_, _Rd_, _Rt_);
        m_regs[_Rd_].setWriteback(true);

        if (_Rd_ == _Rs_) {
            gen.or_(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        } else if (_Rd_ == _Rt_) {
            gen.or_(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
        } else {
            gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
            gen.or_(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
        }

        gen.not_(m_regs[_Rd_].allocatedReg);
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

        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        gen.or_(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].val);
    } else if (m_regs[_Rt_].isConst()) {
        allocateReg(_Rs_, _Rd_);
        m_regs[_Rd_].setWriteback(true);

        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
        gen.or_(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].val);
    } else {
        allocateReg(_Rs_, _Rd_, _Rt_);
        m_regs[_Rd_].setWriteback(true);

        if (_Rd_ == _Rs_) {
            gen.or_(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        } else if (_Rd_ == _Rt_) {
            gen.or_(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
        } else {
            gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
            gen.or_(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
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

void DynaRecCPU::recXOR() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].markConst(m_regs[_Rs_].val ^ m_regs[_Rt_].val);
    } else if (m_regs[_Rs_].isConst()) {
        allocateReg(_Rt_, _Rd_);
        m_regs[_Rd_].setWriteback(true);

        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        gen.xor_(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].val);
    } else if (m_regs[_Rt_].isConst()) {
        allocateReg(_Rs_, _Rd_);
        m_regs[_Rd_].setWriteback(true);

        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
        gen.xor_(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].val);
    } else {
        allocateReg(_Rs_, _Rd_, _Rt_);
        m_regs[_Rd_].setWriteback(true);

        if (_Rd_ == _Rs_) {
            gen.xor_(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        } else if (_Rd_ == _Rt_) {
            gen.xor_(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
        } else {
            gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
            gen.xor_(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].allocatedReg);
        }
    }
}

void DynaRecCPU::recXORI() {
    BAILZERO(_Rt_);
    maybeCancelDelayedLoad(_Rt_);

    if (_Rs_ == _Rt_) {
        if (m_regs[_Rs_].isConst()) {
            m_regs[_Rt_].val ^= _ImmU_;
        } else {
            m_regs[_Rt_].setWriteback(true);
            allocateReg(_Rt_);
            gen.xor_(m_regs[_Rt_].allocatedReg, _ImmU_);
        }
    } else {
        if (m_regs[_Rs_].isConst()) {
            m_regs[_Rt_].markConst(m_regs[_Rs_].val ^ _ImmU_);
        } else {
            m_regs[_Rt_].setWriteback(true);
            allocateReg(_Rt_, _Rs_);
            gen.mov(m_regs[_Rt_].allocatedReg, m_regs[_Rs_].allocatedReg);
            if (_ImmU_) {
                gen.xor_(m_regs[_Rt_].allocatedReg, _ImmU_);
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

        if (_Rd_ != _Rt_) {
            gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        }
        
        if (_Sa_) {
            gen.shl(m_regs[_Rd_].allocatedReg, _Sa_);
        }
    }
}

void DynaRecCPU::recSLLV() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].markConst(m_regs[_Rt_].val << (m_regs[_Rs_].val & 0x1F));
    } else if (m_regs[_Rs_].isConst()) {
        m_regs[_Rd_].setWriteback(true);

        if (_Rt_ == _Rd_) {
            allocateReg(_Rd_);
            gen.shl(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].val & 0x1F);
        } else {
            allocateReg(_Rd_, _Rt_);
            gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
            gen.shl(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].val & 0x1F);
        }
    } else if (m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].setWriteback(true);

        allocateReg(_Rd_, _Rs_);
        gen.mov(ecx, m_regs[_Rs_].allocatedReg);  // Shift amount in ecx
        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].val);
        gen.shl(m_regs[_Rd_].allocatedReg, cl);  // No need to mask the shift amount, x86 does so implicitly
    } else {
        allocateReg(_Rd_, _Rs_, _Rt_);
        m_regs[_Rd_].setWriteback(true);
        gen.mov(ecx, m_regs[_Rs_].allocatedReg); // Shift amount in ecx

        if (_Rt_ == _Rd_) {
            gen.shl(m_regs[_Rd_].allocatedReg, cl);
        } else {
            gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
            gen.shl(m_regs[_Rd_].allocatedReg, cl);
        }
    }
}

void DynaRecCPU::recSRA() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].markConst((int32_t) m_regs[_Rt_].val >> _Sa_);
    } else {
        allocateReg(_Rt_, _Rd_);
        m_regs[_Rd_].setWriteback(true);

        if (_Rd_ != _Rt_) {
            gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        }

        if (_Sa_) {
            gen.sar(m_regs[_Rd_].allocatedReg, _Sa_);
        }
    }
}

void DynaRecCPU::recSRAV() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].markConst((int32_t) m_regs[_Rt_].val >> (m_regs[_Rs_].val & 0x1F));
    } else if (m_regs[_Rs_].isConst()) {
        m_regs[_Rd_].setWriteback(true);

        if (_Rt_ == _Rd_) {
            allocateReg(_Rd_);
            gen.sar(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].val & 0x1F);
        } else {
            allocateReg(_Rd_, _Rt_);
            gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
            gen.sar(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].val & 0x1F);
        }
    } else if (m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].setWriteback(true);

        allocateReg(_Rd_, _Rs_);
        gen.mov(ecx, m_regs[_Rs_].allocatedReg);  // Shift amount in ecx
        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].val);
        gen.sar(m_regs[_Rd_].allocatedReg, cl);  // No need to mask the shift amount, x86 does so implicitly
    } else {
        allocateReg(_Rd_, _Rs_, _Rt_);
        m_regs[_Rd_].setWriteback(true);
        gen.mov(ecx, m_regs[_Rs_].allocatedReg);  // Shift amount in ecx

        if (_Rt_ == _Rd_) {
            gen.sar(m_regs[_Rd_].allocatedReg, cl);
        } else {
            gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
            gen.sar(m_regs[_Rd_].allocatedReg, cl);
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

        if (_Rd_ != _Rt_) {
            gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        }

        if (_Sa_) {
            gen.shr(m_regs[_Rd_].allocatedReg, _Sa_);
        }
    }
}

void DynaRecCPU::recSRLV() {
    BAILZERO(_Rd_);
    maybeCancelDelayedLoad(_Rd_);

    if (m_regs[_Rs_].isConst() && m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].markConst(m_regs[_Rt_].val >> (m_regs[_Rs_].val & 0x1F));
    } else if (m_regs[_Rs_].isConst()) {
        m_regs[_Rd_].setWriteback(true);

        if (_Rt_ == _Rd_) {
            allocateReg(_Rd_);
            gen.shr(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].val & 0x1F);
        } else {
            allocateReg(_Rd_, _Rt_);
            gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
            gen.shr(m_regs[_Rd_].allocatedReg, m_regs[_Rs_].val & 0x1F);
        }
    } else if (m_regs[_Rt_].isConst()) {
        m_regs[_Rd_].setWriteback(true);

        allocateReg(_Rd_, _Rs_);
        gen.mov(ecx, m_regs[_Rs_].allocatedReg);  // Shift amount in ecx
        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].val);
        gen.shr(m_regs[_Rd_].allocatedReg, cl);  // No need to mask the shift amount, x86 does so implicitly
    } else {
        allocateReg(_Rd_, _Rs_, _Rt_);
        m_regs[_Rd_].setWriteback(true);
        gen.mov(ecx, m_regs[_Rs_].allocatedReg);  // Shift amount in ecx

        if (_Rt_ == _Rd_) {
            gen.shr(m_regs[_Rd_].allocatedReg, cl);
        } else {
            gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
            gen.shr(m_regs[_Rd_].allocatedReg, cl);
        }
    }
}

void DynaRecCPU::recMULT() {
    fmt::print("Lo: {}\nHi: {}\n", (void*) &m_psxRegs.GPR.n.lo, (void*) &m_psxRegs.GPR.n.hi);
    abort();
}

// TODO: Add a static_assert that makes sure address_of_hi == address_of_lo + 4
void DynaRecCPU::recMULTU() {
    if ((m_regs[_Rs_].isConst() && m_regs[_Rs_].val == 0) || (m_regs[_Rt_].isConst() && m_regs[_Rt_].val == 0)) {
        gen.mov(qword[contextPointer + LO_OFFSET], 0); // Set both LO and HI to 0 in a single 64-bit write
        return;
    }

    if (m_regs[_Rs_].isConst()) {
        gen.mov(eax, m_regs[_Rs_].val);
        
        if (m_regs[_Rt_].isConst()) {
            gen.mov(edx, m_regs[_Rt_].val);
            gen.mul(edx);
        }
        else {
            allocateReg(_Rt_);
            gen.mul(m_regs[_Rt_].allocatedReg);
        }
    } else {
        if (m_regs[_Rt_].isConst()) {
            allocateReg(_Rs_);
            gen.mov(eax, m_regs[_Rt_].val);
            gen.mul(m_regs[_Rs_].allocatedReg);
        } else {
            allocateReg(_Rt_, _Rs_);
            gen.mov(eax, m_regs[_Rs_].allocatedReg);
            gen.mul(m_regs[_Rt_].allocatedReg);
        }
    }

    gen.mov(dword[contextPointer + LO_OFFSET], eax);
    gen.mov(dword[contextPointer + HI_OFFSET], edx);
}

template <int size, bool signExtend>
void DynaRecCPU::recompileLoad() {
    if (m_regs[_Rs_].isConst()) { // Store the address in first argument register
        const uint32_t addr = m_regs[_Rs_].val + _Imm_;
        gen.mov(arg1, addr);
    } else {
        allocateReg(_Rs_);
        gen.lea(arg1, dword[m_regs[_Rs_].allocatedReg + _Imm_]);
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
        allocateReg(_Rt_);  // Allocate $rt after calling the read function, otherwise call() might flush it
        m_regs[_Rt_].setWriteback(true);
        
        switch (size) {
            case 8:
                signExtend ? gen.movsx(m_regs[_Rt_].allocatedReg, al) : gen.movzx(m_regs[_Rt_].allocatedReg, al);
                break;
            case 16:
                signExtend ? gen.movsx(m_regs[_Rt_].allocatedReg, ax) : gen.movzx(m_regs[_Rt_].allocatedReg, ax);
                break;
            case 32:
                gen.mov(m_regs[_Rt_].allocatedReg, eax);
                break;
        }
    }
}

void DynaRecCPU::recLB()  { recompileLoad<8, true>(); }
void DynaRecCPU::recLBU() { recompileLoad<8, false>(); }
void DynaRecCPU::recLH()  { recompileLoad<16, true>(); }
void DynaRecCPU::recLHU() { recompileLoad<16, false>(); }
void DynaRecCPU::recLW()  { recompileLoad<32, false>(); }

void DynaRecCPU::recSB() {
    if (m_regs[_Rs_].isConst()) {
        const uint32_t addr = m_regs[_Rs_].val + _Imm_;
        const auto pointer = PCSX::g_emulator->m_psxMem->psxMemPointer(addr);
        if (pointer != nullptr) {
            gen.mov(rax, (uintptr_t)pointer);
            if (m_regs[_Rt_].isConst()) {
                gen.mov(Xbyak::util::byte[rax], m_regs[_Rt_].val & 0xFF);
            } else {
                allocateReg(_Rt_);
                gen.mov(Xbyak::util::byte[rax], m_regs[_Rt_].allocatedReg.cvt8());
            }

            return;
        }

        if (m_regs[_Rt_].isConst()) {  // Value to write in arg2
            gen.mov(arg2, m_regs[_Rt_].val & 0xFF);
        } else {
            allocateReg(_Rt_);
            gen.movzx(arg2, m_regs[_Rt_].allocatedReg.cvt8());
        }

        gen.mov(arg1, addr);  // Address to write to in arg1   TODO: Optimize
        call(psxMemWrite8Wrapper);
    }

    else {
        if (m_regs[_Rt_].isConst()) {  // Value to write in arg2
            gen.mov(arg2, m_regs[_Rt_].val & 0xFF);
        } else {
            allocateReg(_Rt_);
            gen.movzx(arg2, m_regs[_Rt_].allocatedReg.cvt8());
        }

        allocateReg(_Rs_);
        gen.lea(arg1, dword[m_regs[_Rs_].allocatedReg + _Imm_]);  // Address to write to in arg1   TODO: Optimize
        call(psxMemWrite8Wrapper);
    }
}

void DynaRecCPU::recSH() {
    if (m_regs[_Rs_].isConst()) {
        const uint32_t addr = m_regs[_Rs_].val + _Imm_;
        const auto pointer = PCSX::g_emulator->m_psxMem->psxMemPointer(addr);
        if (pointer != nullptr) {
            gen.mov(rax, (uintptr_t)pointer);
            if (m_regs[_Rt_].isConst()) {
                gen.mov(word[rax], m_regs[_Rt_].val & 0xFFFF);
            } else {
                allocateReg(_Rt_);
                gen.mov(word[rax], m_regs[_Rt_].allocatedReg.cvt16());
            }

            return;
        }

        if (m_regs[_Rt_].isConst()) {  // Value to write in arg2
            gen.mov(arg2, m_regs[_Rt_].val & 0xFFFF);
        } else {
            allocateReg(_Rt_);
            gen.movzx(arg2, m_regs[_Rt_].allocatedReg.cvt16());
        }

        gen.mov(arg1, addr);  // Address to write to in arg1   TODO: Optimize
        call(psxMemWrite16Wrapper);
    }

    else {
        if (m_regs[_Rt_].isConst()) {  // Value to write in arg2
            gen.mov(arg2, m_regs[_Rt_].val & 0xFFFF);
        } else {
            allocateReg(_Rt_);
            gen.movzx(arg2, m_regs[_Rt_].allocatedReg.cvt16());
        }

        allocateReg(_Rs_);
        gen.lea(arg1, dword[m_regs[_Rs_].allocatedReg + _Imm_]);  // Address to write to in arg1   TODO: Optimize
        call(psxMemWrite16Wrapper);
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
        call(psxMemWrite32Wrapper);
    }

    else {
        if (m_regs[_Rt_].isConst()) {  // Value to write in arg2
            gen.mov(arg2, m_regs[_Rt_].val);
        } else {
            allocateReg(_Rt_);
            gen.mov(arg2, m_regs[_Rt_].allocatedReg);
        }

        allocateReg(_Rs_);
        gen.lea(arg1, dword[m_regs[_Rs_].allocatedReg + _Imm_]);  // Address to write to in arg1   TODO: Optimize
        call(psxMemWrite32Wrapper);
    }
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
            abort();
            break;
    }
}

void DynaRecCPU::recMFC0() {
    BAILZERO(_Rt_);
    maybeCancelDelayedLoad(_Rt_);
    allocateReg(_Rt_);
    m_regs[_Rt_].setWriteback(true);

    gen.mov(m_regs[_Rt_].allocatedReg, dword[contextPointer + COP0_OFFSET(_Rd_)]);
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
        testSoftwareInterrupt<true>();
    }
}

void DynaRecCPU::recRFE() {
    gen.mov(eax, dword[contextPointer + COP0_OFFSET(12)]); // eax = COP0 status register
    gen.mov(ecx, eax); // Copy to ecx
    gen.and_(eax, ~0xF); // Clear bottom 4 bits of eax
    gen.and_(ecx, 0x3c); // Shift bits [5:2] of previous SR two places to the right, mask out the rest of the cached SR value
    gen.shr(ecx, 2);
    gen.or_(eax, ecx); // Merge the shifted bits into eax
    gen.mov(dword[contextPointer + COP0_OFFSET(12)], eax); // Write eax back to SR
    testSoftwareInterrupt<false>();
}

// Checks if a write to SR/CAUSE forcibly triggered an interrupt
// loadSR: Shows if SR is already in eax or if it should be loaded from memory
template <bool loadSR>
void DynaRecCPU::testSoftwareInterrupt() { 
    Label label;
    if (!m_pcWrittenBack) {
        gen.mov(dword[contextPointer + PC_OFFSET], m_pc);
        m_pcWrittenBack = true;
    }

    m_stopCompiling = true;
    setupStackFrame(); // This function uses a conditional call, so we will have to set up a stack frame separately and unconditionally.

    if constexpr (loadSR) {
        gen.mov(eax, dword[contextPointer + COP0_OFFSET(12)]);  // eax = SR
    }
    gen.test(eax, 1);                                      // Check if interrupts are enabled
    gen.jz(label, CodeGenerator::LabelType::T_NEAR);       // If not, skip to the end

    gen.mov(arg2, dword[contextPointer + COP0_OFFSET(13)]); // arg2 = CAUSE
    gen.and_(eax, arg2);
    gen.and_(eax, 0x300);                             // Check if an interrupt was force-fired
    gen.jz(label, CodeGenerator::LabelType::T_NEAR);  // Skip to the end if not

    // Fire the interrupt if it was triggered
    // This object in arg1. Exception code is already in arg2 from before (will be masked by exception handler)
    loadThisPointer(arg1.cvt64());
    gen.mov(arg3, (int32_t) m_inDelaySlot); // Store whether we're in a delay slot in arg3
    gen.mov(dword[contextPointer + PC_OFFSET], m_pc - 4); // PC for exception handler to use
    call<false>(psxExceptionWrapper); // Call the exception wrapper function

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

void DynaRecCPU::recJAL() {
    maybeCancelDelayedLoad(31);
    m_regs[31].markConst(m_pc + 4); // Set $ra to the return value, then treat instruction like a normal J
    recJ();
}

void DynaRecCPU::recJALR() {
    recJR();
    maybeCancelDelayedLoad(_Rd_);
    m_regs[_Rd_].markConst(m_pc + 4); // Link
}

void DynaRecCPU::recJR() {
    m_nextIsDelaySlot = true;
    m_stopCompiling = true;
    m_pcWrittenBack = true;

    if (m_regs[_Rs_].isConst()) {
        gen.mov(dword[contextPointer + PC_OFFSET], m_regs[_Rs_].val & ~3);  // force align jump address
    } else {
        allocateReg(_Rs_);
        gen.and_(m_regs[_Rs_].allocatedReg, ~3); // Align jump address
        gen.mov(dword[contextPointer + PC_OFFSET], m_regs[_Rs_].allocatedReg);
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
        if (isBGEZ) { // BGEZ
            if ((int32_t)m_regs[_Rs_].val >= 0) {
                m_pcWrittenBack = true;
                m_stopCompiling = true;

                gen.mov(dword[contextPointer + PC_OFFSET], target);
            }
        }

        else { // BLTZ
            if ((int32_t)m_regs[_Rs_].val < 0) {
                m_pcWrittenBack = true;
                m_stopCompiling = true;

                gen.mov(dword[contextPointer + PC_OFFSET], target);
            }
        }

        if (link) {
            maybeCancelDelayedLoad(31);
            m_regs[31].markConst(m_pc + 4);
        }

        return;
    }

    m_pcWrittenBack = true;
    m_stopCompiling = true;

    allocateReg(_Rs_);
    gen.test(m_regs[_Rs_].allocatedReg, m_regs[_Rs_].allocatedReg);
    gen.mov(ecx, target);    // ecx = addr if jump taken
    gen.mov(eax, m_pc + 4);  // eax = addr if jump not taken

    if (isBGEZ) { // We're lazy so we can handle the difference between bgez/bltz by just emitting a different form of cmov
        gen.cmovns(eax, ecx);  // if $rs >= 0, move the jump addr into eax
    } else {
        gen.cmovs(eax, ecx);   // if $rs < 0, move the jump addr into eax
    }
    
    gen.mov(dword[contextPointer + PC_OFFSET], eax);
    if (link) {
        maybeCancelDelayedLoad(31);
        m_regs[31].markConst(m_pc + 4);
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

    if (m_regs[_Rs_].isAllocated()) { // Don't bother allocating Rs unless it's already allocated
        gen.test(m_regs[_Rs_].allocatedReg, m_regs[_Rs_].allocatedReg);
    } else {
        gen.cmp(dword[contextPointer + GPR_OFFSET(_Rs_)], 0);
    }

    gen.mov(eax, m_pc + 4); // eax = addr if jump not taken
    gen.mov(ecx, target); // ecx = addr if jump is taken
    gen.cmovg(eax, ecx);  // if taken, move the jump addr into eax
    gen.mov(dword[contextPointer + PC_OFFSET], eax);
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
            gen.mov(dword[contextPointer + PC_OFFSET], target);
        }
        return;
    }

    m_pcWrittenBack = true;
    m_stopCompiling = true;

    if (m_regs[_Rs_].isAllocated()) {  // Don't bother allocating Rs unless it's already allocated
        gen.test(m_regs[_Rs_].allocatedReg, m_regs[_Rs_].allocatedReg);
    } else {
        gen.cmp(dword[contextPointer + GPR_OFFSET(_Rs_)], 0);
    }

    gen.mov(eax, m_pc + 4);  // eax = addr if jump not taken
    gen.mov(ecx, target);    // ecx = addr if jump is taken
    gen.cmovle(eax, ecx);     // if taken, move the jump addr into eax
    gen.mov(dword[contextPointer + PC_OFFSET], eax);
}

// TODO: Handle INT_MIN / -1
void DynaRecCPU::recDIV() {
    Label divisionByZero;

    if (m_regs[_Rt_].isConst()) { // Check divisor if constant
        if (m_regs[_Rt_].val == 0) { // Handle case where divisor is 0
            if (m_regs[_Rs_].isConst()) {
                gen.mov(dword[contextPointer + HI_OFFSET], m_regs[_Rs_].val); // HI = $rs
                gen.mov(dword[contextPointer + LO_OFFSET], m_regs[_Rs_].val & 0x80000000 ? 1 : -1); // LO = 1 or -1 depending on the sign of $rs
            }

            else {
                allocateReg(_Rs_);
                gen.mov(dword[contextPointer + HI_OFFSET], m_regs[_Rs_].allocatedReg); // Set hi to $rs
                gen.mov(eax, m_regs[_Rs_].allocatedReg);
                gen.shr(eax, 31);
                gen.lea(eax, dword[rax + rax - 1]);
                gen.mov(dword[contextPointer + LO_OFFSET], eax); // Set lo to 1 or -1 depending on the sign of $rs
            }

            return;
        }

        gen.mov(ecx, m_regs[_Rt_].val); // Divisor in ecx
        if (m_regs[_Rs_].isConst()) {
            gen.mov(eax, m_regs[_Rs_].val);
        } else {
            allocateReg(_Rs_);
            gen.mov(eax, m_regs[_Rs_].allocatedReg);
        }
    } else { // non-constant divisor
        if (m_regs[_Rs_].isConst()) {
            allocateReg(_Rt_);
            gen.mov(eax, m_regs[_Rs_].val);  // Dividend in eax
        } else {
            allocateReg(_Rt_, _Rs_);
            gen.mov(ecx, m_regs[_Rt_].allocatedReg); // Divisor in ecx
            gen.mov(eax, m_regs[_Rs_].allocatedReg); // Dividend in eax
            gen.test(ecx, ecx);  // Check if divisor is 0
            gen.jz(divisionByZero, CodeGenerator::LabelType::T_NEAR);  // Jump to divisionByZero label if so
        }
    }

    gen.cdq(); // Sign extend dividend to 64 bits in edx:eax
    gen.idiv(ecx); // Signed division by divisor
    gen.mov(dword[contextPointer + LO_OFFSET], eax); // Lo = quotient
    gen.mov(dword[contextPointer + HI_OFFSET], edx); // Hi = remainder

    if (!m_regs[_Rt_].isConst()) { // Emit a division by 0 handler if the divisor is unknown at compile time
        Label end;
        gen.jmp(end, CodeGenerator::LabelType::T_NEAR); // skip to the end if not a div by zero
        gen.L(divisionByZero); // Here starts our division by 0 handler

        gen.mov(dword[contextPointer + HI_OFFSET], eax);  // Set hi to $rs
        gen.shr(eax, 31);
        gen.lea(eax, dword[rax + rax - 1]);
        gen.mov(dword[contextPointer + LO_OFFSET], eax);  // Set lo to 1 or -1 depending on the sign of $rs

        gen.L(end);
    }
}

void DynaRecCPU::recDIVU() {
    Label divisionByZero;

    if (m_regs[_Rt_].isConst()) {     // Check divisor if constant
        if (m_regs[_Rt_].val == 0) {  // Handle case where divisor is 0
            if (m_regs[_Rs_].isConst()) {
                gen.mov(dword[contextPointer + HI_OFFSET], m_regs[_Rs_].val);  // HI = $rs
                gen.mov(dword[contextPointer + LO_OFFSET], -1);  // LO gets set to -1 on DIVU by zero
            }

            else {
                allocateReg(_Rs_);
                gen.mov(dword[contextPointer + HI_OFFSET], m_regs[_Rs_].allocatedReg);  // Set hi to $rs
                gen.mov(dword[contextPointer + LO_OFFSET], -1); // Set lo to -1
            }

            return;
        }

        gen.mov(ecx, m_regs[_Rt_].val);  // Divisor in ecx
        if (m_regs[_Rs_].isConst()) {
            gen.mov(eax, m_regs[_Rs_].val);
        } else {
            allocateReg(_Rs_);
            gen.mov(eax, m_regs[_Rs_].allocatedReg);
        }
    } else {  // non-constant divisor
        if (m_regs[_Rs_].isConst()) {
            allocateReg(_Rt_);
            gen.mov(eax, m_regs[_Rs_].val);  // Dividend in eax
        } else {
            allocateReg(_Rt_, _Rs_);
            gen.mov(ecx, m_regs[_Rt_].allocatedReg);                   // Divisor in ecx
            gen.mov(eax, m_regs[_Rs_].allocatedReg);                   // Dividend in eax
            gen.test(ecx, ecx);                                        // Check if divisor is 0
            gen.jz(divisionByZero, CodeGenerator::LabelType::T_NEAR);  // Jump to divisionByZero label if so
        }
    }

    gen.xor_(edx, edx); // Set top 32 bits of dividend to 
    gen.div(ecx);     // Unsigned division by divisor
    gen.mov(dword[contextPointer + LO_OFFSET], eax);  // Lo = quotient
    gen.mov(dword[contextPointer + HI_OFFSET], edx);  // Hi = remainder

    if (!m_regs[_Rt_].isConst()) {  // Emit a division by 0 handler if the divisor is unknown at compile time
        Label end;
        gen.jmp(end, CodeGenerator::LabelType::T_NEAR);  // skip to the end if not a div by zero
        gen.L(divisionByZero);                           // Here starts our division by 0 handler

        gen.mov(dword[contextPointer + HI_OFFSET], eax);  // Set hi to $rs
        gen.mov(dword[contextPointer + LO_OFFSET], -1);  // Set lo to -1

        gen.L(end);
    }
}

// TODO: Constant propagation for MFLO/HI, read the result from eax/edx if possible instead of reading memory again
void DynaRecCPU::recMFLO() {
    maybeCancelDelayedLoad(_Rd_);
    allocateReg(_Rd_);
    m_regs[_Rd_].setWriteback(true);

    gen.mov(m_regs[_Rd_].allocatedReg, dword[contextPointer + LO_OFFSET]);
}

// TODO: Constant propagation for MFLO/HI, read the result from eax/edx if possible instead of reading memory again
void DynaRecCPU::recMFHI() {
    maybeCancelDelayedLoad(_Rd_);
    allocateReg(_Rd_);
    m_regs[_Rd_].setWriteback(true);

    gen.mov(m_regs[_Rd_].allocatedReg, dword[contextPointer + HI_OFFSET]);
}

void DynaRecCPU::recMTLO() {
    if (m_regs[_Rs_].isConst()) {
        gen.mov(dword[contextPointer + LO_OFFSET], m_regs[_Rs_].val);
    } else {
        allocateReg(_Rs_);
        gen.mov(dword[contextPointer + LO_OFFSET], m_regs[_Rs_].allocatedReg);
    }
}

void DynaRecCPU::recMTHI() {
    if (m_regs[_Rs_].isConst()) {
        gen.mov(dword[contextPointer + HI_OFFSET], m_regs[_Rs_].val);
    } else {
        allocateReg(_Rs_);
        gen.mov(dword[contextPointer + HI_OFFSET], m_regs[_Rs_].allocatedReg);
    }
}

void DynaRecCPU::recException(Exception e) {
    m_pcWrittenBack = true;
    m_stopCompiling = true;

    loadThisPointer(arg1.cvt64()); // Pointer to this object in arg1
    gen.mov(arg2, static_cast<std::underlying_type<Exception>::type>(e) << 2); // Exception type in arg2
    gen.mov(arg3, (int32_t)m_inDelaySlot); // Store whether we're in a delay slot in arg3
    gen.mov(dword[contextPointer + PC_OFFSET], m_pc - 4);  // PC for exception handler to use

    call(psxExceptionWrapper); // Call the exception wrapper
}

void DynaRecCPU::recSYSCALL() {
    recException(Exception::Syscall);
}

void DynaRecCPU::recBREAK() {
    recException(Exception::Break);
}

#endif DYNAREC_X86_64
