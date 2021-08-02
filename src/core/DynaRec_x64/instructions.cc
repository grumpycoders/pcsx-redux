#include "recompiler.h"
#if defined(DYNAREC_X86_64)
#define BAILZERO(x) if (!(x)) { return; }

void DynaRecCPU::recUnknown() {
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
        m_regs[_Rd_].setWriteback(true);
        allocateReg(_Rt_, _Rd_);

        gen.mov(m_regs[_Rd_].allocatedReg, m_regs[_Rt_].allocatedReg);
        if (_Sa_) {
            gen.shl(m_regs[_Rd_].allocatedReg, _Sa_);
        }
    }
}

void DynaRecCPU::recSW() {
    if (m_regs[_Rs_].isConst()) {
        const uint32_t addr = m_regs[_Rs_].val + _Imm_;
        if (m_regs[_Rt_].isConst()) { // Value to write in arg2
            gen.mov(arg2, m_regs[_Rt_].val);
        } else {
            allocateReg(_Rt_);
            gen.mov(arg2, m_regs[_Rt_].allocatedReg);
        }

        gen.mov(arg1, addr); // Address to write to in arg1   TODO: Optimize
        prepareForCall();
        gen.callFunc(psxMemRead32Wrapper);
    }

    else {
        fmt::print("SW without a constant address\n");
        abort();
    }
}

void DynaRecCPU::recJ() {
    const uint32_t target = _Target_ * 4 + (m_pc & 0xf0000000);
    m_nextIsDelaySlot = true;
    m_stopCompiling = true;

    gen.mov(dword[contextPointer + PC_OFFSET], target); // Write PC
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
            
            gen.lea(m_regs[_Rt_].allocatedReg, dword [m_regs[_Rs_].allocatedReg + _Imm_]);
        }
    }
}

#endif DYNAREC_X86_64
