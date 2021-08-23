#include "recompiler.h"

#if defined(DYNAREC_X86_64)
#include "core/gte.h"
#define COP2_CONTROL_OFFSET(reg) ((uintptr_t) &m_psxRegs.CP2C.r[(reg)] - (uintptr_t) &m_psxRegs)
#define COP2_DATA_OFFSET(reg) ((uintptr_t)&m_psxRegs.CP2D.r[(reg)] - (uintptr_t)&m_psxRegs)

void DynaRecCPU::recCOP2() {
    Label end;
    gen.test(dword[contextPointer + COP0_OFFSET(12)], 0x40000000); // Check SR to see if COP2 (GTE) is enabled
    gen.jz(end); // Skip the opcode if not
    
    const auto func = m_recGTE[m_psxRegs.code & 0x3F];  // Look up the opcode in our decoding LUT
    (*this.*func)(); // Jump into the handler to recompile it

    gen.L(end);
}

void DynaRecCPU::recGTEMove() {
    switch (_Rs_) {
        case 0:
            recMFC2();
            break;
        case 2:
            recCFC2();
            break;
        case 4:
            recMTC2();
            break;
        case 6:
            recCTC2();
            break;
        default:
            recUnknown();
            break;
    }
}

void DynaRecCPU::recCTC2() {
    if (m_regs[_Rt_].isConst()) {
        gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(_Rd_)], m_regs[_Rt_].val);

        switch (_Rd_) {
            case 4: // These registers are signed 16-bit values. Reading from them returns their value sign-extended to 32 bits
            case 12:
            case 20:
            case 26:
            case 27:
            case 29:
            case 30:
                gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(_Rd_)], (uint32_t)(int16_t)m_regs[_Rt_].val);
                break;
            default:
                fmt::print("Unimplemented write to COP2 control register {}\n", _Rd_);
                abort();
                gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(_Rd_)], m_regs[_Rt_].val);
        }

    } else {
        allocateReg(_Rt_);

        switch (_Rd_) {
            case 4:  // These registers are signed 16-bit values. Reading from them returns their value sign-extended to 32 bits
            case 12:
            case 20:
            case 26:
            case 27:
            case 29:
            case 30:
                gen.movsx(eax, m_regs[_Rt_].allocatedReg.cvt16()); // Sign extend value from 16 to 32 bits
                gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(_Rd_)], eax);
                break;
            default:
                fmt::print("Unimplemented write to COP2 control register {}\n", _Rd_);
                abort();
                gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(_Rd_)], m_regs[_Rt_].allocatedReg);
        }
    }
}

void DynaRecCPU::recMTC2() {
    switch (_Rd_) {
        default:
            fmt::print("Write to GTE data register {}\n", _Rd_);
            abort();
    }

    if (m_regs[_Rt_].isConst()) {
        gen.mov(dword[contextPointer + COP2_DATA_OFFSET(_Rd_)], m_regs[_Rt_].val);
    } else {
        allocateReg(_Rt_); // TODO: Don't load register if it hasn't been loaded
        gen.mov(dword[contextPointer + COP2_DATA_OFFSET(_Rd_)], m_regs[_Rt_].allocatedReg);
    }
}

void DynaRecCPU::recMFC2() {
    switch (_Rd_) {
        default:
            fmt::print("Read from GTE data register{}\n", _Rd_);
            abort();
    }

    allocateReg(_Rt_); // TODO: Don't load register if it hasn't been loaded
    gen.mov(m_regs[_Rt_].allocatedReg, dword[contextPointer + COP2_DATA_OFFSET(_Rd_)]);
}

void DynaRecCPU::recCFC2() {
    switch (_Rd_) {
        default:
            fmt::print("Read from GTE control register{}\n", _Rd_);
            abort();
    }

    allocateReg(_Rt_);  // TODO: Don't load register if it hasn't been loaded
    gen.mov(m_regs[_Rt_].allocatedReg, dword[contextPointer + COP2_CONTROL_OFFSET(_Rd_)]);
}

#define GTE_FALLBACK(name) \
static void name##Wrapper(uint32_t instruction) { \
    PCSX::g_emulator->m_gte->name(instruction);   \
}                                                 \
                                                  \
void DynaRecCPU::rec##name() {                    \
    gen.mov(arg1, m_psxRegs.code);                \
    call(name##Wrapper);                          \
}

GTE_FALLBACK(RTPS);
GTE_FALLBACK(NCLIP);
GTE_FALLBACK(OP);
GTE_FALLBACK(DPCS);
GTE_FALLBACK(INTPL);
GTE_FALLBACK(MVMVA);
GTE_FALLBACK(NCDS);
GTE_FALLBACK(CDP);
GTE_FALLBACK(NCDT);
GTE_FALLBACK(NCCS);
GTE_FALLBACK(CC);
GTE_FALLBACK(NCS);
GTE_FALLBACK(NCT);
GTE_FALLBACK(SQR);
GTE_FALLBACK(DCPL);
GTE_FALLBACK(DPCT);
GTE_FALLBACK(AVSZ3);
GTE_FALLBACK(AVSZ4);
GTE_FALLBACK(RTPT);
GTE_FALLBACK(GPF);
GTE_FALLBACK(GPL);
GTE_FALLBACK(NCCT);

#endif  // DYNAREC_X86_64
