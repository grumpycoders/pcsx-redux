/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#if defined(DYNAREC_X86_64)
#include "core/gte.h"
#define COP2_CONTROL_OFFSET(reg) ((uintptr_t) &m_psxRegs.CP2C.r[(reg)] - (uintptr_t) &m_psxRegs)
#define COP2_DATA_OFFSET(reg) ((uintptr_t)&m_psxRegs.CP2D.r[(reg)] - (uintptr_t)&m_psxRegs)

void DynaRecCPU::recCOP2() {
    setupStackFrame(); // Set up a stack frame outside the conditional block

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

            case 31:
                fmt::print("[GTE] Wrote to FLAG\n");
                abort();
                break;

            default:
                gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(_Rd_)], m_regs[_Rt_].val);
                break;
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

            case 31:
                fmt::print("[GTE] Wrote to FLAG\n");
                abort();
                break;

            default:
                gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(_Rd_)], m_regs[_Rt_].allocatedReg);
                break;
        }
    }
}

void DynaRecCPU::recMTC2() {
    switch (_Rd_) {
        case 15:
        case 28:
        case 30:
            fmt::print("Unimplemented MTC2 to GTE data register {}\n", _Rd_);
            abort();
            break;

        case 31:
            return;
    }

    if (m_regs[_Rt_].isConst()) {
        gen.mov(dword[contextPointer + COP2_DATA_OFFSET(_Rd_)], m_regs[_Rt_].val);
    } else {
        allocateReg(_Rt_);
        gen.mov(dword[contextPointer + COP2_DATA_OFFSET(_Rd_)], m_regs[_Rt_].allocatedReg);
    }
}

static uint32_t MFC2Wrapper(int reg) {
    return PCSX::g_emulator->m_gte->MFC2(reg);
}

void DynaRecCPU::recMFC2() {
    gen.mov(arg1, _Rd_);
    call<false>(MFC2Wrapper); // No need for a stack frame as recCOP2 sets it up for us

    if (_Rt_) {
        maybeCancelDelayedLoad(_Rt_);
        allocateRegWithoutLoad(_Rt_);
        m_regs[_Rt_].setWriteback(true);
        gen.mov(m_regs[_Rt_].allocatedReg, eax);
    }
}

void DynaRecCPU::recCFC2() {
    if (_Rt_) {
        maybeCancelDelayedLoad(_Rt_);
        allocateRegWithoutLoad(_Rt_);
        m_regs[_Rt_].setWriteback(true);

        gen.mov(m_regs[_Rt_].allocatedReg, dword[contextPointer + COP2_CONTROL_OFFSET(_Rd_)]);
    }
}

void DynaRecCPU::recLWC2() {
    Label end;
    setupStackFrame(); // This instruction might skipped, so set up the stack frame  outside the conditional block
    gen.test(dword[contextPointer + COP0_OFFSET(12)], 0x40000000);  // Check SR to see if COP2 is enabled
    gen.jz(end); // Skip the opcode if not

    if (m_regs[_Rs_].isConst()) { // Store address in arg1
        gen.mov(arg1, m_regs[_Rs_].val + _Imm_);
    } else {
        allocateReg(_Rs_);
        gen.lea(arg1, dword[m_regs[_Rs_].allocatedReg + _Imm_]);
    }

    call<false>(psxMemRead32Wrapper); // Read a value from memory. No need to set up a stack frame as we did it before
    switch (_Rt_) {
        case 15:
        case 28:
        case 30:
            fmt::print("Unimplemented LWC2 to GTE data register {}\n", _Rt_);
            abort();
            break;
    }
    
    if (_Rt_ != 31) {
        gen.mov(dword[contextPointer + COP2_DATA_OFFSET(_Rt_)], eax);
    }

    gen.L(end);
}

void DynaRecCPU::recSWC2() {
    Label end;
    setupStackFrame();  // This instruction might skipped, so set up the stack frame  outside the conditional block
    gen.test(dword[contextPointer + COP0_OFFSET(12)], 0x40000000);  // Check SR to see if COP2 is enabled
    gen.jz(end);                                                    // Skip the opcode if not

    gen.mov(arg1, _Rt_);
    call<false>(MFC2Wrapper);  // Fetch the COP2 data reg in eax

    // Address in arg1
    if (m_regs[_Rs_].isConst()) {
        gen.mov(arg1, m_regs[_Rs_].val + _Imm_);
    } else {
        allocateReg(_Rs_);
        gen.lea(arg1, dword [m_regs[_Rs_].allocatedReg + _Imm_]);
    }

    gen.mov(arg2, eax); // Value to write in arg2
    call<false>(psxMemWrite32Wrapper);

    gen.L(end);
}

#define GTE_FALLBACK(name) \
static void name##Wrapper(uint32_t instruction) {  \
    PCSX::g_emulator->m_gte->name(instruction);    \
}                                                  \
                                                   \
void DynaRecCPU::rec##name() {                     \
    gen.mov(arg1, m_psxRegs.code);                 \
    call<false>(name##Wrapper);                    \
}

// Note: The GTE recompiler functions don't set up a stack frame, because recCOP2 does it already
GTE_FALLBACK(AVSZ3);
GTE_FALLBACK(AVSZ4);
GTE_FALLBACK(CC);
GTE_FALLBACK(CDP);
GTE_FALLBACK(DCPL);
GTE_FALLBACK(DPCS);
GTE_FALLBACK(DPCT);
GTE_FALLBACK(GPF);
GTE_FALLBACK(GPL);
GTE_FALLBACK(INTPL);
GTE_FALLBACK(MVMVA);
GTE_FALLBACK(NCCS);
GTE_FALLBACK(NCCT);
GTE_FALLBACK(NCDS);
GTE_FALLBACK(NCDT);
GTE_FALLBACK(NCLIP);
GTE_FALLBACK(NCS);
GTE_FALLBACK(NCT);
GTE_FALLBACK(OP);
GTE_FALLBACK(RTPS);
GTE_FALLBACK(RTPT);
GTE_FALLBACK(SQR);

#endif  // DYNAREC_X86_64
