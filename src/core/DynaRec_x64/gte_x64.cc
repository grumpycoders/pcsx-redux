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

            case 31: { // Write to FLAG - Set low 12 bits to 0 and fix up the error flag
                uint32_t value = m_regs[_Rt_].val & 0x7ffff000;
                if ((value & 0x7f87e000) != 0) {
                    value |= 0x80000000;
                }
                gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(31)], value);
                break;
            }

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

            case 31: // Write to FLAG - Set low 12 bits to 0 and fix up the error flag
                gen.mov(ecx, m_regs[_Rt_].allocatedReg);
                gen.and_(ecx, 0x7ffff000);
                gen.lea(eax, dword[rcx - 0x80000000]);
                gen.test(m_regs[_Rt_].allocatedReg, 0x7f87e000);
                gen.cmove(eax, ecx);
                gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(31)], eax);
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
            gen.mov(rax, qword[contextPointer + COP2_DATA_OFFSET(13)]); // SXY0 = SXY1 and SXY1 = SXY2
            gen.mov(qword[contextPointer + COP2_DATA_OFFSET(12)], rax);

            // SXY2 = val
            if (m_regs[_Rt_].isConst()) {
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(14)], m_regs[_Rt_].val);
            } else {
                allocateReg(_Rt_);
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(14)], m_regs[_Rt_].allocatedReg);
            }
            break;
            
        case 28: // IRGB
            if (m_regs[_Rt_].isConst()) { // Calculate IR1/IR2/IR3 values and write them back
                const auto value = m_regs[_Rt_].val;

                const auto IR1 = (value & 0x1f) << 7;
                const auto IR2 = (value & 0x3e0) << 2;
                const auto IR3 = (value & 0x7c00) >> 3;

                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(9)], IR1);
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(10)], IR2);
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(11)], IR3);
            } else {
                allocateReg(_Rt_);
                gen.mov(eax, m_regs[_Rt_].allocatedReg);

                gen.and_(eax, 0x1f); // Calculate IR1
                gen.shl(eax, 7);
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(9)], eax);

                gen.lea(eax, dword[4 * m_regs[_Rt_].allocatedReg]); // Calculate IR2
                gen.and_(eax, 0xf80); // The above lea shifted eax by 2 first, so we adjust the mask
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(10)], eax);

                gen.mov(eax, m_regs[_Rt_].allocatedReg); // Calculate IR3
                gen.shr(eax, 3);
                gen.and_(eax, 0xf80);
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(11)], eax);
            }
            
            break;

        case 30:
            if (m_regs[_Rt_].isConst()) {
                const auto result = PCSX::GTE::countLeadingBits(m_regs[_Rt_].val);
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(31)], result); // Set LZCR
            } else {
                allocateReg(_Rt_);

                gen.mov(eax, m_regs[_Rt_].allocatedReg); // eax = value to count leading bits of
                gen.mov(edx, eax); // value = ~value if the msb is set
                gen.sar(edx, 31);
                gen.xor_(eax, edx);

                if (gen.hasLZCNT) { // Count leading zeroes (Return 32 if the input is zero)
                    gen.lzcnt(eax, eax);
                } else { // If our CPU doesn't have LZCNT
                    gen.bsr(eax, eax); // eax = 31 - CLZ(value)
                    gen.mov(edx, 63); // Set eax to 63 if the input was 0
                    gen.cmovz(eax, edx);
                    gen.xor_(eax, 31); // Subtract the value from 31
                }

                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(31)], eax); // Write result to LZCR
            }
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
    if (_Rt_) {
        allocateRegWithoutLoad(_Rt_);
        m_regs[_Rt_].setWriteback(true);
    }

    const auto op = (_Rt_ == 0) ? eax : m_regs[_Rt_].allocatedReg;
    switch (_Rd_) {
        case 1: case 3: case 5: case 8: case 9: case 10: case 11:
            gen.movsx(op, word[contextPointer + COP2_DATA_OFFSET(_Rd_)]);
            gen.mov(dword[contextPointer + COP2_DATA_OFFSET(_Rd_)], op);
            break;

        case 7: case 16: case 17: case 18: case 19:
            gen.movzx(op, word[contextPointer + COP2_DATA_OFFSET(_Rd_)]);
            gen.mov(dword[contextPointer + COP2_DATA_OFFSET(_Rd_)], op);
            break;
        
        case 15: // SXYP
            gen.mov(op, dword[contextPointer + COP2_DATA_OFFSET(14)]); // Copy SXY2 to SXYP
            gen.mov(dword[contextPointer + COP2_DATA_OFFSET(15)], op);
            break;

        case 28: case 29:  // Fallback for IRGB/ORGB
            gen.mov(arg1, _Rd_);
            call(MFC2Wrapper);
            
            if (_Rt_) {
                allocateRegWithoutLoad(_Rt_); // Reallocate the reg in case the call thrashed it
                gen.mov(m_regs[_Rt_].allocatedReg, eax);
            }
            break;

        default:
            if (_Rt_) {
                gen.mov(op, dword[contextPointer + COP2_DATA_OFFSET(_Rd_)]);
            }
            break;
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
    gen.test(dword[contextPointer + COP0_OFFSET(12)], 0x40000000);  // Check SR to see if COP2 is enabled
    gen.jz(end); // Skip the opcode if not

    if (m_regs[_Rs_].isConst()) { // Store address in arg1
        gen.mov(arg1, m_regs[_Rs_].val + _Imm_);
    } else {
        allocateReg(_Rs_);
        gen.moveAndAdd(arg1, m_regs[_Rs_].allocatedReg, _Imm_);
    }

    call(psxMemRead32Wrapper); // Read a value from memory. No need to set up a stack frame as we did it before
    switch (_Rt_) {
        case 15:
        case 30:
            fmt::print("Unimplemented LWC2 to GTE data register {}\n", _Rt_);
            abort();
            break;
        
        case 28: // IRGB
            gen.mov(ecx, eax);

            gen.and_(ecx, 0x1f); // Calculate IR1
            gen.shl(ecx, 7);
            gen.mov(dword[contextPointer + COP2_DATA_OFFSET(9)], ecx);

            gen.lea(ecx, dword[4 * rax]); // Calculate IR2
            gen.and_(ecx, 0xf80); // The above lea shifted eax by 2 first, so we adjust the mask
            gen.mov(dword[contextPointer + COP2_DATA_OFFSET(10)], ecx);

            gen.mov(ecx, eax); // Calculate IR3
            gen.shr(ecx, 3);
            gen.and_(ecx, 0xf80);
            gen.mov(dword[contextPointer + COP2_DATA_OFFSET(11)], ecx);
            break;
    }
    
    if (_Rt_ != 31) {
        gen.mov(dword[contextPointer + COP2_DATA_OFFSET(_Rt_)], eax);
    }

    gen.L(end);
}

void DynaRecCPU::recSWC2() {
    Label end;
    gen.test(dword[contextPointer + COP0_OFFSET(12)], 0x40000000);  // Check SR to see if COP2 is enabled
    gen.jz(end);                                                    // Skip the opcode if not

    gen.moveImm(arg1, _Rt_);
    call(MFC2Wrapper);  // Fetch the COP2 data reg in eax

    // Address in arg1
    if (m_regs[_Rs_].isConst()) {
        gen.mov(arg1, m_regs[_Rs_].val + _Imm_);
    } else {
        allocateReg(_Rs_);
        gen.moveAndAdd(arg1, m_regs[_Rs_].allocatedReg, _Imm_);
    }

    gen.mov(arg2, eax); // Value to write in arg2
    call(psxMemWrite32Wrapper);

    gen.L(end);
}

#define GTE_FALLBACK(name) \
static void name##Wrapper(uint32_t instruction) {  \
    PCSX::g_emulator->m_gte->name(instruction);    \
}                                                  \
                                                   \
void DynaRecCPU::rec##name() {                     \
    gen.mov(arg1, m_psxRegs.code);                 \
    call(name##Wrapper);                           \
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
