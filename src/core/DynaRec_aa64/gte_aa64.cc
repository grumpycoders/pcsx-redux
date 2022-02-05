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
#include "core/gte.h"
#define COP2_CONTROL_OFFSET(reg) ((uintptr_t)&m_psxRegs.CP2C.r[(reg)] - (uintptr_t)this)
#define COP2_DATA_OFFSET(reg) ((uintptr_t)&m_psxRegs.CP2D.r[(reg)] - (uintptr_t)this)

void DynaRecCPU::recCOP2() {
    const auto func = m_recGTE[m_psxRegs.code & 0x3F];  // Look up the opcode in our decoding LUT
    (*this.*func)();                                    // Jump into the handler to recompile it
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
            case 4:  // These registers are signed 16-bit values. Reading from them returns their value sign-extended to
                     // 32 bits
            case 12:
            case 20:
            case 26:
            case 27:
            case 29:
            case 30:
                gen.Mov(w0, (uint32_t)(int16_t)m_regs[_Rt_].val);
                gen.Str(w0, MemOperand(contextPointer, COP2_CONTROL_OFFSET(_Rd_)));
                break;

            case 31: {  // Write to FLAG - Set low 12 bits to 0 and fix up the error flag
                    uint32_t value = m_regs[_Rt_].val & 0x7ffff000;
                    if ((value & 0x7f87e000) != 0) {
                        value |= 0x80000000;
                    }
                    gen.Mov(w0, value);
                gen.Str(w0, MemOperand(contextPointer, COP2_CONTROL_OFFSET(31)));
                break;
            }

            default:
                gen.Mov(w0, m_regs[_Rt_].val);
                gen.Str(w0, MemOperand(contextPointer, COP2_CONTROL_OFFSET(_Rd_)));
                break;
        }

    } else {
        allocateReg(_Rt_);

        switch (_Rd_) {
            case 4:  // These registers are signed 16-bit values. Reading from them returns their value sign-extended to
                     // 32 bits
            case 12:
            case 20:
            case 26:
            case 27:
            case 29:
            case 30:
                // Could probably use a regular Mov then Strsh here
                gen.Sxth(w0, m_regs[_Rt_].allocatedReg); // Sign extend value from 16 to 32 bits
                gen.Str(w0, MemOperand(contextPointer, COP2_CONTROL_OFFSET(_Rd_)));
                break;

            case 31:  // Write to FLAG - Set low 12 bits to 0 and fix up the error flag
                gen.And(w1, m_regs[_Rt_].allocatedReg, 0x7f87e000);
                gen.Mov(w0, 0x80000000);
                gen.Sub(w0, w1, 0x80000000);
                gen.Mov(w2, 0x7f87e000);
                gen.Tst(m_regs[_Rt_].allocatedReg, w2);
                // Change order here and condition to possibly eliminate an unneeded mov
                gen.Csel(w0, w1, w0, eq);
                gen.Str(w0, MemOperand(contextPointer, COP2_CONTROL_OFFSET(31)));
                break;

            default:
                gen.Str(m_regs[_Rt_].allocatedReg, MemOperand(contextPointer, COP2_CONTROL_OFFSET(_Rd_)));
                break;
        }
    }
}

void DynaRecCPU::recMTC2() {
    switch (_Rd_) {
        case 15:
            gen.Ldr(x0, MemOperand(contextPointer, COP2_DATA_OFFSET(13))); // SXY0 = SXY1 and SXY1 = SXY2
            gen.Str(x0, MemOperand(contextPointer, COP2_DATA_OFFSET(12)));

            // SXY2 = val
            if (m_regs[_Rt_].isConst()) {
                gen.Mov(w1,  m_regs[_Rt_].val);
                gen.Str(w1, MemOperand(contextPointer, COP2_DATA_OFFSET(14)));
            } else {
                allocateReg(_Rt_);
                gen.Str(m_regs[_Rt_].allocatedReg, MemOperand(contextPointer, COP2_DATA_OFFSET(14)));
            }
            break;

        case 28:                           // IRGB
            if (m_regs[_Rt_].isConst()) {  // Calculate IR1/IR2/IR3 values and write them back
                const auto value = m_regs[_Rt_].val;

                const auto IR1 = (value & 0x1f) << 7;
                const auto IR2 = (value & 0x3e0) << 2;
                const auto IR3 = (value & 0x7c00) >> 3;
                gen.Mov(w1, IR1);
                gen.Mov(w2, IR2);
                gen.Mov(w3, IR3);
                gen.Str(w1, MemOperand(contextPointer, COP2_DATA_OFFSET(9)));
                gen.Str(w2, MemOperand(contextPointer, COP2_DATA_OFFSET(10)));
                gen.Str(w3, MemOperand(contextPointer, COP2_DATA_OFFSET(11)));
            } else {
                allocateReg(_Rt_);
                gen.And(w0, m_regs[_Rt_].allocatedReg, 0x1f); // Calculate IR1
                gen.Lsl(w0, w0, 7);
                gen.Str(w0, MemOperand(contextPointer, COP2_DATA_OFFSET(9)));
                gen.Lsl(w0, m_regs[_Rt_].allocatedReg, 2); // Calculate IR2
                gen.And(w0, w0, 0xf80); // The above LSL shifted w0 by 2 first, so we adjust the mask
                gen.Str(w0, MemOperand(contextPointer, COP2_DATA_OFFSET(10)));
                gen.Lsr(w0, m_regs[_Rt_].allocatedReg, 3); // Calculate IR3
                gen.And(w0, w0, 0xf80);
                gen.Str(w0, MemOperand(contextPointer, COP2_DATA_OFFSET(11)));
            }

            break;

        case 30:
            if (m_regs[_Rt_].isConst()) {
                const auto result = PCSX::GTE::countLeadingBits(m_regs[_Rt_].val);
                gen.Mov(w0, result);
                gen.Str(w0, MemOperand(contextPointer, COP2_CONTROL_OFFSET(31))); // Set LZCR
            } else {
                allocateReg(_Rt_);

                gen.Mov(w0, m_regs[_Rt_].allocatedReg); // w0 = value to count leading bits of
                gen.Asr(w1, w0, 31);                    // value = ~value if the msb is set
                gen.Eor(w0, w0, w1);

                gen.Clz(w0, w0);                        // Count leading Zeros
                gen.Str(w0, MemOperand(contextPointer, COP2_DATA_OFFSET(31))); // Write result to LZCR
            }
            break;

        case 31:
            return;
    }

    if (m_regs[_Rt_].isConst()) {
        gen.Mov(w0, m_regs[_Rt_].val);
        gen.Str(w0, MemOperand(contextPointer, COP2_DATA_OFFSET(_Rd_)));
    } else {
        allocateReg(_Rt_);
        gen.Str(m_regs[_Rt_].allocatedReg, MemOperand(contextPointer, COP2_DATA_OFFSET(_Rd_)));
    }
}

static uint32_t MFC2Wrapper(int reg) { return PCSX::g_emulator->m_gte->MFC2(reg); }

void DynaRecCPU::recMFC2() { throw std::runtime_error("[Unimplemented] MFC2 instruction"); }

void DynaRecCPU::recCFC2() { throw std::runtime_error("[Unimplemented] CFC2 instruction"); }

void DynaRecCPU::recLWC2() { throw std::runtime_error("[Unimplemented] LWC2 instruction"); }

void DynaRecCPU::recSWC2() { throw std::runtime_error("[Unimplemented] SWC2 instruction"); }

#define GTE_FALLBACK(name)                                                                          \
    static void name##Wrapper(uint32_t instruction) { PCSX::g_emulator->m_gte->name(instruction); } \
                                                                                                    \
    void DynaRecCPU::rec##name() {                                                                  \
        gen.Mov(arg1, m_psxRegs.code);                                                              \
        call(name##Wrapper);                                                                        \
    }

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
