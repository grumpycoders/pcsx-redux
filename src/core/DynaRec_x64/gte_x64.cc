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
#define COP2_CONTROL_OFFSET(reg) ((uintptr_t) & m_regs.CP2C.r[(reg)] - (uintptr_t)this)
#define COP2_DATA_OFFSET(reg) ((uintptr_t) & m_regs.CP2D.r[(reg)] - (uintptr_t)this)

void DynaRecCPU::recCOP2(uint32_t code) {
    const auto func = m_recGTE[m_regs.code & 0x3F];  // Look up the opcode in our decoding LUT
    (*this.*func)(code);                             // Jump into the handler to recompile it
}

void DynaRecCPU::recGTEMove(uint32_t code) {
    switch (_Rs_) {
        case 0:
            recMFC2(code);
            break;
        case 2:
            recCFC2(code);
            break;
        case 4:
            recMTC2(code);
            break;
        case 6:
            recCTC2(code);
            break;
        default:
            recUnknown(code);
            break;
    }
}

void DynaRecCPU::recCTC2(uint32_t code) {
    if (m_gprs[_Rt_].isConst()) {
        switch (_Rd_) {
            case 4:  // These registers are signed 16-bit values. Reading from them returns their value sign-extended to
                     // 32 bits
            case 12:
            case 20:
            case 26:
            case 27:
            case 29:
            case 30:
                gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(_Rd_)], (uint32_t)(int16_t)m_gprs[_Rt_].val);
                break;

            case 31: {  // Write to FLAG - Set low 12 bits to 0 and fix up the error flag
                uint32_t value = m_gprs[_Rt_].val & 0x7ffff000;
                if ((value & 0x7f87e000) != 0) {
                    value |= 0x80000000;
                }
                gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(31)], value);
                break;
            }

            default:
                gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(_Rd_)], m_gprs[_Rt_].val);
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
                gen.movsx(eax, m_gprs[_Rt_].allocatedReg.cvt16());  // Sign extend value from 16 to 32 bits
                gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(_Rd_)], eax);
                break;

            case 31:  // Write to FLAG - Set low 12 bits to 0 and fix up the error flag
                gen.mov(ecx, m_gprs[_Rt_].allocatedReg);
                gen.and_(ecx, 0x7ffff000);
                gen.lea(eax, dword[rcx - 0x80000000]);
                gen.test(m_gprs[_Rt_].allocatedReg, 0x7f87e000);
                gen.cmove(eax, ecx);
                gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(31)], eax);
                break;

            default:
                gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(_Rd_)], m_gprs[_Rt_].allocatedReg);
                break;
        }
    }
}

void DynaRecCPU::recMTC2(uint32_t code) {
    switch (_Rd_) {
        case 15:                                                         // SXYP
            gen.mov(rax, qword[contextPointer + COP2_DATA_OFFSET(13)]);  // SXY0 = SXY1 and SXY1 = SXY2
            gen.mov(qword[contextPointer + COP2_DATA_OFFSET(12)], rax);

            // SXY2 = val
            if (m_gprs[_Rt_].isConst()) {
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(14)], m_gprs[_Rt_].val);
            } else {
                allocateReg(_Rt_);
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(14)], m_gprs[_Rt_].allocatedReg);
            }
            return;

        case 28:                           // IRGB
            if (m_gprs[_Rt_].isConst()) {  // Calculate IR1/IR2/IR3 values and write them back
                const auto value = m_gprs[_Rt_].val;

                const auto IR1 = (value & 0x1f) << 7;
                const auto IR2 = (value & 0x3e0) << 2;
                const auto IR3 = (value & 0x7c00) >> 3;

                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(9)], IR1);
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(10)], IR2);
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(11)], IR3);
            } else {
                allocateReg(_Rt_);
                gen.mov(eax, m_gprs[_Rt_].allocatedReg);

                gen.and_(eax, 0x1f);  // Calculate IR1
                gen.shl(eax, 7);
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(9)], eax);

                gen.lea(eax, dword[4 * m_gprs[_Rt_].allocatedReg]);  // Calculate IR2
                gen.and_(eax, 0xf80);  // The above lea shifted eax by 2 first, so we adjust the mask
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(10)], eax);

                gen.mov(eax, m_gprs[_Rt_].allocatedReg);  // Calculate IR3
                gen.shr(eax, 3);
                gen.and_(eax, 0xf80);
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(11)], eax);
            }

            break;

        case 30:
            if (m_gprs[_Rt_].isConst()) {
                const auto result = PCSX::GTE::countLeadingBits(m_gprs[_Rt_].val);
                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(31)], result);  // Set LZCR
            } else {
                allocateReg(_Rt_);

                gen.mov(eax, m_gprs[_Rt_].allocatedReg);  // eax = value to count leading bits of
                gen.mov(edx, eax);                        // value = ~value if the msb is set
                gen.sar(edx, 31);
                gen.xor_(eax, edx);

                if (gen.hasLZCNT) {  // Count leading zeroes (Return 32 if the input is zero)
                    gen.lzcnt(eax, eax);
                } else {                // If our CPU doesn't have LZCNT
                    gen.bsr(eax, eax);  // eax = 31 - CLZ(value)
                    gen.mov(edx, 63);   // Set eax to 63 if the input was 0
                    gen.cmovz(eax, edx);
                    gen.xor_(eax, 31);  // Subtract the value from 31
                }

                gen.mov(dword[contextPointer + COP2_DATA_OFFSET(31)], eax);  // Write result to LZCR
            }
            break;

        case 31:
            return;
    }

    if (m_gprs[_Rt_].isConst()) {
        gen.mov(dword[contextPointer + COP2_DATA_OFFSET(_Rd_)], m_gprs[_Rt_].val);
    } else {
        allocateReg(_Rt_);
        gen.mov(dword[contextPointer + COP2_DATA_OFFSET(_Rd_)], m_gprs[_Rt_].allocatedReg);
    }
}

static uint32_t MFC2Wrapper(int reg) { return PCSX::g_emulator->m_gte->MFC2(reg); }

// Note: For IRGB/ORGB this will generate a call instruction. Only use if you do not care about a call happening
void DynaRecCPU::loadGTEDataRegister(Reg32 dest, int index) {
    switch (index) {
        case 1:
        case 3:
        case 5:
        case 8:
        case 9:
        case 10:
        case 11:
            gen.movsx(dest, word[contextPointer + COP2_DATA_OFFSET(index)]);
            break;

        case 7:
        case 16:
        case 17:
        case 18:
        case 19:
            gen.movzx(dest, word[contextPointer + COP2_DATA_OFFSET(index)]);
            break;

        case 15:  // Return SXY2 from SXYP
            gen.mov(dest, dword[contextPointer + COP2_DATA_OFFSET(14)]);
            break;

        case 28:
        case 29:  // Fallback for IRGB/ORGB
            gen.mov(arg1, index);
            call(MFC2Wrapper);
            gen.mov(dest, eax);
            break;

        default:
            gen.mov(dest, dword[contextPointer + COP2_DATA_OFFSET(index)]);
            break;
    }
}

void DynaRecCPU::recMFC2(uint32_t code) {
    if (!_Rt_) return;

    const auto loadDelayDependency = getLoadDelayDependencyType(_Rt_);
    if (loadDelayDependency != LoadDelayDependencyType::NoDependency) {
        loadGTEDataRegister(eax, _Rd_);

        if (loadDelayDependency == LoadDelayDependencyType::DependencyAcrossBlocks) {
            const auto delayedLoadValueOffset = (uintptr_t)&m_runtimeLoadDelay.value - (uintptr_t)this;
            const auto isActiveOffset = (uintptr_t)&m_runtimeLoadDelay.active - (uintptr_t)this;
            const auto indexOffset = (uintptr_t)&m_runtimeLoadDelay.index - (uintptr_t)this;
            gen.mov(dword[contextPointer + delayedLoadValueOffset], eax);
            gen.mov(Xbyak::util::byte[contextPointer + isActiveOffset], 1);
            gen.mov(dword[contextPointer + indexOffset], _Rt_);
        } else {
            auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
            const auto delayedLoadValueOffset = (uintptr_t)&delayedLoad.value - (uintptr_t)this;
            delayedLoad.index = _Rt_;
            gen.mov(dword[contextPointer + delayedLoadValueOffset], eax);
        }
        return;
    }

    // If we won't emulate the load delay, make sure to cancel any pending loads that might trample the value
    maybeCancelDelayedLoad(_Rt_);
    allocateRegWithoutLoad(_Rt_);
    m_gprs[_Rt_].setWriteback(true);

    switch (_Rd_) {
        // Fallback for IRGB/ORGB. Can't use loadGTEDataRegister for these because the call might unallocate $rt
        case 28:
        case 29:
            gen.mov(arg1, _Rd_);
            call(MFC2Wrapper);

            allocateRegWithoutLoad(_Rt_);  // Reallocate the reg in case the call thrashed it
            m_gprs[_Rt_].setWriteback(true);
            gen.mov(m_gprs[_Rt_].allocatedReg, eax);
            break;

        default:
            loadGTEDataRegister(m_gprs[_Rt_].allocatedReg, _Rd_);
            break;
    }
}

void DynaRecCPU::recCFC2(uint32_t code) {
    if (!_Rt_) return;

    const auto loadDelayDependency = getLoadDelayDependencyType(_Rt_);
    if (loadDelayDependency != LoadDelayDependencyType::NoDependency) {
        gen.mov(eax, dword[contextPointer + COP2_CONTROL_OFFSET(_Rd_)]);

        if (loadDelayDependency == LoadDelayDependencyType::DependencyAcrossBlocks) {
            const auto delayedLoadValueOffset = (uintptr_t)&m_runtimeLoadDelay.value - (uintptr_t)this;
            const auto isActiveOffset = (uintptr_t)&m_runtimeLoadDelay.active - (uintptr_t)this;
            const auto indexOffset = (uintptr_t)&m_runtimeLoadDelay.index - (uintptr_t)this;
            gen.mov(dword[contextPointer + delayedLoadValueOffset], eax);
            gen.mov(Xbyak::util::byte[contextPointer + isActiveOffset], 1);
            gen.mov(dword[contextPointer + indexOffset], _Rt_);
        } else {
            auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
            const auto delayedLoadValueOffset = (uintptr_t)&delayedLoad.value - (uintptr_t)this;
            delayedLoad.index = _Rt_;
            gen.mov(dword[contextPointer + delayedLoadValueOffset], eax);
        }
    } else {
        // If we won't emulate the load delay, make sure to cancel any pending loads that might trample the value
        maybeCancelDelayedLoad(_Rt_);
        allocateRegWithoutLoad(_Rt_);
        m_gprs[_Rt_].setWriteback(true);

        gen.mov(m_gprs[_Rt_].allocatedReg, dword[contextPointer + COP2_CONTROL_OFFSET(_Rd_)]);
    }
}

void DynaRecCPU::recLWC2(uint32_t code) {
    if (m_gprs[_Rs_].isConst()) {  // Store address in arg2
        gen.mov(arg2, m_gprs[_Rs_].val + _Imm_);
    } else {
        allocateReg(_Rs_);
        gen.moveAndAdd(arg2, m_gprs[_Rs_].allocatedReg, _Imm_);
    }

    callMemoryFunc(&PCSX::Memory::read32);
    switch (_Rt_) {
        case 15:                                                         // SXYP
            gen.mov(rcx, qword[contextPointer + COP2_DATA_OFFSET(13)]);  // SXY0 = SXY1 and SXY1 = SXY2
            gen.mov(qword[contextPointer + COP2_DATA_OFFSET(12)], rcx);
            gen.mov(dword[contextPointer + COP2_DATA_OFFSET(14)], eax);  // SXY2 = val
            return;

        case 28:  // IRGB
            gen.mov(ecx, eax);

            gen.and_(ecx, 0x1f);  // Calculate IR1
            gen.shl(ecx, 7);
            gen.mov(dword[contextPointer + COP2_DATA_OFFSET(9)], ecx);

            gen.lea(ecx, dword[4 * rax]);  // Calculate IR2
            gen.and_(ecx, 0xf80);          // The above lea shifted eax by 2 first, so we adjust the mask
            gen.mov(dword[contextPointer + COP2_DATA_OFFSET(10)], ecx);

            gen.mov(ecx, eax);  // Calculate IR3
            gen.shr(ecx, 3);
            gen.and_(ecx, 0xf80);
            gen.mov(dword[contextPointer + COP2_DATA_OFFSET(11)], ecx);
            break;

        case 30:
            gen.mov(edx, eax);  // value = ~value if the msb is set
            gen.sar(edx, 31);
            gen.xor_(eax, edx);

            if (gen.hasLZCNT) {  // Count leading zeroes (Return 32 if the input is zero)
                gen.lzcnt(eax, eax);
            } else {                // If our CPU doesn't have LZCNT
                gen.bsr(eax, eax);  // eax = 31 - CLZ(value)
                gen.mov(edx, 63);   // Set eax to 63 if the input was 0
                gen.cmovz(eax, edx);
                gen.xor_(eax, 31);  // Subtract the value from 31
            }

            gen.mov(dword[contextPointer + COP2_DATA_OFFSET(31)], eax);  // Write result to LZCR
            break;
    }

    if (_Rt_ != 31) {
        gen.mov(dword[contextPointer + COP2_DATA_OFFSET(_Rt_)], eax);
    }
}

void DynaRecCPU::recSWC2(uint32_t code) {
    loadGTEDataRegister(arg3, _Rt_);  // Load the register we'll write to memory in arg3

    // Address in arg2
    if (m_gprs[_Rs_].isConst()) {
        gen.mov(arg2, m_gprs[_Rs_].val + _Imm_);
    } else {
        allocateReg(_Rs_);
        gen.moveAndAdd(arg2, m_gprs[_Rs_].allocatedReg, _Imm_);
    }

    callMemoryFunc(&PCSX::Memory::write32);
}

template <bool isAVSZ4>
void DynaRecCPU::recAVSZ(uint32_t code) {
    Xbyak::Label noOverflow, label1, end, checkIfBelowLim, notBelowLim;

    constexpr Reg32 flag = arg1;  // Register for FLAG
    const Reg64 scaleFactor = arg2.cvt64();

    gen.xor_(flag, flag);  // Set FLAG to 0

    if constexpr (isAVSZ4) {  // Load SZF4 into scaleFactor if this is AVSZ4
        gen.movsx(scaleFactor, word[contextPointer + COP2_CONTROL_OFFSET(30)]);
    } else {  // Otherwise, load SZF3
        gen.movsx(scaleFactor, word[contextPointer + COP2_CONTROL_OFFSET(29)]);
    }

    // eax = SZ1 + SZ2 + SZ3
    gen.movzx(eax, word[contextPointer + COP2_DATA_OFFSET(17)]);
    gen.movzx(arg3, word[contextPointer + COP2_DATA_OFFSET(18)]);
    gen.add(rax, arg3.cvt64());
    gen.movzx(arg3, word[contextPointer + COP2_DATA_OFFSET(19)]);
    gen.add(rax, arg3.cvt64());

    // eax += SZ0 for AVSZ4
    if constexpr (isAVSZ4) {
        gen.movzx(arg3.cvt64(), word[contextPointer + COP2_DATA_OFFSET(16)]);
        gen.add(rax, arg3.cvt64());
    }

    // rax = (Sum of Z values) * scaleFactor
    gen.imul(rax, scaleFactor);
    // Set MAC0
    gen.mov(dword[contextPointer + COP2_DATA_OFFSET(24)], eax);
    // Calculate flags if MAC0 result is larger than 31 bits
    gen.cmp(rax, 0x7fffffff);
    gen.jle(label1);
    gen.mov(flag, (1 << 31) | (1 << 16));
    gen.jmp(noOverflow);

    gen.L(label1);
    gen.cmp(rax, 0x80000000);
    gen.jge(noOverflow);
    gen.mov(flag, (1 << 31) | (1 << 15));
    gen.L(noOverflow);

    gen.shr(rax, 12);
    // Saturate eax to [0, 0xffff] and set OTZ to the saturated value

    gen.cmp(eax, 0x10000);    // Check if above 0xffff
    gen.jl(checkIfBelowLim);  // If not, check if below
    // Set FLAG, set OTZ to 0xffff is MAC0 > 0xffff
    gen.or_(flag, (1 << 31) | (1 << 18));
    gen.mov(word[contextPointer + COP2_DATA_OFFSET(7)], 0xffff);
    gen.jmp(end);

    gen.L(checkIfBelowLim);  // Check if below 0
    gen.test(eax, eax);
    gen.jns(notBelowLim);
    // Set FLAG, and set OTZ to 0 if MAC0 < 0
    gen.or_(flag, (1 << 31) | (1 << 18));
    gen.mov(word[contextPointer + COP2_DATA_OFFSET(7)], 0);
    gen.jmp(end);

    gen.L(notBelowLim);  // handle the case where eax doesn't need to be saturated
    gen.mov(word[contextPointer + COP2_DATA_OFFSET(7)], ax);
    gen.L(end);
    gen.mov(dword[contextPointer + COP2_CONTROL_OFFSET(31)], flag);  // Writeback FLAG
}

void DynaRecCPU::recAVSZ3(uint32_t code) { recAVSZ<false>(code); }
void DynaRecCPU::recAVSZ4(uint32_t code) { recAVSZ<true>(code); }

#define GTE_FALLBACK(name)                      \
    void DynaRecCPU::rec##name(uint32_t code) { \
        gen.mov(arg2, code);                    \
        callGTEFunc(&PCSX::GTE::name);          \
    }

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

#undef GTE_FALLBACK
#endif  // DYNAREC_X86_64
