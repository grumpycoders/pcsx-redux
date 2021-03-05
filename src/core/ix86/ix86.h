/***************************************************************************
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
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

/*
 * ix86 definitions v0.5.1
 *  Authors: linuzappz <linuzappz@pcsx.net>
 *           alexey silinov
 */

#pragma once

// include basic types
#include "core/psxemulator.h"
#include "core/r3000a.h"

namespace PCSX {

class ix86 {
  public:
    // x86Flags defines
    static const uint32_t X86FLAG_FPU = 0x00000001;
    static const uint32_t X86FLAG_VME = 0x00000002;
    static const uint32_t X86FLAG_DEBUGEXT = 0x00000004;
    static const uint32_t X86FLAG_4MPAGE = 0x00000008;
    static const uint32_t X86FLAG_TSC = 0x00000010;
    static const uint32_t X86FLAG_MSR = 0x00000020;
    static const uint32_t X86FLAG_PAE = 0x00000040;
    static const uint32_t X86FLAG_MCHKXCP = 0x00000080;
    static const uint32_t X86FLAG_CMPXCHG8B = 0x00000100;
    static const uint32_t X86FLAG_APIC = 0x00000200;
    static const uint32_t X86FLAG_SYSENTER = 0x00000800;
    static const uint32_t X86FLAG_MTRR = 0x00001000;
    static const uint32_t X86FLAG_GPE = 0x00002000;
    static const uint32_t X86FLAG_MCHKARCH = 0x00004000;
    static const uint32_t X86FLAG_CMOV = 0x00008000;
    static const uint32_t X86FLAG_PAT = 0x00010000;
    static const uint32_t X86FLAG_PSE36 = 0x00020000;
    static const uint32_t X86FLAG_PN = 0x00040000;
    static const uint32_t X86FLAG_MMX = 0x00800000;
    static const uint32_t X86FLAG_FXSAVE = 0x01000000;
    static const uint32_t X86FLAG_SSE = 0x02000000;

    // x86EFlags defines

    static const uint32_t X86EFLAG_MMXEXT = 0x00400000;
    static const uint32_t X86EFLAG_3DNOWEXT = 0x40000000;
    static const uint32_t X86EFLAG_3DNOW = 0x80000000;

    /* general helpers */
    template <class T>
    void write(T val) {
        *(T*)m_x86Ptr = val;
        m_x86Ptr += sizeof(val);
    }
    void write8(uint8_t val) { write(val); }
    void write16(uint16_t val) { write(val); }
    void write32(uint32_t val) { write(val); }
    void write64(uint64_t val) { write(val); }

    enum mainRegister {
        EAX = 0,
        EBX = 3,
        ECX = 1,
        EDX = 2,
        ESI = 6,
        EDI = 7,
        EBP = 5,
        ESP = 4,
    };

    enum mmxRegister {
        MM0 = 0,
        MM1 = 1,
        MM2 = 2,
        MM3 = 3,
        MM4 = 4,
        MM5 = 5,
        MM6 = 6,
        MM7 = 7,
    };

    enum sseRegister {
        XMM0 = 0,
        XMM1 = 1,
        XMM2 = 2,
        XMM3 = 3,
        XMM4 = 4,
        XMM5 = 5,
        XMM6 = 6,
        XMM7 = 7,
    };

    void x86Init(int8_t* ptr);
    void x86Shutdown();
    int8_t* x86GetPtr() { return m_x86Ptr; }

    void x86SetJ8(unsigned slot);
    void x86SetJ32(unsigned slot);
    void x86Align(uintptr_t bytes);
    void NOP(unsigned bytes, int8_t* at = nullptr);

    /********************/
    /* IX86 intructions */
    /********************/

    /*
     * scale values:
     *  0 - *1
     *  1 - *2
     *  2 - *4
     *  3 - *8
     */

    ////////////////////////////////////
    // mov instructions                /
    ////////////////////////////////////

    /* mov r32 to r32 */
    void MOV32RtoR(mainRegister to, mainRegister from);
    /* mov r32 to m32 */
    void MOV32RtoM(uint32_t to, mainRegister from);
    /* mov m32 to r32 */
    void MOV32MtoR(mainRegister to, uint32_t from);
    /* mov [r32] to r32 */
    void MOV32RmtoR(mainRegister to, mainRegister from);
    /* mov [r32][r32*scale] to r32 */
    void MOV32RmStoR(mainRegister to, mainRegister from, mainRegister from2, unsigned scale);
    /* mov r32 to [r32] */
    void MOV32RtoRm(mainRegister to, mainRegister from);
    /* mov r32 to [r32][r32*scale] */
    void MOV32RtoRmS(mainRegister to, mainRegister to2, unsigned scale, mainRegister from);
    /* mov imm32 to r32 */
    void MOV32ItoR(mainRegister to, uint32_t from);
    /* mov imm32 to m32 */
    void MOV32ItoM(uint32_t to, uint32_t from);

    /* mov r16 to m16 */
    void MOV16RtoM(uint32_t to, mainRegister from);
    /* mov m16 to r16 */
    void MOV16MtoR(mainRegister to, uint32_t from);
    /* mov imm16 to m16 */
    void MOV16ItoM(uint32_t to, uint16_t from);

    /* mov r8 to m8 */
    void MOV8RtoM(uint32_t to, mainRegister from);
    /* mov m8 to r8 */
    void MOV8MtoR(mainRegister to, uint32_t from);
    /* mov imm8 to m8 */
    void MOV8ItoM(uint32_t to, uint8_t from);

    /* movsx r8 to r32 */
    void MOVSX32R8toR(mainRegister to, mainRegister from);
    /* movsx m8 to r32 */
    void MOVSX32M8toR(mainRegister to, uint32_t from);
    /* movsx r16 to r32 */
    void MOVSX32R16toR(mainRegister to, mainRegister from);
    /* movsx m16 to r32 */
    void MOVSX32M16toR(mainRegister to, uint32_t from);

    /* movzx r8 to r32 */
    void MOVZX32R8toR(mainRegister to, mainRegister from);
    /* movzx m8 to r32 */
    void MOVZX32M8toR(mainRegister to, uint32_t from);
    /* movzx r16 to r32 */
    void MOVZX32R16toR(mainRegister to, mainRegister from);
    /* movzx m16 to r32 */
    void MOVZX32M16toR(mainRegister to, uint32_t from);

    /* cmovne r32 to r32 */
    void CMOVNE32RtoR(mainRegister to, mainRegister from);
    /* cmovne m32 to r32*/
    void CMOVNE32MtoR(mainRegister to, uint32_t from);
    /* cmove r32 to r32*/
    void CMOVE32RtoR(mainRegister to, mainRegister from);
    /* cmove m32 to r32*/
    void CMOVE32MtoR(mainRegister to, uint32_t from);
    /* cmovg r32 to r32*/
    void CMOVG32RtoR(mainRegister to, mainRegister from);
    /* cmovg m32 to r32*/
    void CMOVG32MtoR(mainRegister to, uint32_t from);
    /* cmovge r32 to r32*/
    void CMOVGE32RtoR(mainRegister to, mainRegister from);
    /* cmovge m32 to r32*/
    void CMOVGE32MtoR(mainRegister to, uint32_t from);
    /* cmovl r32 to r32*/
    void CMOVL32RtoR(mainRegister to, mainRegister from);
    /* cmovl m32 to r32*/
    void CMOVL32MtoR(mainRegister to, uint32_t from);
    /* cmovle r32 to r32*/
    void CMOVLE32RtoR(mainRegister to, mainRegister from);
    /* cmovle m32 to r32*/
    void CMOVLE32MtoR(mainRegister to, uint32_t from);

    ////////////////////////////////////
    // arithmetic instructions         /
    ////////////////////////////////////

    /* add imm32 to r32 */
    void ADD32ItoR(mainRegister to, uint32_t from);
    /* add imm32 to m32 */
    void ADD32ItoM(uint32_t to, uint32_t from);
    /* add r32 to r32 */
    void ADD32RtoR(mainRegister to, mainRegister from);
    /* add r32 to m32 */
    void ADD32RtoM(uint32_t to, mainRegister from);
    /* add m32 to r32 */
    void ADD32MtoR(mainRegister to, uint32_t from);

    /* adc imm32 to r32 */
    void ADC32ItoR(mainRegister to, uint32_t from);
    /* adc r32 to r32 */
    void ADC32RtoR(mainRegister to, mainRegister from);
    /* adc m32 to r32 */
    void ADC32MtoR(mainRegister to, uint32_t from);

    /* inc r32 */
    void INC32R(mainRegister to);
    /* inc m32 */
    void INC32M(uint32_t to);

    /* sub imm32 to r32 */
    void SUB32ItoR(mainRegister to, uint32_t from);
    /* sub r32 to r32 */
    void SUB32RtoR(mainRegister to, mainRegister from);
    /* sub m32 to r32 */
    void SUB32MtoR(mainRegister to, uint32_t from);

    /* sbb imm32 to r32 */
    void SBB32ItoR(mainRegister to, uint32_t from);
    /* sbb r32 to r32 */
    void SBB32RtoR(mainRegister to, mainRegister from);
    /* sbb m32 to r32 */
    void SBB32MtoR(mainRegister to, uint32_t from);

    /* dec r32 */
    void DEC32R(mainRegister to);
    /* dec m32 */
    void DEC32M(uint32_t to);

    /* mul eax by r32 to edx:eax */
    void MUL32R(mainRegister from);
    /* mul eax by m32 to edx:eax */
    void MUL32M(uint32_t from);

    /* imul eax by r32 to edx:eax */
    void IMUL32R(mainRegister from);
    /* imul eax by m32 to edx:eax */
    void IMUL32M(uint32_t from);
    /* imul r32 by r32 to r32 */
    void IMUL32RtoR(mainRegister to, mainRegister from);

    /* div eax by r32 to edx:eax */
    void DIV32R(mainRegister from);
    /* div eax by m32 to edx:eax */
    void DIV32M(uint32_t from);

    /* idiv eax by r32 to edx:eax */
    void IDIV32R(mainRegister from);
    /* idiv eax by m32 to edx:eax */
    void IDIV32M(uint32_t from);

    ////////////////////////////////////
    // shifting instructions           /
    ////////////////////////////////////

    /* shl imm8 to r32 */
    void SHL32ItoR(mainRegister to, uint8_t from);
    /* shl cl to r32 */
    void SHL32CLtoR(mainRegister to);

    /* shr imm8 to r32 */
    void SHR32ItoR(mainRegister to, uint8_t from);
    /* shr cl to r32 */
    void SHR32CLtoR(mainRegister to);

    /* sar imm8 to r32 */
    void SAR32ItoR(mainRegister to, uint8_t from);
    /* sar cl to r32 */
    void SAR32CLtoR(mainRegister to);

    /* sal imm8 to r32 */
    void SAL32ItoR(mainRegister to, uint8_t from) { SHL32ItoR(to, from); }
    /* sal cl to r32 */
    void SAL32CLtoR(mainRegister to) { SHL32CLtoR(to); }

    // logical instructions

    /* or imm32 to r32 */
    void OR32ItoR(mainRegister to, uint32_t from);
    /* or imm32 to m32 */
    void OR32ItoM(uint32_t to, uint32_t from);
    /* or r32 to r32 */
    void OR32RtoR(mainRegister to, mainRegister from);
    /* or r32 to m32 */
    void OR32RtoM(uint32_t to, mainRegister from);
    /* or m32 to r32 */
    void OR32MtoR(mainRegister to, uint32_t from);

    /* xor imm32 to r32 */
    void XOR32ItoR(mainRegister to, uint32_t from);
    /* xor imm32 to m32 */
    void XOR32ItoM(uint32_t to, uint32_t from);
    /* xor r32 to r32 */
    void XOR32RtoR(mainRegister to, mainRegister from);
    /* xor r32 to m32 */
    void XOR32RtoM(uint32_t to, mainRegister from);
    /* xor m32 to r32 */
    void XOR32MtoR(mainRegister to, uint32_t from);

    /* and imm8 to r32 */
    void AND8ItoR32(mainRegister to, uint8_t from);
    /* and imm32 to r32 */
    void AND32ItoR(mainRegister to, uint32_t from);
    /* and imm32 to m32 */
    void AND32ItoM(uint32_t to, uint32_t from);
    /* and r32 to r32 */
    void AND32RtoR(mainRegister to, mainRegister from);
    /* and r32 to m32 */
    void AND32RtoM(uint32_t to, mainRegister from);
    /* and m32 to r32 */
    void AND32MtoR(mainRegister to, uint32_t from);

    /* not r32 */
    void NOT32R(mainRegister from);
    /* neg r32 */
    void NEG32R(mainRegister from);

    ////////////////////////////////////
    // jump instructions               /
    ////////////////////////////////////

    /* jmp rel8 */
    unsigned JMP8(uint8_t to);

    /* jmp rel32 */
    unsigned JMP32(uint32_t to);
    /* jmp r32 */
    void JMP32R(mainRegister to);

    /* je rel8 */
    unsigned JE8(uint8_t to);
    /* jz rel8 */
    unsigned JZ8(uint8_t to);
    /* jg rel8 */
    unsigned JG8(uint8_t to);
    /* jge rel8 */
    unsigned JGE8(uint8_t to);
    /* jl rel8 */
    unsigned JL8(uint8_t to);
    /* jle rel8 */
    unsigned JLE8(uint8_t to);
    /* jne rel8 */
    unsigned JNE8(uint8_t to);
    /* jnz rel8 */
    unsigned JNZ8(uint8_t to);
    /* jng rel8 */
    unsigned JNG8(uint8_t to);
    /* jnge rel8 */
    unsigned JNGE8(uint8_t to);
    /* jnl rel8 */
    unsigned JNL8(uint8_t to);
    /* jnle rel8 */
    unsigned JNLE8(uint8_t to);
    /* jo rel8 */
    unsigned JO8(uint8_t to);
    /* jno rel8 */
    unsigned JNO8(uint8_t to);

    /* je rel32 */
    unsigned JE32(uint32_t to);
    /* jz rel32 */
    unsigned JZ32(uint32_t to);
    /* jg rel32 */
    unsigned JG32(uint32_t to);
    /* jge rel32 */
    unsigned JGE32(uint32_t to);
    /* jl rel32 */
    unsigned JL32(uint32_t to);
    /* jle rel32 */
    unsigned JLE32(uint32_t to);
    /* jne rel32 */
    unsigned JNE32(uint32_t to);
    /* jnz rel32 */
    unsigned JNZ32(uint32_t to);
    /* jng rel32 */
    unsigned JNG32(uint32_t to);
    /* jnge rel32 */
    unsigned JNGE32(uint32_t to);
    /* jnl rel32 */
    unsigned JNL32(uint32_t to);
    /* jnle rel32 */
    unsigned JNLE32(uint32_t to);
    /* jo rel32 */
    unsigned JO32(uint32_t to);
    /* jno rel32 */
    unsigned JNO32(uint32_t to);

    /* call func */
    void CALLFunc(uint32_t func);  // based on CALL32
    /* call rel32 */
    void CALL32(uint32_t to);
    /* call r32 */
    void CALL32R(mainRegister to);
    /* call m32 */
    void CALL32M(uint32_t to);

    ////////////////////////////////////
    // misc instructions               /
    ////////////////////////////////////

    /* cmp imm32 to r32 */
    void CMP32ItoR(mainRegister to, uint32_t from);
    /* cmp imm32 to m32 */
    void CMP32ItoM(uint32_t to, uint32_t from);
    /* cmp r32 to r32 */
    void CMP32RtoR(mainRegister to, mainRegister from);
    /* cmp m32 to r32 */
    void CMP32MtoR(mainRegister to, uint32_t from);

    /* test imm32 to r32 */
    void TEST32ItoR(mainRegister to, uint32_t from);
    /* test r32 to r32 */
    void TEST32RtoR(mainRegister to, mainRegister from);
    /* sets r8 */
    void SETS8R(mainRegister to);
    /* setl r8 */
    void SETL8R(mainRegister to);
    /* setb r8 */
    void SETB8R(mainRegister to);

    /* cbw */
    void CBW();
    /* cwd */
    void CWD();
    /* cdq */
    void CDQ();

    /* push r32 */
    void PUSH32R(mainRegister from);
    /* push m32 */
    void PUSH32M(uint32_t from);
    /* push imm32 */
    void PUSH32I(uint32_t from);

    /* pop r32 */
    void POP32R(mainRegister from);

    /* pushad */
    void PUSHA32();
    /* popad */
    void POPA32();

    /* ret */
    void RET();

    /********************/
    /* FPU instructions */
    /********************/

    /* fild m32 to fpu reg stack */
    void FILD32(uint32_t from);
    /* fistp m32 from fpu reg stack */
    void FISTP32(uint32_t from);
    /* fld m32 to fpu reg stack */
    void FLD32(uint32_t from);
    /* fstp m32 from fpu reg stack */
    void FSTP32(uint32_t to);

    /* fldcw fpu control word from m16 */
    void FLDCW(uint32_t from);
    /* fstcw fpu control word to m16 */
    void FNSTCW(uint32_t to);

    /* fadd m32 to fpu reg stack */
    void FADD32(uint32_t from);
    /* fsub m32 to fpu reg stack */
    void FSUB32(uint32_t from);
    /* fmul m32 to fpu reg stack */
    void FMUL32(uint32_t from);
    /* fdiv m32 to fpu reg stack */
    void FDIV32(uint32_t from);
    /* fabs fpu reg stack */
    void FABS();
    /* fsqrt fpu reg stack */
    void FSQRT();
    /* fchs fpu reg stack */
    void FCHS();

    /********************/
    /* MMX instructions */
    /********************/

    // r64 = mm

    /* movq m64 to r64 */
    void MOVQMtoR(mmxRegister to, uint32_t from);
    /* movq r64 to m64 */
    void MOVQRtoM(uint32_t to, mmxRegister from);

    /* pand r64 to r64 */
    void PANDRtoR(mmxRegister to, mmxRegister from);
    /* pand m64 to r64 */
    void PANDMtoR(mmxRegister to, uint32_t from);

    /* pandn r64 to r64 */
    void PANDNRtoR(mmxRegister to, mmxRegister from);

    /* pandn r64 to r64 */
    void PANDNMtoR(mmxRegister to, uint32_t from);

    /* por r64 to r64 */
    void PORRtoR(mmxRegister to, mmxRegister from);
    /* por m64 to r64 */
    void PORMtoR(mmxRegister to, uint32_t from);

    /* pxor r64 to r64 */
    void PXORRtoR(mmxRegister to, mmxRegister from);
    /* pxor m64 to r64 */
    void PXORMtoR(mmxRegister to, uint32_t from);

    /* psllq r64 to r64 */
    void PSLLQRtoR(mmxRegister to, mmxRegister from);
    /* psllq m64 to r64 */
    void PSLLQMtoR(mmxRegister to, uint32_t from);
    /* psllq imm8 to r64 */
    void PSLLQItoR(mmxRegister to, uint8_t from);

    /* psrlq r64 to r64 */
    void PSRLQRtoR(mmxRegister to, mmxRegister from);
    /* psrlq m64 to r64 */
    void PSRLQMtoR(mmxRegister to, uint32_t from);
    /* psrlq imm8 to r64 */
    void PSRLQItoR(mmxRegister to, uint8_t from);

    /* paddusb r64 to r64 */
    void PADDUSBRtoR(mmxRegister to, mmxRegister from);
    /* paddusb m64 to r64 */
    void PADDUSBMtoR(mmxRegister to, uint32_t from);
    /* paddusw r64 to r64 */
    void PADDUSWRtoR(mmxRegister to, mmxRegister from);
    /* paddusw m64 to r64 */
    void PADDUSWMtoR(mmxRegister to, uint32_t from);

    /* paddb r64 to r64 */
    void PADDBRtoR(mmxRegister to, mmxRegister from);
    /* paddb m64 to r64 */
    void PADDBMtoR(mmxRegister to, uint32_t from);
    /* paddw r64 to r64 */
    void PADDWRtoR(mmxRegister to, mmxRegister from);
    /* paddw m64 to r64 */
    void PADDWMtoR(mmxRegister to, uint32_t from);
    /* paddd r64 to r64 */
    void PADDDRtoR(mmxRegister to, mmxRegister from);
    /* paddd m64 to r64 */
    void PADDDMtoR(mmxRegister to, uint32_t from);

    /* emms */
    void EMMS();
    void FEMMS();
    void BT32ItoR(mainRegister to, mainRegister from);
    void RCR32ItoR(mainRegister to, mainRegister from);

    // Basara:changed
    void PADDSBRtoR(mmxRegister to, mmxRegister from);
    void PADDSWRtoR(mmxRegister to, mmxRegister from);
    void PADDSDRtoR(mmxRegister to, mmxRegister from);
    void PSUBSBRtoR(mmxRegister to, mmxRegister from);
    void PSUBSWRtoR(mmxRegister to, mmxRegister from);
    void PSUBSDRtoR(mmxRegister to, mmxRegister from);

    void PSUBBRtoR(mmxRegister to, mmxRegister from);
    void PSUBWRtoR(mmxRegister to, mmxRegister from);
    void PSUBDRtoR(mmxRegister to, mmxRegister from);

    void PSUBUSBRtoR(mmxRegister to, mmxRegister from);
    void PSUBUSWRtoR(mmxRegister to, mmxRegister from);

    void PMAXSWRtoR(mmxRegister to, mmxRegister from);
    void PMINSWRtoR(mmxRegister to, mmxRegister from);

    void PCMPEQBRtoR(mmxRegister to, mmxRegister from);
    void PCMPEQWRtoR(mmxRegister to, mmxRegister from);
    void PCMPEQDRtoR(mmxRegister to, mmxRegister from);

    void PCMPGTBRtoR(mmxRegister to, mmxRegister from);
    void PCMPGTWRtoR(mmxRegister to, mmxRegister from);
    void PCMPGTDRtoR(mmxRegister to, mmxRegister from);

    void PSRLWItoR(mmxRegister to, uint8_t from);
    void PSRLDItoR(mmxRegister to, uint8_t from);
    void PSLLWItoR(mmxRegister to, uint8_t from);
    void PSLLDItoR(mmxRegister to, uint8_t from);
    void PSRAWItoR(mmxRegister to, uint8_t from);
    void PSRADItoR(mmxRegister to, uint8_t from);

    // Added:basara 11.01.2003
    void FCOMP32(uint32_t from);
    void FNSTSWtoAX();
    void SETNZ8R(mainRegister to);

    // Added:basara 14.01.2003
    void PFCMPEQMtoR(sseRegister to, uint32_t from);
    void PFCMPGTMtoR(sseRegister to, uint32_t from);
    void PFCMPGEMtoR(sseRegister to, uint32_t from);

    void PFADDMtoR(sseRegister to, uint32_t from);
    void PFADDRtoR(sseRegister to, sseRegister from);

    void PFSUBMtoR(sseRegister to, uint32_t from);
    void PFSUBRtoR(sseRegister to, sseRegister from);

    void PFMULMtoR(sseRegister to, uint32_t from);
    void PFMULRtoR(sseRegister to, sseRegister from);

    void PFRCPMtoR(sseRegister to, uint32_t from);
    void PFRCPRtoR(sseRegister to, sseRegister from);
    void PFRCPIT1RtoR(sseRegister to, sseRegister from);
    void PFRCPIT2RtoR(sseRegister to, sseRegister from);

    void PFRSQRTRtoR(sseRegister to, sseRegister from);
    void PFRSQIT1RtoR(sseRegister to, sseRegister from);

    void PF2IDMtoR(sseRegister to, uint32_t from);
    void PF2IDRtoR(sseRegister to, sseRegister from);
    void PI2FDMtoR(sseRegister to, uint32_t from);
    void PI2FDRtoR(sseRegister to, sseRegister from);

    void PFMAXMtoR(sseRegister to, uint32_t from);
    void PFMAXRtoR(sseRegister to, sseRegister from);
    void PFMINMtoR(sseRegister to, uint32_t from);
    void PFMINRtoR(sseRegister to, sseRegister from);

    void MOVDMtoR(mmxRegister to, uint32_t from);
    void MOVDRtoM(uint32_t to, mmxRegister from);
    void MOVD32RtoR(mmxRegister to, mainRegister from);
    void MOVD64RtoR(mainRegister to, mmxRegister from);

    void MOVQRtoR(mmxRegister to, mmxRegister from);

    // if to==from MMLO=MMHI
    void PUNPCKHDQRtoR(mmxRegister to, mmxRegister from);

    // if to==from MMHI=MMLO
    void PUNPCKLDQRtoR(mmxRegister to, mmxRegister from);

    /*
            SSE intructions
    */
    void MOVAPSMtoR(sseRegister to, sseRegister from);
    void MOVAPSRtoM(sseRegister to, sseRegister from);
    void MOVAPSRtoR(sseRegister to, sseRegister from);

    void ORPSMtoR(sseRegister to, sseRegister from);
    void ORPSRtoR(sseRegister to, sseRegister from);

    void XORPSMtoR(sseRegister to, sseRegister from);
    void XORPSRtoR(sseRegister to, sseRegister from);

    void ANDPSMtoR(sseRegister to, sseRegister from);
    void ANDPSRtoR(sseRegister to, sseRegister from);

  private:
    static const unsigned DISP32 = 5;

    /* private helpers */
    void ModRM(unsigned mod, unsigned rm, unsigned reg) { write8((mod << 6) | (rm << 3) | (reg)); }
    void SibSB(unsigned ss, unsigned rm, unsigned index) { write8((ss << 6) | (rm << 3) | (index)); }
    void SET8R(uint8_t cc, uint8_t to) {
        write8(0x0F);
        write8(cc);
        write8((0xC0) | (to));
    }
    unsigned J8Rel(uint8_t cc, uint8_t to) {
        static const unsigned arraySize = sizeof(m_j8Ptr) / sizeof(m_j8Ptr[0]);
        write8(cc);
        write8(to);
        if (to != 0) return arraySize;
        uint8_t* ptr = reinterpret_cast<uint8_t*>(m_x86Ptr - 1);
        for (unsigned i = 0; i < arraySize; i++) {
            if (m_j8Ptr[i] == NULL) {
                m_j8Ptr[i] = ptr;
                return i;
            }
        }

        abort();
        return arraySize;
    }
    unsigned J32Rel(uint8_t cc, uint32_t to) {
        static const unsigned arraySize = sizeof(m_j32Ptr) / sizeof(m_j32Ptr[0]);
        write8(0x0F);
        write8(cc);
        write32(to);
        if (to != 0) return arraySize;
        uint32_t* ptr = reinterpret_cast<uint32_t*>(m_x86Ptr - 4);
        for (unsigned i = 0; i < arraySize; i++) {
            if (m_j32Ptr[i] == NULL) {
                m_j32Ptr[i] = ptr;
                return i;
            }
        }

        abort();
        return arraySize;
    }
    void CMOV32RtoR(uint8_t cc, mainRegister to, mainRegister from) {
        write8(0x0F);
        write8(cc);
        ModRM(3, to, from);
    }
    void CMOV32MtoR(uint8_t cc, mainRegister to, uint32_t from) {
        write8(0x0F);
        write8(cc);
        ModRM(0, to, DISP32);
        write32(from);
    }

    int8_t* m_x86Ptr;
    uint8_t* m_j8Ptr[32];
    uint32_t* m_j32Ptr[32];
};

}  // namespace PCSX
