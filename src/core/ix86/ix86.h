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

#ifndef __IX86_H__
#define __IX86_H__

// include basic types
#include "core/psxemulator.h"
#include "core/psxhle.h"
#include "core/r3000a.h"

// x86Flags defines
#define X86FLAG_FPU 0x00000001
#define X86FLAG_VME 0x00000002
#define X86FLAG_DEBUGEXT 0x00000004
#define X86FLAG_4MPAGE 0x00000008
#define X86FLAG_TSC 0x00000010
#define X86FLAG_MSR 0x00000020
#define X86FLAG_PAE 0x00000040
#define X86FLAG_MCHKXCP 0x00000080
#define X86FLAG_CMPXCHG8B 0x00000100
#define X86FLAG_APIC 0x00000200
#define X86FLAG_SYSENTER 0x00000800
#define X86FLAG_MTRR 0x00001000
#define X86FLAG_GPE 0x00002000
#define X86FLAG_MCHKARCH 0x00004000
#define X86FLAG_CMOV 0x00008000
#define X86FLAG_PAT 0x00010000
#define X86FLAG_PSE36 0x00020000
#define X86FLAG_PN 0x00040000
#define X86FLAG_MMX 0x00800000
#define X86FLAG_FXSAVE 0x01000000
#define X86FLAG_SSE 0x02000000

// x86EFlags defines

#define X86EFLAG_MMXEXT 0x00400000
#define X86EFLAG_3DNOWEXT 0x40000000
#define X86EFLAG_3DNOW 0x80000000

/* general defines */
#define write8(val)     \
    *(uint8_t*)g_x86Ptr = val; \
    g_x86Ptr++;
#define write16(val)     \
    *(uint16_t*)g_x86Ptr = val; \
    g_x86Ptr += 2;
#define write32(val)     \
    *(uint32_t*)g_x86Ptr = val; \
    g_x86Ptr += 4;
#define write64(val)     \
    *(uint64_t*)g_x86Ptr = val; \
    g_x86Ptr += 8;

#define EAX 0
#define EBX 3
#define ECX 1
#define EDX 2
#define ESI 6
#define EDI 7
#define EBP 5
#define ESP 4

#define MM0 0
#define MM1 1
#define MM2 2
#define MM3 3
#define MM4 4
#define MM5 5
#define MM6 6
#define MM7 7

#define XMM0 0
#define XMM1 1
#define XMM2 2
#define XMM3 3
#define XMM4 4
#define XMM5 5
#define XMM6 6
#define XMM7 7

extern int8_t* g_x86Ptr;
extern uint8_t* g_j8Ptr[32];
extern uint32_t* g_j32Ptr[32];

void x86Init();
void x86SetPtr(int8_t* ptr);
void x86Shutdown();

void x86SetJ8(uint8_t* j8);
void x86SetJ32(uint32_t* j32);
void x86Align(int bytes);

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
void MOV32RtoR(int to, int from);
/* mov r32 to m32 */
void MOV32RtoM(uint32_t to, int from);
/* mov m32 to r32 */
void MOV32MtoR(int to, uint32_t from);
/* mov [r32] to r32 */
void MOV32RmtoR(int to, int from);
/* mov [r32][r32*scale] to r32 */
void MOV32RmStoR(int to, int from, int from2, int scale);
/* mov r32 to [r32] */
void MOV32RtoRm(int to, int from);
/* mov r32 to [r32][r32*scale] */
void MOV32RtoRmS(int to, int to2, int scale, int from);
/* mov imm32 to r32 */
void MOV32ItoR(int to, uint32_t from);
/* mov imm32 to m32 */
void MOV32ItoM(uint32_t to, uint32_t from);

/* mov r16 to m16 */
void MOV16RtoM(uint32_t to, int from);
/* mov m16 to r16 */
void MOV16MtoR(int to, uint32_t from);
/* mov imm16 to m16 */
void MOV16ItoM(uint32_t to, uint16_t from);

/* mov r8 to m8 */
void MOV8RtoM(uint32_t to, int from);
/* mov m8 to r8 */
void MOV8MtoR(int to, uint32_t from);
/* mov imm8 to m8 */
void MOV8ItoM(uint32_t to, uint8_t from);

/* movsx r8 to r32 */
void MOVSX32R8toR(int to, int from);
/* movsx m8 to r32 */
void MOVSX32M8toR(int to, uint32_t from);
/* movsx r16 to r32 */
void MOVSX32R16toR(int to, int from);
/* movsx m16 to r32 */
void MOVSX32M16toR(int to, uint32_t from);

/* movzx r8 to r32 */
void MOVZX32R8toR(int to, int from);
/* movzx m8 to r32 */
void MOVZX32M8toR(int to, uint32_t from);
/* movzx r16 to r32 */
void MOVZX32R16toR(int to, int from);
/* movzx m16 to r32 */
void MOVZX32M16toR(int to, uint32_t from);

/* cmovne r32 to r32 */
void CMOVNE32RtoR(int to, int from);
/* cmovne m32 to r32*/
void CMOVNE32MtoR(int to, uint32_t from);
/* cmove r32 to r32*/
void CMOVE32RtoR(int to, int from);
/* cmove m32 to r32*/
void CMOVE32MtoR(int to, uint32_t from);
/* cmovg r32 to r32*/
void CMOVG32RtoR(int to, int from);
/* cmovg m32 to r32*/
void CMOVG32MtoR(int to, uint32_t from);
/* cmovge r32 to r32*/
void CMOVGE32RtoR(int to, int from);
/* cmovge m32 to r32*/
void CMOVGE32MtoR(int to, uint32_t from);
/* cmovl r32 to r32*/
void CMOVL32RtoR(int to, int from);
/* cmovl m32 to r32*/
void CMOVL32MtoR(int to, uint32_t from);
/* cmovle r32 to r32*/
void CMOVLE32RtoR(int to, int from);
/* cmovle m32 to r32*/
void CMOVLE32MtoR(int to, uint32_t from);

////////////////////////////////////
// arithmetic instructions         /
////////////////////////////////////

/* add imm32 to r32 */
void ADD32ItoR(int to, uint32_t from);
/* add imm32 to m32 */
void ADD32ItoM(uint32_t to, uint32_t from);
/* add r32 to r32 */
void ADD32RtoR(int to, int from);
/* add r32 to m32 */
void ADD32RtoM(uint32_t to, int from);
/* add m32 to r32 */
void ADD32MtoR(int to, uint32_t from);

/* adc imm32 to r32 */
void ADC32ItoR(int to, uint32_t from);
/* adc r32 to r32 */
void ADC32RtoR(int to, int from);
/* adc m32 to r32 */
void ADC32MtoR(int to, uint32_t from);

/* inc r32 */
void INC32R(int to);
/* inc m32 */
void INC32M(uint32_t to);

/* sub imm32 to r32 */
void SUB32ItoR(int to, uint32_t from);
/* sub r32 to r32 */
void SUB32RtoR(int to, int from);
/* sub m32 to r32 */
void SUB32MtoR(int to, uint32_t from);

/* sbb imm32 to r32 */
void SBB32ItoR(int to, uint32_t from);
/* sbb r32 to r32 */
void SBB32RtoR(int to, int from);
/* sbb m32 to r32 */
void SBB32MtoR(int to, uint32_t from);

/* dec r32 */
void DEC32R(int to);
/* dec m32 */
void DEC32M(uint32_t to);

/* mul eax by r32 to edx:eax */
void MUL32R(int from);
/* mul eax by m32 to edx:eax */
void MUL32M(uint32_t from);

/* imul eax by r32 to edx:eax */
void IMUL32R(int from);
/* imul eax by m32 to edx:eax */
void IMUL32M(uint32_t from);
/* imul r32 by r32 to r32 */
void IMUL32RtoR(int to, int from);

/* div eax by r32 to edx:eax */
void DIV32R(int from);
/* div eax by m32 to edx:eax */
void DIV32M(uint32_t from);

/* idiv eax by r32 to edx:eax */
void IDIV32R(int from);
/* idiv eax by m32 to edx:eax */
void IDIV32M(uint32_t from);

////////////////////////////////////
// shifting instructions           /
////////////////////////////////////

/* shl imm8 to r32 */
void SHL32ItoR(int to, uint8_t from);
/* shl cl to r32 */
void SHL32CLtoR(int to);

/* shr imm8 to r32 */
void SHR32ItoR(int to, uint8_t from);
/* shr cl to r32 */
void SHR32CLtoR(int to);

/* sar imm8 to r32 */
void SAR32ItoR(int to, uint8_t from);
/* sar cl to r32 */
void SAR32CLtoR(int to);

/* sal imm8 to r32 */
#define SAL32ItoR SHL32ItoR
/* sal cl to r32 */
#define SAL32CLtoR SHL32CLtoR

// logical instructions

/* or imm32 to r32 */
void OR32ItoR(int to, uint32_t from);
/* or imm32 to m32 */
void OR32ItoM(uint32_t to, uint32_t from);
/* or r32 to r32 */
void OR32RtoR(int to, int from);
/* or r32 to m32 */
void OR32RtoM(uint32_t to, int from);
/* or m32 to r32 */
void OR32MtoR(int to, uint32_t from);

/* xor imm32 to r32 */
void XOR32ItoR(int to, uint32_t from);
/* xor imm32 to m32 */
void XOR32ItoM(uint32_t to, uint32_t from);
/* xor r32 to r32 */
void XOR32RtoR(int to, int from);
/* xor r32 to m32 */
void XOR32RtoM(uint32_t to, int from);
/* xor m32 to r32 */
void XOR32MtoR(int to, uint32_t from);

/* and imm32 to r32 */
void AND32ItoR(int to, uint32_t from);
/* and imm32 to m32 */
void AND32ItoM(uint32_t to, uint32_t from);
/* and r32 to r32 */
void AND32RtoR(int to, int from);
/* and r32 to m32 */
void AND32RtoM(uint32_t to, int from);
/* and m32 to r32 */
void AND32MtoR(int to, uint32_t from);

/* not r32 */
void NOT32R(int from);
/* neg r32 */
void NEG32R(int from);

////////////////////////////////////
// jump instructions               /
////////////////////////////////////

/* jmp rel8 */
uint8_t* JMP8(uint8_t to);

/* jmp rel32 */
uint32_t* JMP32(uint32_t to);
/* jmp r32 */
void JMP32R(int to);

/* je rel8 */
uint8_t* JE8(uint8_t to);
/* jz rel8 */
uint8_t* JZ8(uint8_t to);
/* jg rel8 */
uint8_t* JG8(uint8_t to);
/* jge rel8 */
uint8_t* JGE8(uint8_t to);
/* jl rel8 */
uint8_t* JL8(uint8_t to);
/* jle rel8 */
uint8_t* JLE8(uint8_t to);
/* jne rel8 */
uint8_t* JNE8(uint8_t to);
/* jnz rel8 */
uint8_t* JNZ8(uint8_t to);
/* jng rel8 */
uint8_t* JNG8(uint8_t to);
/* jnge rel8 */
uint8_t* JNGE8(uint8_t to);
/* jnl rel8 */
uint8_t* JNL8(uint8_t to);
/* jnle rel8 */
uint8_t* JNLE8(uint8_t to);
/* jo rel8 */
uint8_t* JO8(uint8_t to);
/* jno rel8 */
uint8_t* JNO8(uint8_t to);

/* je rel32 */
uint32_t* JE32(uint32_t to);
/* jz rel32 */
uint32_t* JZ32(uint32_t to);
/* jg rel32 */
uint32_t* JG32(uint32_t to);
/* jge rel32 */
uint32_t* JGE32(uint32_t to);
/* jl rel32 */
uint32_t* JL32(uint32_t to);
/* jle rel32 */
uint32_t* JLE32(uint32_t to);
/* jne rel32 */
uint32_t* JNE32(uint32_t to);
/* jnz rel32 */
uint32_t* JNZ32(uint32_t to);
/* jng rel32 */
uint32_t* JNG32(uint32_t to);
/* jnge rel32 */
uint32_t* JNGE32(uint32_t to);
/* jnl rel32 */
uint32_t* JNL32(uint32_t to);
/* jnle rel32 */
uint32_t* JNLE32(uint32_t to);
/* jo rel32 */
uint32_t* JO32(uint32_t to);
/* jno rel32 */
uint32_t* JNO32(uint32_t to);

/* call func */
void CALLFunc(uint32_t func);  // based on CALL32
/* call rel32 */
void CALL32(uint32_t to);
/* call r32 */
void CALL32R(int to);
/* call m32 */
void CALL32M(uint32_t to);

////////////////////////////////////
// misc instructions               /
////////////////////////////////////

/* cmp imm32 to r32 */
void CMP32ItoR(int to, uint32_t from);
/* cmp imm32 to m32 */
void CMP32ItoM(uint32_t to, uint32_t from);
/* cmp r32 to r32 */
void CMP32RtoR(int to, int from);
/* cmp m32 to r32 */
void CMP32MtoR(int to, uint32_t from);

/* test imm32 to r32 */
void TEST32ItoR(int to, uint32_t from);
/* test r32 to r32 */
void TEST32RtoR(int to, int from);
/* sets r8 */
void SETS8R(int to);
/* setl r8 */
void SETL8R(int to);
/* setb r8 */
void SETB8R(int to);

/* cbw */
void CBW();
/* cwd */
void CWD();
/* cdq */
void CDQ();

/* push r32 */
void PUSH32R(int from);
/* push m32 */
void PUSH32M(uint32_t from);
/* push imm32 */
void PUSH32I(uint32_t from);

/* pop r32 */
void POP32R(int from);

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
void MOVQMtoR(int to, uint32_t from);
/* movq r64 to m64 */
void MOVQRtoM(uint32_t to, int from);

/* pand r64 to r64 */
void PANDRtoR(int to, int from);
/* pand m64 to r64 */
void PANDMtoR(int to, uint32_t from);

/* pandn r64 to r64 */
void PANDNRtoR(int to, int from);

/* pandn r64 to r64 */
void PANDNMtoR(int to, uint32_t from);

/* por r64 to r64 */
void PORRtoR(int to, int from);
/* por m64 to r64 */
void PORMtoR(int to, uint32_t from);

/* pxor r64 to r64 */
void PXORRtoR(int to, int from);
/* pxor m64 to r64 */
void PXORMtoR(int to, uint32_t from);

/* psllq r64 to r64 */
void PSLLQRtoR(int to, int from);
/* psllq m64 to r64 */
void PSLLQMtoR(int to, uint32_t from);
/* psllq imm8 to r64 */
void PSLLQItoR(int to, uint8_t from);

/* psrlq r64 to r64 */
void PSRLQRtoR(int to, int from);
/* psrlq m64 to r64 */
void PSRLQMtoR(int to, uint32_t from);
/* psrlq imm8 to r64 */
void PSRLQItoR(int to, uint8_t from);

/* paddusb r64 to r64 */
void PADDUSBRtoR(int to, int from);
/* paddusb m64 to r64 */
void PADDUSBMtoR(int to, uint32_t from);
/* paddusw r64 to r64 */
void PADDUSWRtoR(int to, int from);
/* paddusw m64 to r64 */
void PADDUSWMtoR(int to, uint32_t from);

/* paddb r64 to r64 */
void PADDBRtoR(int to, int from);
/* paddb m64 to r64 */
void PADDBMtoR(int to, uint32_t from);
/* paddw r64 to r64 */
void PADDWRtoR(int to, int from);
/* paddw m64 to r64 */
void PADDWMtoR(int to, uint32_t from);
/* paddd r64 to r64 */
void PADDDRtoR(int to, int from);
/* paddd m64 to r64 */
void PADDDMtoR(int to, uint32_t from);

/* emms */
void EMMS();
void FEMMS();
void BT32ItoR(int to, int from);
void RCR32ItoR(int to, int from);

// Basara:changed
void PADDSBRtoR(int to, int from);
void PADDSWRtoR(int to, int from);
void PADDSDRtoR(int to, int from);
void PSUBSBRtoR(int to, int from);
void PSUBSWRtoR(int to, int from);
void PSUBSDRtoR(int to, int from);

void PSUBBRtoR(int to, int from);
void PSUBWRtoR(int to, int from);
void PSUBDRtoR(int to, int from);

void MOVQ64ItoR(int reg, uint64_t i);  // Prototype.Todo add all consts to end of block.not after jr $+8

void PMAXSWRtoR(int to, int from);
void PMINSWRtoR(int to, int from);

void PCMPEQBRtoR(int to, int from);
void PCMPEQWRtoR(int to, int from);
void PCMPEQDRtoR(int to, int from);

void PCMPGTBRtoR(int to, int from);
void PCMPGTWRtoR(int to, int from);
void PCMPGTDRtoR(int to, int from);

void PSRLWItoR(int to, int from);
void PSRLDItoR(int to, int from);
void PSLLWItoR(int to, int from);
void PSLLDItoR(int to, int from);
void PSRAWItoR(int to, int from);
void PSRADItoR(int to, int from);

// Added:basara 11.01.2003
void FCOMP32(uint32_t from);
void FNSTSWtoAX();
void SETNZ8R(int to);

// Added:basara 14.01.2003
void PFCMPEQMtoR(int to, int from);
void PFCMPGTMtoR(int to, int from);
void PFCMPGEMtoR(int to, int from);

void PFADDMtoR(int to, int from);
void PFADDRtoR(int to, int from);

void PFSUBMtoR(int to, int from);
void PFSUBRtoR(int to, int from);

void PFMULMtoR(int to, int from);
void PFMULRtoR(int to, int from);

void PFRCPMtoR(int to, int from);
void PFRCPRtoR(int to, int from);
void PFRCPIT1RtoR(int to, int from);
void PFRCPIT2RtoR(int to, int from);

void PFRSQRTRtoR(int to, int from);
void PFRSQIT1RtoR(int to, int from);

void PF2IDMtoR(int to, int from);
void PF2IDRtoR(int to, int from);
void PI2FDMtoR(int to, int from);
void PI2FDRtoR(int to, int from);

void PFMAXMtoR(int to, int from);
void PFMAXRtoR(int to, int from);
void PFMINMtoR(int to, int from);
void PFMINRtoR(int to, int from);

void MOVDMtoR(int to, uint32_t from);
void MOVDRtoM(uint32_t to, int from);
void MOVD32RtoR(int to, int from);
void MOVD64RtoR(int to, int from);

void MOVQRtoR(int to, int from);

// if to==from MMLO=MMHI
void PUNPCKHDQRtoR(int to, int from);

// if to==from MMHI=MMLO
void PUNPCKLDQRtoR(int to, int from);

/*
        SSE	intructions
*/
void MOVAPSMtoR(int to, int from);
void MOVAPSRtoM(int to, int from);
void MOVAPSRtoR(int to, int from);

void ORPSMtoR(int to, int from);
void ORPSRtoR(int to, int from);

void XORPSMtoR(int to, int from);
void XORPSRtoR(int to, int from);

void ANDPSMtoR(int to, int from);
void ANDPSRtoR(int to, int from);

#endif
