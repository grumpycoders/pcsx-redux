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
 * ix86 core v0.5.1
 *  Authors: linuzappz <linuzappz@pcsx.net>
 *           alexey silinov
 */

#if defined(__i386__) || defined(_M_IX86)

#include "ix86.h"

s8* g_x86Ptr;
u8* g_j8Ptr[32];
u32* g_j32Ptr[32];

void x86Init() {}

void x86SetPtr(char* ptr) { g_x86Ptr = ptr; }

void x86Shutdown() {}

void x86SetJ8(u8* j8) {
    u32 jump = (g_x86Ptr - (s8*)j8) - 1;

    if (jump > 0x7f) printf("j8 greater than 0x7f!!\n");
    *j8 = (u8)jump;
}

void x86SetJ32(u32* j32) { *j32 = (g_x86Ptr - (s8*)j32) - 4; }

void x86Align(int bytes) {
    // fordward align
    g_x86Ptr = (s8*)(((u32)g_x86Ptr + bytes) & ~(bytes - 1));
}

#define SIB 4
#define DISP32 5

/* macros helpers */

#define ModRM(mod, rm, reg) write8((mod << 6) | (rm << 3) | (reg));

#define SibSB(ss, rm, index) write8((ss << 6) | (rm << 3) | (index));

#define SET8R(cc, to)          \
    {                          \
        write8(0x0F);          \
        write8(cc);            \
        write8((0xC0) | (to)); \
    }

#define J8Rel(cc, to)      \
    {                      \
        write8(cc);        \
        write8(to);        \
        return g_x86Ptr - 1; \
    }

#define J32Rel(cc, to)             \
    {                              \
        write8(0x0F);              \
        write8(cc);                \
        write32(to);               \
        return (u32*)(g_x86Ptr - 4); \
    }

#define CMOV32RtoR(cc, to, from) \
    {                            \
        write8(0x0F);            \
        write8(cc);              \
        ModRM(3, to, from);      \
    }

#define CMOV32MtoR(cc, to, from) \
    {                            \
        write8(0x0F);            \
        write8(cc);              \
        ModRM(0, to, DISP32);    \
        write32(from);           \
    }

/********************/
/* IX86 intructions */
/********************/

// mov instructions

/* mov r32 to r32 */
void MOV32RtoR(int to, int from) {
    write8(0x89);
    ModRM(3, from, to);
}

/* mov r32 to m32 */
void MOV32RtoM(u32 to, int from) {
    write8(0x89);
    ModRM(0, from, DISP32);
    write32(to);
}

/* mov m32 to r32 */
void MOV32MtoR(int to, u32 from) {
    write8(0x8B);
    ModRM(0, to, DISP32);
    write32(from);
}

/* mov [r32] to r32 */
void MOV32RmtoR(int to, int from) {
    write8(0x8B);
    ModRM(0, to, from);
}

/* mov [r32][r32*scale] to r32 */
void MOV32RmStoR(int to, int from, int from2, int scale) {
    write8(0x8B);
    ModRM(0, to, 0x4);
    SibSB(scale, from2, from);
}

/* mov r32 to [r32] */
void MOV32RtoRm(int to, int from) {
    write8(0x89);
    ModRM(0, from, to);
}

/* mov r32 to [r32][r32*scale] */
void MOV32RtoRmS(int to, int to2, int scale, int from) {
    write8(0x89);
    ModRM(0, from, 0x4);
    SibSB(scale, to2, to);
}

/* mov imm32 to r32 */
void MOV32ItoR(int to, u32 from) {
    write8(0xB8 | to);
    write32(from);
}

/* mov imm32 to m32 */
void MOV32ItoM(u32 to, u32 from) {
    write8(0xC7);
    ModRM(0, 0, DISP32);
    write32(to);
    write32(from);
}

/* mov r16 to m16 */
void MOV16RtoM(u32 to, int from) {
    write8(0x66);
    write8(0x89);
    ModRM(0, from, DISP32);
    write32(to);
}

/* mov m16 to r16 */
void MOV16MtoR(int to, u32 from) {
    write8(0x66);
    write8(0x8B);
    ModRM(0, to, DISP32);
    write32(from);
}

/* mov imm16 to m16 */
void MOV16ItoM(u32 to, u16 from) {
    write8(0x66);
    write8(0xC7);
    ModRM(0, 0, DISP32);
    write32(to);
    write16(from);
}

/* mov r8 to m8 */
void MOV8RtoM(u32 to, int from) {
    write8(0x88);
    ModRM(0, from, DISP32);
    write32(to);
}

/* mov m8 to r8 */
void MOV8MtoR(int to, u32 from) {
    write8(0x8A);
    ModRM(0, to, DISP32);
    write32(from);
}

/* mov imm8 to m8 */
void MOV8ItoM(u32 to, u8 from) {
    write8(0xC6);
    ModRM(0, 0, DISP32);
    write32(to);
    write8(from);
}

/* movsx r8 to r32 */
void MOVSX32R8toR(int to, int from) {
    write16(0xBE0F);
    ModRM(3, to, from);
}

/* movsx m8 to r32 */
void MOVSX32M8toR(int to, u32 from) {
    write16(0xBE0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* movsx r16 to r32 */
void MOVSX32R16toR(int to, int from) {
    write16(0xBF0F);
    ModRM(3, to, from);
}

/* movsx m16 to r32 */
void MOVSX32M16toR(int to, u32 from) {
    write16(0xBF0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* movzx r8 to r32 */
void MOVZX32R8toR(int to, int from) {
    write16(0xB60F);
    ModRM(3, to, from);
}

/* movzx m8 to r32 */
void MOVZX32M8toR(int to, u32 from) {
    write16(0xB60F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* movzx r16 to r32 */
void MOVZX32R16toR(int to, int from) {
    write16(0xB70F);
    ModRM(3, to, from);
}

/* movzx m16 to r32 */
void MOVZX32M16toR(int to, u32 from) {
    write16(0xB70F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* cmovne r32 to r32 */
void CMOVNE32RtoR(int to, int from) { CMOV32RtoR(0x45, to, from); }

/* cmovne m32 to r32*/
void CMOVNE32MtoR(int to, u32 from) { CMOV32MtoR(0x45, to, from); }

/* cmove r32 to r32*/
void CMOVE32RtoR(int to, int from) { CMOV32RtoR(0x44, to, from); }

/* cmove m32 to r32*/
void CMOVE32MtoR(int to, u32 from) { CMOV32MtoR(0x44, to, from); }

/* cmovg r32 to r32*/
void CMOVG32RtoR(int to, int from) { CMOV32RtoR(0x4F, to, from); }

/* cmovg m32 to r32*/
void CMOVG32MtoR(int to, u32 from) { CMOV32MtoR(0x4F, to, from); }

/* cmovge r32 to r32*/
void CMOVGE32RtoR(int to, int from) { CMOV32RtoR(0x4D, to, from); }

/* cmovge m32 to r32*/
void CMOVGE32MtoR(int to, u32 from) { CMOV32MtoR(0x4D, to, from); }

/* cmovl r32 to r32*/
void CMOVL32RtoR(int to, int from) { CMOV32RtoR(0x4C, to, from); }

/* cmovl m32 to r32*/
void CMOVL32MtoR(int to, u32 from) { CMOV32MtoR(0x4C, to, from); }

/* cmovle r32 to r32*/
void CMOVLE32RtoR(int to, int from) { CMOV32RtoR(0x4E, to, from); }

/* cmovle m32 to r32*/
void CMOVLE32MtoR(int to, u32 from) { CMOV32MtoR(0x4E, to, from); }

// arithmic instructions

/* add imm32 to r32 */
void ADD32ItoR(int to, u32 from) {
    if (to == EAX) {
        write8(0x05);
    } else {
        write8(0x81);
        ModRM(3, 0, to);
    }
    write32(from);
}

/* add imm32 to m32 */
void ADD32ItoM(u32 to, u32 from) {
    write8(0x81);
    ModRM(0, 0, DISP32);
    write32(to);
    write32(from);
}

/* add r32 to r32 */
void ADD32RtoR(int to, int from) {
    write8(0x01);
    ModRM(3, from, to);
}

/* add r32 to m32 */
void ADD32RtoM(u32 to, int from) {
    write8(0x01);
    ModRM(0, from, DISP32);
    write32(to);
}

/* add m32 to r32 */
void ADD32MtoR(int to, u32 from) {
    write8(0x03);
    ModRM(0, to, DISP32);
    write32(from);
}

/* adc imm32 to r32 */
void ADC32ItoR(int to, u32 from) {
    if (to == EAX) {
        write8(0x15);
    } else {
        write8(0x81);
        ModRM(3, 2, to);
    }
    write32(from);
}

/* adc r32 to r32 */
void ADC32RtoR(int to, int from) {
    write8(0x11);
    ModRM(3, from, to);
}

/* adc m32 to r32 */
void ADC32MtoR(int to, u32 from) {
    write8(0x13);
    ModRM(0, to, DISP32);
    write32(from);
}

/* inc r32 */
void INC32R(int to) { write8(0x40 + to); }

/* inc m32 */
void INC32M(u32 to) {
    write8(0xFF);
    ModRM(0, 0, DISP32);
    write32(to);
}

/* sub imm32 to r32 */
void SUB32ItoR(int to, u32 from) {
    if (to == EAX) {
        write8(0x2D);
    } else {
        write8(0x81);
        ModRM(3, 5, to);
    }
    write32(from);
}

/* sub r32 to r32 */
void SUB32RtoR(int to, int from) {
    write8(0x29);
    ModRM(3, from, to);
}

/* sub m32 to r32 */
void SUB32MtoR(int to, u32 from) {
    write8(0x2B);
    ModRM(0, to, DISP32);
    write32(from);
}

/* sbb imm32 to r32 */
void SBB32ItoR(int to, u32 from) {
    if (to == EAX) {
        write8(0x1D);
    } else {
        write8(0x81);
        ModRM(3, 3, to);
    }
    write32(from);
}

/* sbb r32 to r32 */
void SBB32RtoR(int to, int from) {
    write8(0x19);
    ModRM(3, from, to);
}

/* sbb m32 to r32 */
void SBB32MtoR(int to, u32 from) {
    write8(0x1B);
    ModRM(0, to, DISP32);
    write32(from);
}

/* dec r32 */
void DEC32R(int to) { write8(0x48 + to); }

/* dec m32 */
void DEC32M(u32 to) {
    write8(0xFF);
    ModRM(0, 1, DISP32);
    write32(to);
}

/* mul eax by r32 to edx:eax */
void MUL32R(int from) {
    write8(0xF7);
    ModRM(3, 4, from);
}

/* imul eax by r32 to edx:eax */
void IMUL32R(int from) {
    write8(0xF7);
    ModRM(3, 5, from);
}

/* mul eax by m32 to edx:eax */
void MUL32M(u32 from) {
    write8(0xF7);
    ModRM(0, 4, DISP32);
    write32(from);
}

/* imul eax by m32 to edx:eax */
void IMUL32M(u32 from) {
    write8(0xF7);
    ModRM(0, 5, DISP32);
    write32(from);
}

/* imul r32 by r32 to r32 */
void IMUL32RtoR(int to, int from) {
    write16(0xAF0F);
    ModRM(3, to, from);
}

/* div eax by r32 to edx:eax */
void DIV32R(int from) {
    write8(0xF7);
    ModRM(3, 6, from);
}

/* idiv eax by r32 to edx:eax */
void IDIV32R(int from) {
    write8(0xF7);
    ModRM(3, 7, from);
}

/* div eax by m32 to edx:eax */
void DIV32M(u32 from) {
    write8(0xF7);
    ModRM(0, 6, DISP32);
    write32(from);
}

/* idiv eax by m32 to edx:eax */
void IDIV32M(u32 from) {
    write8(0xF7);
    ModRM(0, 7, DISP32);
    write32(from);
}

// shifting instructions

void RCR32ItoR(int to, int from) {
    if (from == 1) {
        write8(0xd1);
        write8(0xd8 | to);
    } else {
        write8(0xc1);
        write8(0xd8 | to);
        write8(from);
    }
}

/* shl imm8 to r32 */
void SHL32ItoR(int to, u8 from) {
    if (from == 1) {
        write8(0xd1);
        write8(0xe0 | to);
        return;
    }
    write8(0xC1);
    ModRM(3, 4, to);
    write8(from);
}

/* shl cl to r32 */
void SHL32CLtoR(int to) {
    write8(0xD3);
    ModRM(3, 4, to);
}

/* shr imm8 to r32 */
void SHR32ItoR(int to, u8 from) {
    if (from == 1) {
        write8(0xd1);
        write8(0xe8 | to);
        return;
    }
    write8(0xC1);
    ModRM(3, 5, to);
    write8(from);
}

/* shr cl to r32 */
void SHR32CLtoR(int to) {
    write8(0xD3);
    ModRM(3, 5, to);
}

/* sar imm8 to r32 */
void SAR32ItoR(int to, u8 from) {
    write8(0xC1);
    ModRM(3, 7, to);
    write8(from);
}

/* sar cl to r32 */
void SAR32CLtoR(int to) {
    write8(0xD3);
    ModRM(3, 7, to);
}

// logical instructions

/* or imm32 to r32 */
void OR32ItoR(int to, u32 from) {
    if (to == EAX) {
        write8(0x0D);
    } else {
        write8(0x81);
        ModRM(3, 1, to);
    }
    write32(from);
}

/* or imm32 to m32 */
void OR32ItoM(u32 to, u32 from) {
    write8(0x81);
    ModRM(0, 1, DISP32);
    write32(to);
    write32(from);
}

/* or r32 to r32 */
void OR32RtoR(int to, int from) {
    write8(0x09);
    ModRM(3, from, to);
}

/* or r32 to m32 */
void OR32RtoM(u32 to, int from) {
    write8(0x09);
    ModRM(0, from, DISP32);
    write32(to);
}

/* or m32 to r32 */
void OR32MtoR(int to, u32 from) {
    write8(0x0B);
    ModRM(0, to, DISP32);
    write32(from);
}

/* xor imm32 to r32 */
void XOR32ItoR(int to, u32 from) {
    if (to == EAX) {
        write8(0x35);
    } else {
        write8(0x81);
        ModRM(3, 6, to);
    }
    write32(from);
}

/* xor imm32 to m32 */
void XOR32ItoM(u32 to, u32 from) {
    write8(0x81);
    ModRM(0, 6, DISP32);
    write32(to);
    write32(from);
}

/* xor r32 to r32 */
void XOR32RtoR(int to, int from) {
    write8(0x31);
    ModRM(3, from, to);
}

/* xor r32 to m32 */
void XOR32RtoM(u32 to, int from) {
    write8(0x31);
    ModRM(0, from, DISP32);
    write32(to);
}

/* xor m32 to r32 */
void XOR32MtoR(int to, u32 from) {
    write8(0x33);
    ModRM(0, to, DISP32);
    write32(from);
}

/* and imm32 to r32 */
void AND32ItoR(int to, u32 from) {
    if (to == EAX) {
        write8(0x25);
    } else {
        write8(0x81);
        ModRM(3, 0x4, to);
    }
    write32(from);
}

/* and imm32 to m32 */
void AND32ItoM(u32 to, u32 from) {
    write8(0x81);
    ModRM(0, 0x4, DISP32);
    write32(to);
    write32(from);
}

/* and r32 to r32 */
void AND32RtoR(int to, int from) {
    write8(0x21);
    ModRM(3, from, to);
}

/* and r32 to m32 */
void AND32RtoM(u32 to, int from) {
    write8(0x21);
    ModRM(0, from, DISP32);
    write32(to);
}

/* and m32 to r32 */
void AND32MtoR(int to, u32 from) {
    write8(0x23);
    ModRM(0, to, DISP32);
    write32(from);
}

/* not r32 */
void NOT32R(int from) {
    write8(0xF7);
    ModRM(3, 2, from);
}

/* neg r32 */
void NEG32R(int from) {
    write8(0xF7);
    ModRM(3, 3, from);
}

// jump instructions

/* jmp rel8 */
u8* JMP8(u8 to) {
    write8(0xEB);
    write8(to);
    return g_x86Ptr - 1;
}

/* jmp rel32 */
u32* JMP32(u32 to) {
    write8(0xE9);
    write32(to);
    return (u32*)(g_x86Ptr - 4);
}

/* jmp r32 */
void JMP32R(int to) {
    write8(0xFF);
    ModRM(3, 4, to);
}

/* je rel8 */
u8* JE8(u8 to) { J8Rel(0x74, to); }

/* jz rel8 */
u8* JZ8(u8 to) { J8Rel(0x74, to); }

/* jg rel8 */
u8* JG8(u8 to) { J8Rel(0x7F, to); }

/* jge rel8 */
u8* JGE8(u8 to) { J8Rel(0x7D, to); }

/* jl rel8 */
u8* JL8(u8 to) { J8Rel(0x7C, to); }

/* jle rel8 */
u8* JLE8(u8 to) { J8Rel(0x7E, to); }

/* jne rel8 */
u8* JNE8(u8 to) { J8Rel(0x75, to); }

/* jnz rel8 */
u8* JNZ8(u8 to) { J8Rel(0x75, to); }

/* jng rel8 */
u8* JNG8(u8 to) { J8Rel(0x7E, to); }

/* jnge rel8 */
u8* JNGE8(u8 to) { J8Rel(0x7C, to); }

/* jnl rel8 */
u8* JNL8(u8 to) { J8Rel(0x7D, to); }

/* jnle rel8 */
u8* JNLE8(u8 to) { J8Rel(0x7F, to); }

/* jo rel8 */
u8* JO8(u8 to) { J8Rel(0x70, to); }

/* jno rel8 */
u8* JNO8(u8 to) { J8Rel(0x71, to); }

/* je rel32 */
u32* JE32(u32 to) { J32Rel(0x84, to); }

/* jz rel32 */
u32* JZ32(u32 to) { J32Rel(0x84, to); }

/* jg rel32 */
u32* JG32(u32 to) { J32Rel(0x8F, to); }

/* jge rel32 */
u32* JGE32(u32 to) { J32Rel(0x8D, to); }

/* jl rel32 */
u32* JL32(u32 to) { J32Rel(0x8C, to); }

/* jle rel32 */
u32* JLE32(u32 to) { J32Rel(0x8E, to); }

/* jne rel32 */
u32* JNE32(u32 to) { J32Rel(0x85, to); }

/* jnz rel32 */
u32* JNZ32(u32 to) { J32Rel(0x85, to); }

/* jng rel32 */
u32* JNG32(u32 to) { J32Rel(0x8E, to); }

/* jnge rel32 */
u32* JNGE32(u32 to) { J32Rel(0x8C, to); }

/* jnl rel32 */
u32* JNL32(u32 to) { J32Rel(0x8D, to); }

/* jnle rel32 */
u32* JNLE32(u32 to) { J32Rel(0x8F, to); }

/* jo rel32 */
u32* JO32(u32 to) { J32Rel(0x80, to); }

/* jno rel32 */
u32* JNO32(u32 to) { J32Rel(0x81, to); }

/* call func */
void CALLFunc(u32 func) { CALL32(func - ((u32)g_x86Ptr + 5)); }

/* call rel32 */
void CALL32(u32 to) {
    write8(0xE8);
    write32(to);
}

/* call r32 */
void CALL32R(int to) {
    write8(0xFF);
    ModRM(3, 2, to);
}

/* call m32 */
void CALL32M(u32 to) {
    write8(0xFF);
    ModRM(0, 2, DISP32);
    write32(to);
}

// misc instructions

/* cmp imm32 to r32 */
void CMP32ItoR(int to, u32 from) {
    if (to == EAX) {
        write8(0x3D);
    } else {
        write8(0x81);
        ModRM(3, 7, to);
    }
    write32(from);
}

/* cmp imm32 to m32 */
void CMP32ItoM(u32 to, u32 from) {
    write8(0x81);
    ModRM(0, 7, DISP32);
    write32(to);
    write32(from);
}

/* cmp r32 to r32 */
void CMP32RtoR(int to, int from) {
    write8(0x39);
    ModRM(3, from, to);
}

/* cmp m32 to r32 */
void CMP32MtoR(int to, u32 from) {
    write8(0x3B);
    ModRM(0, to, DISP32);
    write32(from);
}

/* test imm32 to r32 */
void TEST32ItoR(int to, u32 from) {
    if (to == EAX) {
        write8(0xA9);
    } else {
        write8(0xF7);
        ModRM(3, 0, to);
    }
    write32(from);
}

/* test r32 to r32 */
void TEST32RtoR(int to, int from) {
    write8(0x85);
    ModRM(3, from, to);
}

void BT32ItoR(int to, int from) {
    write16(0xba0f);
    write8(0xe0 | to);
    write8(from);
}

/* sets r8 */
void SETS8R(int to) { SET8R(0x98, to); }
/* setl r8 */
void SETL8R(int to) { SET8R(0x9C, to); }

/* setb r8 */
void SETB8R(int to) { SET8R(0x92, to); }

/* setnz r8 */
void SETNZ8R(int to) { SET8R(0x95, to); }

/* cbw */
void CBW() { write16(0x9866); }

/* cwd */
void CWD() { write8(0x98); }

/* cdq */
void CDQ() { write8(0x99); }

/* push r32 */
void PUSH32R(int from) { write8(0x50 | from); }

/* push m32 */
void PUSH32M(u32 from) {
    write8(0xFF);
    ModRM(0, 6, DISP32);
    write32(from);
}

/* push imm32 */
void PUSH32I(u32 from) {
    write8(0x68);
    write32(from);
}

/* pop r32 */
void POP32R(int from) { write8(0x58 | from); }

/* pushad */
void PUSHA32() { write8(0x60); }

/* popad */
void POPA32() { write8(0x61); }

/* ret */
void RET() { write8(0xC3); }

/********************/
/* FPU instructions */
/********************/

// Added:basara 14.01.2003
/* compare m32 to fpu reg stack */
void FCOMP32(u32 from) {
    write8(0xD8);
    ModRM(0, 0x3, DISP32);
    write32(from);
}

void FNSTSWtoAX() { write16(0xE0DF); }

/* fild m32 to fpu reg stack */
void FILD32(u32 from) {
    write8(0xDB);
    ModRM(0, 0x0, DISP32);
    write32(from);
}

/* fistp m32 from fpu reg stack */
void FISTP32(u32 from) {
    write8(0xDB);
    ModRM(0, 0x3, DISP32);
    write32(from);
}

/* fld m32 to fpu reg stack */
void FLD32(u32 from) {
    write8(0xD9);
    ModRM(0, 0x0, DISP32);
    write32(from);
}

/* fstp m32 from fpu reg stack */
void FSTP32(u32 to) {
    write8(0xD9);
    ModRM(0, 0x3, DISP32);
    write32(to);
}

//

/* fldcw fpu control word from m16 */
void FLDCW(u32 from) {
    write8(0xD9);
    ModRM(0, 0x5, DISP32);
    write32(from);
}

/* fnstcw fpu control word to m16 */
void FNSTCW(u32 to) {
    write8(0xD9);
    ModRM(0, 0x7, DISP32);
    write32(to);
}

//

/* fadd m32 to fpu reg stack */
void FADD32(u32 from) {
    write8(0xD8);
    ModRM(0, 0x0, DISP32);
    write32(from);
}

/* fsub m32 to fpu reg stack */
void FSUB32(u32 from) {
    write8(0xD8);
    ModRM(0, 0x4, DISP32);
    write32(from);
}

/* fmul m32 to fpu reg stack */
void FMUL32(u32 from) {
    write8(0xD8);
    ModRM(0, 0x1, DISP32);
    write32(from);
}

/* fdiv m32 to fpu reg stack */
void FDIV32(u32 from) {
    write8(0xD8);
    ModRM(0, 0x6, DISP32);
    write32(from);
}

/* fabs fpu reg stack */
void FABS() { write16(0xE1D9); }

/* fsqrt fpu reg stack */
void FSQRT() { write16(0xFAD9); }

/* fchs fpu reg stack */
void FCHS() { write16(0xE0D9); }

/********************/
/* MMX instructions */
/********************/

// r64 = mm

/* movq m64 to r64 */
void MOVQMtoR(int to, u32 from) {
    write16(0x6F0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* movq r64 to m64 */
void MOVQRtoM(u32 to, int from) {
    write16(0x7F0F);
    ModRM(0, from, DISP32);
    write32(to);
}

/* pand r64 to r64 */
void PANDRtoR(int to, int from) {
    write16(0xDB0F);
    ModRM(3, to, from);
}

/* pand r64 to r64 */
void PANDNRtoR(int to, int from) {
    write16(0xDF0F);
    ModRM(3, to, from);
}

/* por r64 to r64 */
void PORRtoR(int to, int from) {
    write16(0xEB0F);
    ModRM(3, to, from);
}

/* pxor r64 to r64 */
void PXORRtoR(int to, int from) {
    write16(0xEF0F);
    ModRM(3, to, from);
}

/* psllq r64 to r64 */
void PSLLQRtoR(int to, int from) {
    write16(0xF30F);
    ModRM(3, to, from);
}

/* psllq m64 to r64 */
void PSLLQMtoR(int to, u32 from) {
    write16(0xF30F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* psllq imm8 to r64 */
void PSLLQItoR(int to, u8 from) {
    write16(0x730F);
    ModRM(3, 6, to);
    write8(from);
}

/* psrlq r64 to r64 */
void PSRLQRtoR(int to, int from) {
    write16(0xD30F);
    ModRM(3, to, from);
}

/* psrlq m64 to r64 */
void PSRLQMtoR(int to, u32 from) {
    write16(0xD30F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* psrlq imm8 to r64 */
void PSRLQItoR(int to, u8 from) {
    write16(0x730F);
    ModRM(3, 2, to);
    write8(from);
}

/* paddusb r64 to r64 */
void PADDUSBRtoR(int to, int from) {
    write16(0xDC0F);
    ModRM(3, to, from);
}

/* paddusb m64 to r64 */
void PADDUSBMtoR(int to, u32 from) {
    write16(0xDC0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* paddusw r64 to r64 */
void PADDUSWRtoR(int to, int from) {
    write16(0xDD0F);
    ModRM(3, to, from);
}

/* paddusw m64 to r64 */
void PADDUSWMtoR(int to, u32 from) {
    write16(0xDD0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* paddb r64 to r64 */
void PADDBRtoR(int to, int from) {
    write16(0xFC0F);
    ModRM(3, to, from);
}

/* paddb m64 to r64 */
void PADDBMtoR(int to, u32 from) {
    write16(0xFC0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* paddw r64 to r64 */
void PADDWRtoR(int to, int from) {
    write16(0xFD0F);
    ModRM(3, to, from);
}

/* paddw m64 to r64 */
void PADDWMtoR(int to, u32 from) {
    write16(0xFD0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* paddd r64 to r64 */
void PADDDRtoR(int to, int from) {
    write16(0xFE0F);
    ModRM(3, to, from);
}

/* paddd m64 to r64 */
void PADDDMtoR(int to, u32 from) {
    write16(0xFE0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* emms */
void EMMS() {
    // use femms if we have 3dnow
    write16(0x0e0f);
    return;
}

/* femms */
void FEMMS() {
    write16(0x770F);
    return;
}

// Basara:changed
void PADDSBRtoR(int to, int from) {
    write16(0xEC0F);
    ModRM(3, to, from);
}

void PADDSWRtoR(int to, int from) {
    write16(0xED0F);
    ModRM(3, to, from);
}

void PADDSDRtoR(int to, int from) {
    write16(0xEE0F);
    ModRM(3, to, from);
}

void PSUBSBRtoR(int to, int from) {
    write16(0xE80F);
    ModRM(3, to, from);
}

void PSUBSWRtoR(int to, int from) {
    write16(0xE90F);
    ModRM(3, to, from);
}

void PSUBSDRtoR(int to, int from) {
    write16(0xEA0F);
    ModRM(3, to, from);
}

void PSUBBRtoR(int to, int from) {
    write16(0xF80F);
    ModRM(3, to, from);
}

void PSUBWRtoR(int to, int from) {
    write16(0xF90F);
    ModRM(3, to, from);
}

void PSUBDRtoR(int to, int from) {
    write16(0xFA0F);
    ModRM(3, to, from);
}

// changed:basara
// P.s.It's sux.Don't use it offten.
void MOVQ64ItoR(int reg, u64 i) {
    MOVQMtoR(reg, (u32)(g_x86Ptr) + 2 + 7);
    JMP8(8);
    write64(i);
}

void PSUBUSBRtoR(int to, int from) {
    write16(0xD80F);
    ModRM(3, to, from);
}

void PSUBUSWRtoR(int to, int from) {
    write16(0xD90F);
    ModRM(3, to, from);
}

void PMAXSWRtoR(int to, int from) {
    write16(0xEE0F);
    ModRM(3, to, from);
}

void PMINSWRtoR(int to, int from) {
    write16(0xEA0F);
    ModRM(3, to, from);
}

void PCMPEQBRtoR(int to, int from) {
    write16(0x740F);
    ModRM(3, to, from);
}

void PCMPEQWRtoR(int to, int from) {
    write16(0x750F);
    ModRM(3, to, from);
}

void PCMPEQDRtoR(int to, int from) {
    write16(0x760F);
    ModRM(3, to, from);
}

void PCMPGTBRtoR(int to, int from) {
    write16(0x640F);
    ModRM(3, to, from);
}

void PCMPGTWRtoR(int to, int from) {
    write16(0x650F);
    ModRM(3, to, from);
}

void PCMPGTDRtoR(int to, int from) {
    write16(0x660F);
    ModRM(3, to, from);
}

// Basara:Added 10.01.2003
void PSRLWItoR(int to, int from) {
    write16(0x710f);
    ModRM(2, 2, to);
    write8(from);
}
void PSRLDItoR(int to, int from) {
    write16(0x720f);
    ModRM(2, 2, to);
    write8(from);
}

void PSLLWItoR(int to, int from) {
    write16(0x710f);
    ModRM(3, 6, to);
    write8(from);
}

void PSLLDItoR(int to, int from) {
    write16(0x720f);
    ModRM(3, 6, to);
    write8(from);
}

void PSRAWItoR(int to, int from) {
    write16(0x710f);
    ModRM(3, 4, to);
    write8(from);
}

void PSRADItoR(int to, int from) {
    write16(0x720f);
    ModRM(3, 4, to);
    write8(from);
}

/* por m64 to r64 */
void PORMtoR(int to, u32 from) {
    write16(0xEB0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* pxor m64 to r64 */
void PXORMtoR(int to, u32 from) {
    write16(0xEF0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* pand m64 to r64 */
void PANDMtoR(int to, u32 from) {
    write16(0xDB0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* pandn m64 to r64 */
void PANDNMtoR(int to, u32 from) {
    write16(0xDF0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* movd m32 to r64 */
void MOVDMtoR(int to, u32 from) {
    write16(0x6E0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* movq r64 to m32 */
void MOVDRtoM(u32 to, int from) {
    write16(0x7E0F);
    ModRM(0, from, DISP32);
    write32(to);
}

/* movd r32 to r64 */
void MOVD32RtoR(int to, int from) {
    write16(0x6E0F);
    ModRM(3, to, from);
}

/* movq r64 to r32 */
void MOVD64RtoR(int to, int from) {
    write16(0x7E0F);
    ModRM(3, from, to);
}

void MOVQRtoR(int to, int from) {
    write16(0x6F0F);
    ModRM(3, to, from);
}

void PUNPCKHDQRtoR(int to, int from) {
    write16(0x6A0F);
    ModRM(3, to, from);
}

void PUNPCKLDQRtoR(int to, int from) {
    write16(0x620F);
    ModRM(3, to, from);
}

//////////////////////////////////////////////////////////////////////////
//	SSE	intructions
//////////////////////////////////////////////////////////////////////////

void MOVAPSMtoR(int to, int from) {
    write16(0x280f);
    ModRM(0, to, DISP32);
    write32(from);
}

void MOVAPSRtoM(int to, int from) {
    write16(0x2b0f);
    ModRM(0, from, DISP32);
    write32(to);
}

void MOVAPSRtoR(int to, int from) {
    write16(0x290f);
    ModRM(3, to, from);
}

void ORPSMtoR(int to, int from) {
    write16(0x560f);
    ModRM(0, to, DISP32);
    write32(from);
}

void ORPSRtoR(int to, int from) {
    write16(0x560f);
    ModRM(3, to, from);
}

void XORPSMtoR(int to, int from) {
    write16(0x570f);
    ModRM(0, to, DISP32);
    write32(from);
}

void XORPSRtoR(int to, int from) {
    write16(0x570f);
    ModRM(3, to, from);
}

void ANDPSMtoR(int to, int from) {
    write16(0x540f);
    ModRM(0, to, DISP32);
    write32(from);
}

void ANDPSRtoR(int to, int from) {
    write16(0x540f);
    ModRM(3, to, from);
}

/*
        3DNOW intructions
*/

void PFCMPEQMtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0xb0);
}

void PFCMPGTMtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0xa0);
}

void PFCMPGEMtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0x90);
}

void PFADDMtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0x9e);
}

void PFADDRtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0x9e);
}

void PFSUBMtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0x9a);
}

void PFSUBRtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0x9a);
}

void PFMULMtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0xb4);
}

void PFMULRtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0xb4);
}

void PFRCPMtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0x96);
}

void PFRCPRtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0x96);
}

void PFRCPIT1RtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0xa6);
}

void PFRCPIT2RtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0xb6);
}

void PFRSQRTRtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0x97);
}

void PFRSQIT1RtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0xa7);
}

void PF2IDMtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0x1d);
}

void PF2IDRtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0x1d);
}

void PI2FDMtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0x0d);
}

void PI2FDRtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0x0d);
}

/*
        3DNOW Extension intructions
*/

void PFMAXMtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0xa4);
}

void PFMAXRtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0xa4);
}

void PFMINMtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0x94);
}

void PFMINRtoR(int to, int from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0x94);
}

#endif
