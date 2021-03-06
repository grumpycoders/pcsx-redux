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

#include "core/ix86/ix86.h"

void PCSX::ix86::x86Init(int8_t* ptr) {
    m_x86Ptr = ptr;
    memset(m_j8Ptr, 0, sizeof(m_j8Ptr));
    memset(m_j32Ptr, 0, sizeof(m_j32Ptr));
}

void PCSX::ix86::x86Shutdown() {}

void PCSX::ix86::x86SetJ8(unsigned slot) {
    static const unsigned arraySize = sizeof(m_j8Ptr) / sizeof(m_j8Ptr[0]);
    assert(slot < arraySize);
    uint8_t* j8 = m_j8Ptr[slot];
    m_j8Ptr[slot] = nullptr;
    assert(*j8 == 0);
    uint32_t jump = (m_x86Ptr - (int8_t*)j8) - 1;

    assert(jump <= 0x7f);  // assert that the jump is within range of the displacement
    *j8 = (uint8_t)jump;
}

void PCSX::ix86::x86SetJ32(unsigned slot) {
    static const unsigned arraySize = sizeof(m_j32Ptr) / sizeof(m_j32Ptr[0]);
    assert(slot < arraySize);
    uint32_t* j32 = m_j32Ptr[slot];
    m_j32Ptr[slot] = nullptr;
    assert(*j32 == 0);
    *j32 = (m_x86Ptr - (int8_t*)j32) - 4;
}

void PCSX::ix86::x86Align(uintptr_t bytes) {
    // forward align
    bytes--;
    int8_t* newPtr = (int8_t*)(((uintptr_t)m_x86Ptr + bytes) & ~bytes);
    // filling with NOPs
    NOP(newPtr - m_x86Ptr);
    assert(m_x86Ptr == newPtr);
}

void PCSX::ix86::NOP(unsigned bytes, int8_t* at) {
    if (at) std::swap(at, m_x86Ptr);
    while (bytes) {
        switch (bytes) {
            case 1:  // nop
                write8(0x90);
                bytes -= 1;
                break;
            case 2:  // nop (16 bits operands)
                write16(0x9066);
                bytes -= 2;
                break;
            case 3:  // nop dword ptr[eax]
                write16(0x1f0f);
                write8(0x00);
                bytes -= 3;
                break;
            case 4:  // nop dword ptr[eax + 0x00]
                write32(0x00401f0f);
                bytes -= 4;
                break;
            case 5:  // nop dword ptr[eax + eax + 0x00]
                write32(0x00441f0f);
                write8(0x00);
                bytes -= 5;
                break;
            case 6:  // nop dword ptr[eax + eax + 0] (16 bits operands)
                write32(0x441f0f66);
                write16(0x0000);
                bytes -= 6;
                break;
            case 7:  // nop dword ptr[eax + 0x00000000]
                write32(0x00801f0f);
                write16(0x0000);
                write8(0x00);
                bytes -= 7;
                break;
            case 8:  // nop dword ptr[eax + eax + 0x00000000]
                write32(0x00841f0f);
                write32(0x00000000);
                bytes -= 8;
                break;
            default:  // nop dword ptr[eax + eax + 0x00000000] (16 bits operands)
                write32(0x841f0f66);
                write32(0x00000000);
                write8(0x00);
                bytes -= 9;
                break;
        }
    }
    if (at) std::swap(at, m_x86Ptr);
}

/********************/
/* IX86 intructions */
/********************/

// mov instructions

/* mov r32 to r32 */
void PCSX::ix86::MOV32RtoR(mainRegister to, mainRegister from) {
    write8(0x89);
    ModRM(3, from, to);
}

/* mov r32 to m32 */
void PCSX::ix86::MOV32RtoM(uint32_t to, mainRegister from) {
    write8(0x89);
    ModRM(0, from, DISP32);
    write32(to);
}

/* mov m32 to r32 */
void PCSX::ix86::MOV32MtoR(mainRegister to, uint32_t from) {
    write8(0x8B);
    ModRM(0, to, DISP32);
    write32(from);
}

/* mov [r32] to r32 */
void PCSX::ix86::MOV32RmtoR(mainRegister to, mainRegister from) {
    write8(0x8B);
    ModRM(0, to, from);
}

/* mov [r32][r32*scale] to r32 */
void PCSX::ix86::MOV32RmStoR(mainRegister to, mainRegister from, mainRegister from2, unsigned scale) {
    write8(0x8B);
    ModRM(0, to, 0x4);
    SibSB(scale, from2, from);
}

/* mov r32 to [r32] */
void PCSX::ix86::MOV32RtoRm(mainRegister to, mainRegister from) {
    write8(0x89);
    ModRM(0, from, to);
}

/* mov r32 to [r32][r32*scale] */
void PCSX::ix86::MOV32RtoRmS(mainRegister to, mainRegister to2, unsigned scale, mainRegister from) {
    write8(0x89);
    ModRM(0, from, 0x4);
    SibSB(scale, to2, to);
}

/* mov imm32 to r32 */
void PCSX::ix86::MOV32ItoR(mainRegister to, uint32_t from) {
    write8(0xB8 | to);
    write32(from);
}

/* mov imm32 to m32 */
void PCSX::ix86::MOV32ItoM(uint32_t to, uint32_t from) {
    write8(0xC7);
    ModRM(0, 0, DISP32);
    write32(to);
    write32(from);
}

/* mov r16 to m16 */
void PCSX::ix86::MOV16RtoM(uint32_t to, mainRegister from) {
    write8(0x66);
    write8(0x89);
    ModRM(0, from, DISP32);
    write32(to);
}

/* mov m16 to r16 */
void PCSX::ix86::MOV16MtoR(mainRegister to, uint32_t from) {
    write8(0x66);
    write8(0x8B);
    ModRM(0, to, DISP32);
    write32(from);
}

/* mov imm16 to m16 */
void PCSX::ix86::MOV16ItoM(uint32_t to, uint16_t from) {
    write8(0x66);
    write8(0xC7);
    ModRM(0, 0, DISP32);
    write32(to);
    write16(from);
}

/* mov r8 to m8 */
void PCSX::ix86::MOV8RtoM(uint32_t to, mainRegister from) {
    write8(0x88);
    ModRM(0, from, DISP32);
    write32(to);
}

/* mov m8 to r8 */
void PCSX::ix86::MOV8MtoR(mainRegister to, uint32_t from) {
    write8(0x8A);
    ModRM(0, to, DISP32);
    write32(from);
}

/* mov imm8 to m8 */
void PCSX::ix86::MOV8ItoM(uint32_t to, uint8_t from) {
    write8(0xC6);
    ModRM(0, 0, DISP32);
    write32(to);
    write8(from);
}

/* movsx r8 to r32 */
void PCSX::ix86::MOVSX32R8toR(mainRegister to, mainRegister from) {
    write16(0xBE0F);
    ModRM(3, to, from);
}

/* movsx m8 to r32 */
void PCSX::ix86::MOVSX32M8toR(mainRegister to, uint32_t from) {
    write16(0xBE0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* movsx r16 to r32 */
void PCSX::ix86::MOVSX32R16toR(mainRegister to, mainRegister from) {
    write16(0xBF0F);
    ModRM(3, to, from);
}

/* movsx m16 to r32 */
void PCSX::ix86::MOVSX32M16toR(mainRegister to, uint32_t from) {
    write16(0xBF0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* movzx r8 to r32 */
void PCSX::ix86::MOVZX32R8toR(mainRegister to, mainRegister from) {
    write16(0xB60F);
    ModRM(3, to, from);
}

/* movzx m8 to r32 */
void PCSX::ix86::MOVZX32M8toR(mainRegister to, uint32_t from) {
    write16(0xB60F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* movzx r16 to r32 */
void PCSX::ix86::MOVZX32R16toR(mainRegister to, mainRegister from) {
    write16(0xB70F);
    ModRM(3, to, from);
}

/* movzx m16 to r32 */
void PCSX::ix86::MOVZX32M16toR(mainRegister to, uint32_t from) {
    write16(0xB70F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* cmovne r32 to r32 */
void PCSX::ix86::CMOVNE32RtoR(mainRegister to, mainRegister from) { CMOV32RtoR(0x45, to, from); }

/* cmovne m32 to r32*/
void PCSX::ix86::CMOVNE32MtoR(mainRegister to, uint32_t from) { CMOV32MtoR(0x45, to, from); }

/* cmove r32 to r32*/
void PCSX::ix86::CMOVE32RtoR(mainRegister to, mainRegister from) { CMOV32RtoR(0x44, to, from); }

/* cmove m32 to r32*/
void PCSX::ix86::CMOVE32MtoR(mainRegister to, uint32_t from) { CMOV32MtoR(0x44, to, from); }

/* cmovg r32 to r32*/
void PCSX::ix86::CMOVG32RtoR(mainRegister to, mainRegister from) { CMOV32RtoR(0x4F, to, from); }

/* cmovg m32 to r32*/
void PCSX::ix86::CMOVG32MtoR(mainRegister to, uint32_t from) { CMOV32MtoR(0x4F, to, from); }

/* cmovge r32 to r32*/
void PCSX::ix86::CMOVGE32RtoR(mainRegister to, mainRegister from) { CMOV32RtoR(0x4D, to, from); }

/* cmovge m32 to r32*/
void PCSX::ix86::CMOVGE32MtoR(mainRegister to, uint32_t from) { CMOV32MtoR(0x4D, to, from); }

/* cmovl r32 to r32*/
void PCSX::ix86::CMOVL32RtoR(mainRegister to, mainRegister from) { CMOV32RtoR(0x4C, to, from); }

/* cmovl m32 to r32*/
void PCSX::ix86::CMOVL32MtoR(mainRegister to, uint32_t from) { CMOV32MtoR(0x4C, to, from); }

/* cmovle r32 to r32*/
void PCSX::ix86::CMOVLE32RtoR(mainRegister to, mainRegister from) { CMOV32RtoR(0x4E, to, from); }

/* cmovle m32 to r32*/
void PCSX::ix86::CMOVLE32MtoR(mainRegister to, uint32_t from) { CMOV32MtoR(0x4E, to, from); }

// arithmic instructions

// add imm8 to r32
// preferable to using a 32-bit immediate wherever appropriate due to saving on code size
// TODO: potentially template
void PCSX::ix86::ADD8ItoR32(mainRegister to, uint8_t from) {
    write8 (0x83); // opcode for all op r32, imm8 instructions
    ModRM (3, 0, to); // 3 -> Decides the addressing mode. 0 -> The sub-opcode
    write8 (from); // immediate
}

/* add imm32 to r32 */
void PCSX::ix86::ADD32ItoR(mainRegister to, uint32_t from) {
    if (to == EAX) {
        write8(0x05);
    } else {
        write8(0x81);
        ModRM(3, 0, to);
    }
    write32(from);
}

/* add imm32 to m32 */
void PCSX::ix86::ADD32ItoM(uint32_t to, uint32_t from) {
    write8(0x81);
    ModRM(0, 0, DISP32);
    write32(to);
    write32(from);
}

/* add r32 to r32 */
void PCSX::ix86::ADD32RtoR(mainRegister to, mainRegister from) {
    write8(0x01);
    ModRM(3, from, to);
}

/* add r32 to m32 */
void PCSX::ix86::ADD32RtoM(uint32_t to, mainRegister from) {
    write8(0x01);
    ModRM(0, from, DISP32);
    write32(to);
}

/* add m32 to r32 */
void PCSX::ix86::ADD32MtoR(mainRegister to, uint32_t from) {
    write8(0x03);
    ModRM(0, to, DISP32);
    write32(from);
}

/* adc imm32 to r32 */
void PCSX::ix86::ADC32ItoR(mainRegister to, uint32_t from) {
    if (to == EAX) {
        write8(0x15);
    } else {
        write8(0x81);
        ModRM(3, 2, to);
    }
    write32(from);
}

/* adc r32 to r32 */
void PCSX::ix86::ADC32RtoR(mainRegister to, mainRegister from) {
    write8(0x11);
    ModRM(3, from, to);
}

/* adc m32 to r32 */
void PCSX::ix86::ADC32MtoR(mainRegister to, uint32_t from) {
    write8(0x13);
    ModRM(0, to, DISP32);
    write32(from);
}

/* inc r32 */
void PCSX::ix86::INC32R(mainRegister to) { write8(0x40 + to); }

/* inc m32 */
void PCSX::ix86::INC32M(uint32_t to) {
    write8(0xFF);
    ModRM(0, 0, DISP32);
    write32(to);
}

/* sub imm32 to r32 */
void PCSX::ix86::SUB32ItoR(mainRegister to, uint32_t from) {
    if (to == EAX) {
        write8(0x2D);
    } else {
        write8(0x81);
        ModRM(3, 5, to);
    }
    write32(from);
}

/* sub r32 to r32 */
void PCSX::ix86::SUB32RtoR(mainRegister to, mainRegister from) {
    write8(0x29);
    ModRM(3, from, to);
}

/* sub m32 to r32 */
void PCSX::ix86::SUB32MtoR(mainRegister to, uint32_t from) {
    write8(0x2B);
    ModRM(0, to, DISP32);
    write32(from);
}

/* sbb imm32 to r32 */
void PCSX::ix86::SBB32ItoR(mainRegister to, uint32_t from) {
    if (to == EAX) {
        write8(0x1D);
    } else {
        write8(0x81);
        ModRM(3, 3, to);
    }
    write32(from);
}

/* sbb r32 to r32 */
void PCSX::ix86::SBB32RtoR(mainRegister to, mainRegister from) {
    write8(0x19);
    ModRM(3, from, to);
}

/* sbb m32 to r32 */
void PCSX::ix86::SBB32MtoR(mainRegister to, uint32_t from) {
    write8(0x1B);
    ModRM(0, to, DISP32);
    write32(from);
}

/* dec r32 */
void PCSX::ix86::DEC32R(mainRegister to) { write8(0x48 + to); }

/* dec m32 */
void PCSX::ix86::DEC32M(uint32_t to) {
    write8(0xFF);
    ModRM(0, 1, DISP32);
    write32(to);
}

/* mul eax by r32 to edx:eax */
void PCSX::ix86::MUL32R(mainRegister from) {
    write8(0xF7);
    ModRM(3, 4, from);
}

/* imul eax by r32 to edx:eax */
void PCSX::ix86::IMUL32R(mainRegister from) {
    write8(0xF7);
    ModRM(3, 5, from);
}

/* mul eax by m32 to edx:eax */
void PCSX::ix86::MUL32M(uint32_t from) {
    write8(0xF7);
    ModRM(0, 4, DISP32);
    write32(from);
}

/* imul eax by m32 to edx:eax */
void PCSX::ix86::IMUL32M(uint32_t from) {
    write8(0xF7);
    ModRM(0, 5, DISP32);
    write32(from);
}

/* imul r32 by r32 to r32 */
void PCSX::ix86::IMUL32RtoR(mainRegister to, mainRegister from) {
    write16(0xAF0F);
    ModRM(3, to, from);
}

/* div eax by r32 to edx:eax */
void PCSX::ix86::DIV32R(mainRegister from) {
    write8(0xF7);
    ModRM(3, 6, from);
}

/* idiv eax by r32 to edx:eax */
void PCSX::ix86::IDIV32R(mainRegister from) {
    write8(0xF7);
    ModRM(3, 7, from);
}

/* div eax by m32 to edx:eax */
void PCSX::ix86::DIV32M(uint32_t from) {
    write8(0xF7);
    ModRM(0, 6, DISP32);
    write32(from);
}

/* idiv eax by m32 to edx:eax */
void PCSX::ix86::IDIV32M(uint32_t from) {
    write8(0xF7);
    ModRM(0, 7, DISP32);
    write32(from);
}

// shifting instructions

void PCSX::ix86::RCR32ItoR(mainRegister to, mainRegister from) {
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
void PCSX::ix86::SHL32ItoR(mainRegister to, uint8_t from) {
    if (from == 1) {
        write8(0xd1);
        write8(0xe0 | to);
    } else {
        write8(0xC1);
        ModRM(3, 4, to);
        write8(from);
    }
}

/* shl cl to r32 */
void PCSX::ix86::SHL32CLtoR(mainRegister to) {
    write8(0xD3);
    ModRM(3, 4, to);
}

/* shr imm8 to r32 */
void PCSX::ix86::SHR32ItoR(mainRegister to, uint8_t from) {
    if (from == 1) {
        write8(0xd1);
        write8(0xe8 | to);
    } else {
        write8(0xC1);
        ModRM(3, 5, to);
        write8(from);
    }
}

/* shr cl to r32 */
void PCSX::ix86::SHR32CLtoR(mainRegister to) {
    write8(0xD3);
    ModRM(3, 5, to);
}

/* sar imm8 to r32 */
void PCSX::ix86::SAR32ItoR(mainRegister to, uint8_t from) {
    write8(0xC1);
    ModRM(3, 7, to);
    write8(from);
}

/* sar cl to r32 */
void PCSX::ix86::SAR32CLtoR(mainRegister to) {
    write8(0xD3);
    ModRM(3, 7, to);
}

// logical instructions

/* or imm32 to r32 */
void PCSX::ix86::OR32ItoR(mainRegister to, uint32_t from) {
    if (to == EAX) {
        write8(0x0D);
    } else {
        write8(0x81);
        ModRM(3, 1, to);
    }
    write32(from);
}

/* or imm32 to m32 */
void PCSX::ix86::OR32ItoM(uint32_t to, uint32_t from) {
    write8(0x81);
    ModRM(0, 1, DISP32);
    write32(to);
    write32(from);
}

/* or r32 to r32 */
void PCSX::ix86::OR32RtoR(mainRegister to, mainRegister from) {
    write8(0x09);
    ModRM(3, from, to);
}

/* or r32 to m32 */
void PCSX::ix86::OR32RtoM(uint32_t to, mainRegister from) {
    write8(0x09);
    ModRM(0, from, DISP32);
    write32(to);
}

/* or m32 to r32 */
void PCSX::ix86::OR32MtoR(mainRegister to, uint32_t from) {
    write8(0x0B);
    ModRM(0, to, DISP32);
    write32(from);
}

/* xor imm32 to r32 */
void PCSX::ix86::XOR32ItoR(mainRegister to, uint32_t from) {
    if (to == EAX) {
        write8(0x35);
    } else {
        write8(0x81);
        ModRM(3, 6, to);
    }
    write32(from);
}

/* xor imm32 to m32 */
void PCSX::ix86::XOR32ItoM(uint32_t to, uint32_t from) {
    write8(0x81);
    ModRM(0, 6, DISP32);
    write32(to);
    write32(from);
}

/* xor r32 to r32 */
void PCSX::ix86::XOR32RtoR(mainRegister to, mainRegister from) {
    write8(0x31);
    ModRM(3, from, to);
}

/* xor r32 to m32 */
void PCSX::ix86::XOR32RtoM(uint32_t to, mainRegister from) {
    write8(0x31);
    ModRM(0, from, DISP32);
    write32(to);
}

/* xor m32 to r32 */
void PCSX::ix86::XOR32MtoR(mainRegister to, uint32_t from) {
    write8(0x33);
    ModRM(0, to, DISP32);
    write32(from);
}

// and imm8 to r32
// preferable to using a 32-bit immediate wherever appropriate due to saving on code size
// TODO: potentially template
void PCSX::ix86::AND8ItoR32(mainRegister to, uint8_t from) {
    write8 (0x83); // opcode for all op r32, imm8 instructions
    ModRM (3, 0x4, to); // 3 -> Decides the addressing mode. 4 -> The sub-opcode
    write8 (from); // immediate
}

/* and imm32 to r32 */
void PCSX::ix86::AND32ItoR(mainRegister to, uint32_t from) {
    if (to == EAX) {
        write8(0x25);
    } else {
        write8(0x81);
        ModRM(3, 0x4, to);
    }
    write32(from);
}

/* and imm32 to m32 */
void PCSX::ix86::AND32ItoM(uint32_t to, uint32_t from) {
    write8(0x81);
    ModRM(0, 0x4, DISP32);
    write32(to);
    write32(from);
}

/* and r32 to r32 */
void PCSX::ix86::AND32RtoR(mainRegister to, mainRegister from) {
    write8(0x21);
    ModRM(3, from, to);
}

/* and r32 to m32 */
void PCSX::ix86::AND32RtoM(uint32_t to, mainRegister from) {
    write8(0x21);
    ModRM(0, from, DISP32);
    write32(to);
}

/* and m32 to r32 */
void PCSX::ix86::AND32MtoR(mainRegister to, uint32_t from) {
    write8(0x23);
    ModRM(0, to, DISP32);
    write32(from);
}

/* not r32 */
void PCSX::ix86::NOT32R(mainRegister from) {
    write8(0xF7);
    ModRM(3, 2, from);
}

/* neg r32 */
void PCSX::ix86::NEG32R(mainRegister from) {
    write8(0xF7);
    ModRM(3, 3, from);
}

// jump instructions

/* jmp rel8 */
unsigned PCSX::ix86::JMP8(uint8_t to) {
    static const unsigned arraySize = sizeof(m_j8Ptr) / sizeof(m_j8Ptr[0]);
    write8(0xEB);
    write8(to);
    if (to != 0) return arraySize;
    uint8_t* ptr = reinterpret_cast<uint8_t*>(m_x86Ptr - 1);
    for (unsigned i = 0; i < arraySize; i++) {
        if (m_j8Ptr[i] == nullptr) {
            m_j8Ptr[i] = ptr;
            return i;
        }
    }

    abort();
    return arraySize;
}

/* jmp rel32 */
unsigned PCSX::ix86::JMP32(uint32_t to) {
    static const unsigned arraySize = sizeof(m_j32Ptr) / sizeof(m_j32Ptr[0]);
    write8(0xE9);
    write32(to);
    uint32_t* ptr = reinterpret_cast<uint32_t*>(m_x86Ptr - 4);
    if (to != 0) return arraySize;
    for (unsigned i = 0; i < arraySize; i++) {
        if (m_j32Ptr[i] == nullptr) {
            m_j32Ptr[i] = ptr;
            return i;
        }
    }

    abort();
    return arraySize;
}

/* jmp r32 */
void PCSX::ix86::JMP32R(mainRegister to) {
    write8(0xFF);
    ModRM(3, 4, to);
}


/* jc/jb/jnae rel8 */
unsigned PCSX::ix86::JC8(uint8_t to) { return J8Rel(0x72, to); }

/* jnc/jnb/jae rel8 */
unsigned PCSX::ix86::JNC8(uint8_t to) { return J8Rel(0x73, to); }

/* je rel8 */
unsigned PCSX::ix86::JE8(uint8_t to) { return J8Rel(0x74, to); }

/* jz rel8 */
unsigned PCSX::ix86::JZ8(uint8_t to) { return J8Rel(0x74, to); }

/* jg rel8 */
unsigned PCSX::ix86::JG8(uint8_t to) { return J8Rel(0x7F, to); }

/* jge rel8 */
unsigned PCSX::ix86::JGE8(uint8_t to) { return J8Rel(0x7D, to); }

/* jl rel8 */
unsigned PCSX::ix86::JL8(uint8_t to) { return J8Rel(0x7C, to); }

/* jle rel8 */
unsigned PCSX::ix86::JLE8(uint8_t to) { return J8Rel(0x7E, to); }

/* jne rel8 */
unsigned PCSX::ix86::JNE8(uint8_t to) { return J8Rel(0x75, to); }

/* jnz rel8 */
unsigned PCSX::ix86::JNZ8(uint8_t to) { return J8Rel(0x75, to); }

/* jng rel8 */
unsigned PCSX::ix86::JNG8(uint8_t to) { return J8Rel(0x7E, to); }

/* jnge rel8 */
unsigned PCSX::ix86::JNGE8(uint8_t to) { return J8Rel(0x7C, to); }

/* jnl rel8 */
unsigned PCSX::ix86::JNL8(uint8_t to) { return J8Rel(0x7D, to); }

/* jnle rel8 */
unsigned PCSX::ix86::JNLE8(uint8_t to) { return J8Rel(0x7F, to); }

/* jo rel8 */
unsigned PCSX::ix86::JO8(uint8_t to) { return J8Rel(0x70, to); }

/* jno rel8 */
unsigned PCSX::ix86::JNO8(uint8_t to) { return J8Rel(0x71, to); }

/* je rel32 */
unsigned PCSX::ix86::JE32(uint32_t to) { return J32Rel(0x84, to); }

/* jz rel32 */
unsigned PCSX::ix86::JZ32(uint32_t to) { return J32Rel(0x84, to); }

/* jg rel32 */
unsigned PCSX::ix86::JG32(uint32_t to) { return J32Rel(0x8F, to); }

/* jge rel32 */
unsigned PCSX::ix86::JGE32(uint32_t to) { return J32Rel(0x8D, to); }

/* jl rel32 */
unsigned PCSX::ix86::JL32(uint32_t to) { return J32Rel(0x8C, to); }

/* jle rel32 */
unsigned PCSX::ix86::JLE32(uint32_t to) { return J32Rel(0x8E, to); }

/* jne rel32 */
unsigned PCSX::ix86::JNE32(uint32_t to) { return J32Rel(0x85, to); }

/* jnz rel32 */
unsigned PCSX::ix86::JNZ32(uint32_t to) { return J32Rel(0x85, to); }

/* jng rel32 */
unsigned PCSX::ix86::JNG32(uint32_t to) { return J32Rel(0x8E, to); }

/* jnge rel32 */
unsigned PCSX::ix86::JNGE32(uint32_t to) { return J32Rel(0x8C, to); }

/* jnl rel32 */
unsigned PCSX::ix86::JNL32(uint32_t to) { return J32Rel(0x8D, to); }

/* jnle rel32 */
unsigned PCSX::ix86::JNLE32(uint32_t to) { return J32Rel(0x8F, to); }

/* jo rel32 */
unsigned PCSX::ix86::JO32(uint32_t to) { return J32Rel(0x80, to); }

/* jno rel32 */
unsigned PCSX::ix86::JNO32(uint32_t to) { return J32Rel(0x81, to); }

/* call func */
void PCSX::ix86::CALLFunc(uint32_t func) { CALL32(func - ((uintptr_t)m_x86Ptr + 5)); }

/* call rel32 */
void PCSX::ix86::CALL32(uint32_t to) {
    write8(0xE8);
    write32(to);
}

/* call r32 */
void PCSX::ix86::CALL32R(mainRegister to) {
    write8(0xFF);
    ModRM(3, 2, to);
}

/* call m32 */
void PCSX::ix86::CALL32M(uint32_t to) {
    write8(0xFF);
    ModRM(0, 2, DISP32);
    write32(to);
}

// misc instructions

/* cmp imm32 to r32 */
void PCSX::ix86::CMP32ItoR(mainRegister to, uint32_t from) {
    if (to == EAX) {
        write8(0x3D);
    } else {
        write8(0x81);
        ModRM(3, 7, to);
    }
    write32(from);
}

/* cmp imm32 to m32 */
void PCSX::ix86::CMP32ItoM(uint32_t to, uint32_t from) {
    write8(0x81);
    ModRM(0, 7, DISP32);
    write32(to);
    write32(from);
}

/* cmp r32 to r32 */
void PCSX::ix86::CMP32RtoR(mainRegister to, mainRegister from) {
    write8(0x39);
    ModRM(3, from, to);
}

/* cmp m32 to r32 */
void PCSX::ix86::CMP32MtoR(mainRegister to, uint32_t from) {
    write8(0x3B);
    ModRM(0, to, DISP32);
    write32(from);
}

/* test imm32 to r32 */
void PCSX::ix86::TEST32ItoR(mainRegister to, uint32_t from) {
    if (to == EAX) {
        write8(0xA9);
    } else {
        write8(0xF7);
        ModRM(3, 0, to);
    }
    write32(from);
}

/* test i8 to to m8 */
// NASM syntax: test byte [addr], imm8
void PCSX::ix86::TEST8ItoM(uint32_t address, uint8_t imm) {
    write16(0x05f6); // opcode + modrm
    write32(address); // address
    write8 (imm);
}

/* test r32 to r32 */
void PCSX::ix86::TEST32RtoR(mainRegister to, mainRegister from) {
    write8(0x85);
    ModRM(3, from, to);
}

void PCSX::ix86::BT32ItoR(mainRegister to, mainRegister from) {
    write16(0xba0f);
    write8(0xe0 | to);
    write8(from);
}

// Test bit 'bit' of memory address and copy it to carry
// NASM syntax: bt dword [addr], bit
void PCSX::ix86::BT32IToM(uint32_t address, uint8_t bit) {
    write16 (0xba0f); // 2 byte opcode
    write8 (0x25); // mod rm
    write32 (address); // address
    write8 (bit); // bit number
}

/* sets r8 */
void PCSX::ix86::SETS8R(mainRegister to) { SET8R(0x98, to); }
/* setl r8 */
void PCSX::ix86::SETL8R(mainRegister to) { SET8R(0x9C, to); }

/* setb r8 */
void PCSX::ix86::SETB8R(mainRegister to) { SET8R(0x92, to); }

/* setnz r8 */
void PCSX::ix86::SETNZ8R(mainRegister to) { SET8R(0x95, to); }

/* cbw */
void PCSX::ix86::CBW() { write16(0x9866); }

/* cwd */
void PCSX::ix86::CWD() { write8(0x98); }

/* cdq */
void PCSX::ix86::CDQ() { write8(0x99); }

/* push r32 */
void PCSX::ix86::PUSH32R(mainRegister from) { write8(0x50 | from); }

/* push m32 */
void PCSX::ix86::PUSH32M(uint32_t from) {
    write8(0xFF);
    ModRM(0, 6, DISP32);
    write32(from);
}

/* push imm32 */
void PCSX::ix86::PUSH32I(uint32_t from) {
    write8(0x68);
    write32(from);
}

/* pop r32 */
void PCSX::ix86::POP32R(mainRegister from) { write8(0x58 | from); }

/* pushad */
void PCSX::ix86::PUSHA32() { write8(0x60); }

/* popad */
void PCSX::ix86::POPA32() { write8(0x61); }

/* ret */
void PCSX::ix86::RET() { write8(0xC3); }

/********************/
/* FPU instructions */
/********************/

// Added:basara 14.01.2003
/* compare m32 to fpu reg stack */
void PCSX::ix86::FCOMP32(uint32_t from) {
    write8(0xD8);
    ModRM(0, 0x3, DISP32);
    write32(from);
}

void PCSX::ix86::FNSTSWtoAX() { write16(0xE0DF); }

/* fild m32 to fpu reg stack */
void PCSX::ix86::FILD32(uint32_t from) {
    write8(0xDB);
    ModRM(0, 0x0, DISP32);
    write32(from);
}

/* fistp m32 from fpu reg stack */
void PCSX::ix86::FISTP32(uint32_t from) {
    write8(0xDB);
    ModRM(0, 0x3, DISP32);
    write32(from);
}

/* fld m32 to fpu reg stack */
void PCSX::ix86::FLD32(uint32_t from) {
    write8(0xD9);
    ModRM(0, 0x0, DISP32);
    write32(from);
}

/* fstp m32 from fpu reg stack */
void PCSX::ix86::FSTP32(uint32_t to) {
    write8(0xD9);
    ModRM(0, 0x3, DISP32);
    write32(to);
}

//

/* fldcw fpu control word from m16 */
void PCSX::ix86::FLDCW(uint32_t from) {
    write8(0xD9);
    ModRM(0, 0x5, DISP32);
    write32(from);
}

/* fnstcw fpu control word to m16 */
void PCSX::ix86::FNSTCW(uint32_t to) {
    write8(0xD9);
    ModRM(0, 0x7, DISP32);
    write32(to);
}

//

/* fadd m32 to fpu reg stack */
void PCSX::ix86::FADD32(uint32_t from) {
    write8(0xD8);
    ModRM(0, 0x0, DISP32);
    write32(from);
}

/* fsub m32 to fpu reg stack */
void PCSX::ix86::FSUB32(uint32_t from) {
    write8(0xD8);
    ModRM(0, 0x4, DISP32);
    write32(from);
}

/* fmul m32 to fpu reg stack */
void PCSX::ix86::FMUL32(uint32_t from) {
    write8(0xD8);
    ModRM(0, 0x1, DISP32);
    write32(from);
}

/* fdiv m32 to fpu reg stack */
void PCSX::ix86::FDIV32(uint32_t from) {
    write8(0xD8);
    ModRM(0, 0x6, DISP32);
    write32(from);
}

/* fabs fpu reg stack */
void PCSX::ix86::FABS() { write16(0xE1D9); }

/* fsqrt fpu reg stack */
void PCSX::ix86::FSQRT() { write16(0xFAD9); }

/* fchs fpu reg stack */
void PCSX::ix86::FCHS() { write16(0xE0D9); }

/********************/
/* MMX instructions */
/********************/

// r64 = mm

/* movq m64 to r64 */
void PCSX::ix86::MOVQMtoR(mmxRegister to, uint32_t from) {
    write16(0x6F0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* movq r64 to m64 */
void PCSX::ix86::MOVQRtoM(uint32_t to, mmxRegister from) {
    write16(0x7F0F);
    ModRM(0, from, DISP32);
    write32(to);
}

/* pand r64 to r64 */
void PCSX::ix86::PANDRtoR(mmxRegister to, mmxRegister from) {
    write16(0xDB0F);
    ModRM(3, to, from);
}

/* pand r64 to r64 */
void PCSX::ix86::PANDNRtoR(mmxRegister to, mmxRegister from) {
    write16(0xDF0F);
    ModRM(3, to, from);
}

/* por r64 to r64 */
void PCSX::ix86::PORRtoR(mmxRegister to, mmxRegister from) {
    write16(0xEB0F);
    ModRM(3, to, from);
}

/* pxor r64 to r64 */
void PCSX::ix86::PXORRtoR(mmxRegister to, mmxRegister from) {
    write16(0xEF0F);
    ModRM(3, to, from);
}

/* psllq r64 to r64 */
void PCSX::ix86::PSLLQRtoR(mmxRegister to, mmxRegister from) {
    write16(0xF30F);
    ModRM(3, to, from);
}

/* psllq m64 to r64 */
void PCSX::ix86::PSLLQMtoR(mmxRegister to, uint32_t from) {
    write16(0xF30F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* psllq imm8 to r64 */
void PCSX::ix86::PSLLQItoR(mmxRegister to, uint8_t from) {
    write16(0x730F);
    ModRM(3, 6, to);
    write8(from);
}

/* psrlq r64 to r64 */
void PCSX::ix86::PSRLQRtoR(mmxRegister to, mmxRegister from) {
    write16(0xD30F);
    ModRM(3, to, from);
}

/* psrlq m64 to r64 */
void PCSX::ix86::PSRLQMtoR(mmxRegister to, uint32_t from) {
    write16(0xD30F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* psrlq imm8 to r64 */
void PCSX::ix86::PSRLQItoR(mmxRegister to, uint8_t from) {
    write16(0x730F);
    ModRM(3, 2, to);
    write8(from);
}

/* paddusb r64 to r64 */
void PCSX::ix86::PADDUSBRtoR(mmxRegister to, mmxRegister from) {
    write16(0xDC0F);
    ModRM(3, to, from);
}

/* paddusb m64 to r64 */
void PCSX::ix86::PADDUSBMtoR(mmxRegister to, uint32_t from) {
    write16(0xDC0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* paddusw r64 to r64 */
void PCSX::ix86::PADDUSWRtoR(mmxRegister to, mmxRegister from) {
    write16(0xDD0F);
    ModRM(3, to, from);
}

/* paddusw m64 to r64 */
void PCSX::ix86::PADDUSWMtoR(mmxRegister to, uint32_t from) {
    write16(0xDD0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* paddb r64 to r64 */
void PCSX::ix86::PADDBRtoR(mmxRegister to, mmxRegister from) {
    write16(0xFC0F);
    ModRM(3, to, from);
}

/* paddb m64 to r64 */
void PCSX::ix86::PADDBMtoR(mmxRegister to, uint32_t from) {
    write16(0xFC0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* paddw r64 to r64 */
void PCSX::ix86::PADDWRtoR(mmxRegister to, mmxRegister from) {
    write16(0xFD0F);
    ModRM(3, to, from);
}

/* paddw m64 to r64 */
void PCSX::ix86::PADDWMtoR(mmxRegister to, uint32_t from) {
    write16(0xFD0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* paddd r64 to r64 */
void PCSX::ix86::PADDDRtoR(mmxRegister to, mmxRegister from) {
    write16(0xFE0F);
    ModRM(3, to, from);
}

/* paddd m64 to r64 */
void PCSX::ix86::PADDDMtoR(mmxRegister to, uint32_t from) {
    write16(0xFE0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* emms */
void PCSX::ix86::EMMS() {
    // use femms if we have 3dnow
    write16(0x0e0f);
}

/* femms */
void PCSX::ix86::FEMMS() { write16(0x770F); }

// Basara:changed
void PCSX::ix86::PADDSBRtoR(mmxRegister to, mmxRegister from) {
    write16(0xEC0F);
    ModRM(3, to, from);
}

void PCSX::ix86::PADDSWRtoR(mmxRegister to, mmxRegister from) {
    write16(0xED0F);
    ModRM(3, to, from);
}

void PCSX::ix86::PADDSDRtoR(mmxRegister to, mmxRegister from) {
    write16(0xEE0F);
    ModRM(3, to, from);
}

void PCSX::ix86::PSUBSBRtoR(mmxRegister to, mmxRegister from) {
    write16(0xE80F);
    ModRM(3, to, from);
}

void PCSX::ix86::PSUBSWRtoR(mmxRegister to, mmxRegister from) {
    write16(0xE90F);
    ModRM(3, to, from);
}

void PCSX::ix86::PSUBSDRtoR(mmxRegister to, mmxRegister from) {
    write16(0xEA0F);
    ModRM(3, to, from);
}

void PCSX::ix86::PSUBBRtoR(mmxRegister to, mmxRegister from) {
    write16(0xF80F);
    ModRM(3, to, from);
}

void PCSX::ix86::PSUBWRtoR(mmxRegister to, mmxRegister from) {
    write16(0xF90F);
    ModRM(3, to, from);
}

void PCSX::ix86::PSUBDRtoR(mmxRegister to, mmxRegister from) {
    write16(0xFA0F);
    ModRM(3, to, from);
}

void PCSX::ix86::PSUBUSBRtoR(mmxRegister to, mmxRegister from) {
    write16(0xD80F);
    ModRM(3, to, from);
}

void PCSX::ix86::PSUBUSWRtoR(mmxRegister to, mmxRegister from) {
    write16(0xD90F);
    ModRM(3, to, from);
}

void PCSX::ix86::PMAXSWRtoR(mmxRegister to, mmxRegister from) {
    write16(0xEE0F);
    ModRM(3, to, from);
}

void PCSX::ix86::PMINSWRtoR(mmxRegister to, mmxRegister from) {
    write16(0xEA0F);
    ModRM(3, to, from);
}

void PCSX::ix86::PCMPEQBRtoR(mmxRegister to, mmxRegister from) {
    write16(0x740F);
    ModRM(3, to, from);
}

void PCSX::ix86::PCMPEQWRtoR(mmxRegister to, mmxRegister from) {
    write16(0x750F);
    ModRM(3, to, from);
}

void PCSX::ix86::PCMPEQDRtoR(mmxRegister to, mmxRegister from) {
    write16(0x760F);
    ModRM(3, to, from);
}

void PCSX::ix86::PCMPGTBRtoR(mmxRegister to, mmxRegister from) {
    write16(0x640F);
    ModRM(3, to, from);
}

void PCSX::ix86::PCMPGTWRtoR(mmxRegister to, mmxRegister from) {
    write16(0x650F);
    ModRM(3, to, from);
}

void PCSX::ix86::PCMPGTDRtoR(mmxRegister to, mmxRegister from) {
    write16(0x660F);
    ModRM(3, to, from);
}

// Basara:Added 10.01.2003
void PCSX::ix86::PSRLWItoR(mmxRegister to, uint8_t from) {
    write16(0x710f);
    ModRM(2, 2, to);
    write8(from);
}
void PCSX::ix86::PSRLDItoR(mmxRegister to, uint8_t from) {
    write16(0x720f);
    ModRM(2, 2, to);
    write8(from);
}

void PCSX::ix86::PSLLWItoR(mmxRegister to, uint8_t from) {
    write16(0x710f);
    ModRM(3, 6, to);
    write8(from);
}

void PCSX::ix86::PSLLDItoR(mmxRegister to, uint8_t from) {
    write16(0x720f);
    ModRM(3, 6, to);
    write8(from);
}

void PCSX::ix86::PSRAWItoR(mmxRegister to, uint8_t from) {
    write16(0x710f);
    ModRM(3, 4, to);
    write8(from);
}

void PCSX::ix86::PSRADItoR(mmxRegister to, uint8_t from) {
    write16(0x720f);
    ModRM(3, 4, to);
    write8(from);
}

/* por m64 to r64 */
void PCSX::ix86::PORMtoR(mmxRegister to, uint32_t from) {
    write16(0xEB0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* pxor m64 to r64 */
void PCSX::ix86::PXORMtoR(mmxRegister to, uint32_t from) {
    write16(0xEF0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* pand m64 to r64 */
void PCSX::ix86::PANDMtoR(mmxRegister to, uint32_t from) {
    write16(0xDB0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* pandn m64 to r64 */
void PCSX::ix86::PANDNMtoR(mmxRegister to, uint32_t from) {
    write16(0xDF0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* movd m32 to r64 */
void PCSX::ix86::MOVDMtoR(mmxRegister to, uint32_t from) {
    write16(0x6E0F);
    ModRM(0, to, DISP32);
    write32(from);
}

/* movq r64 to m32 */
void PCSX::ix86::MOVDRtoM(uint32_t to, mmxRegister from) {
    write16(0x7E0F);
    ModRM(0, from, DISP32);
    write32(to);
}

/* movd r32 to r64 */
void PCSX::ix86::MOVD32RtoR(mmxRegister to, mainRegister from) {
    write16(0x6E0F);
    ModRM(3, to, from);
}

/* movq r64 to r32 */
void PCSX::ix86::MOVD64RtoR(mainRegister to, mmxRegister from) {
    write16(0x7E0F);
    ModRM(3, from, to);
}

void PCSX::ix86::MOVQRtoR(mmxRegister to, mmxRegister from) {
    write16(0x6F0F);
    ModRM(3, to, from);
}

void PCSX::ix86::PUNPCKHDQRtoR(mmxRegister to, mmxRegister from) {
    write16(0x6A0F);
    ModRM(3, to, from);
}

void PCSX::ix86::PUNPCKLDQRtoR(mmxRegister to, mmxRegister from) {
    write16(0x620F);
    ModRM(3, to, from);
}

//////////////////////////////////////////////////////////////////////////
//  SSE intructions
//////////////////////////////////////////////////////////////////////////

void PCSX::ix86::MOVAPSMtoR(sseRegister to, sseRegister from) {
    write16(0x280f);
    ModRM(0, to, DISP32);
    write32(from);
}

void PCSX::ix86::MOVAPSRtoM(sseRegister to, sseRegister from) {
    write16(0x2b0f);
    ModRM(0, from, DISP32);
    write32(to);
}

void PCSX::ix86::MOVAPSRtoR(sseRegister to, sseRegister from) {
    write16(0x290f);
    ModRM(3, to, from);
}

void PCSX::ix86::ORPSMtoR(sseRegister to, sseRegister from) {
    write16(0x560f);
    ModRM(0, to, DISP32);
    write32(from);
}

void PCSX::ix86::ORPSRtoR(sseRegister to, sseRegister from) {
    write16(0x560f);
    ModRM(3, to, from);
}

void PCSX::ix86::XORPSMtoR(sseRegister to, sseRegister from) {
    write16(0x570f);
    ModRM(0, to, DISP32);
    write32(from);
}

void PCSX::ix86::XORPSRtoR(sseRegister to, sseRegister from) {
    write16(0x570f);
    ModRM(3, to, from);
}

void PCSX::ix86::ANDPSMtoR(sseRegister to, sseRegister from) {
    write16(0x540f);
    ModRM(0, to, DISP32);
    write32(from);
}

void PCSX::ix86::ANDPSRtoR(sseRegister to, sseRegister from) {
    write16(0x540f);
    ModRM(3, to, from);
}

/*
        3DNOW intructions
*/

void PCSX::ix86::PFCMPEQMtoR(sseRegister to, uint32_t from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0xb0);
}

void PCSX::ix86::PFCMPGTMtoR(sseRegister to, uint32_t from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0xa0);
}

void PCSX::ix86::PFCMPGEMtoR(sseRegister to, uint32_t from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0x90);
}

void PCSX::ix86::PFADDMtoR(sseRegister to, uint32_t from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0x9e);
}

void PCSX::ix86::PFADDRtoR(sseRegister to, sseRegister from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0x9e);
}

void PCSX::ix86::PFSUBMtoR(sseRegister to, uint32_t from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0x9a);
}

void PCSX::ix86::PFSUBRtoR(sseRegister to, sseRegister from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0x9a);
}

void PCSX::ix86::PFMULMtoR(sseRegister to, uint32_t from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0xb4);
}

void PCSX::ix86::PFMULRtoR(sseRegister to, sseRegister from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0xb4);
}

void PCSX::ix86::PFRCPMtoR(sseRegister to, uint32_t from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0x96);
}

void PCSX::ix86::PFRCPRtoR(sseRegister to, sseRegister from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0x96);
}

void PCSX::ix86::PFRCPIT1RtoR(sseRegister to, sseRegister from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0xa6);
}

void PCSX::ix86::PFRCPIT2RtoR(sseRegister to, sseRegister from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0xb6);
}

void PCSX::ix86::PFRSQRTRtoR(sseRegister to, sseRegister from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0x97);
}

void PCSX::ix86::PFRSQIT1RtoR(sseRegister to, sseRegister from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0xa7);
}

void PCSX::ix86::PF2IDMtoR(sseRegister to, uint32_t from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0x1d);
}

void PCSX::ix86::PF2IDRtoR(sseRegister to, sseRegister from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0x1d);
}

void PCSX::ix86::PI2FDMtoR(sseRegister to, uint32_t from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0x0d);
}

void PCSX::ix86::PI2FDRtoR(sseRegister to, sseRegister from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0x0d);
}

/*
        3DNOW Extension intructions
*/

void PCSX::ix86::PFMAXMtoR(sseRegister to, uint32_t from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0xa4);
}

void PCSX::ix86::PFMAXRtoR(sseRegister to, sseRegister from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0xa4);
}

void PCSX::ix86::PFMINMtoR(sseRegister to, uint32_t from) {
    write16(0x0f0f);
    ModRM(0, to, DISP32);
    write32(from);
    write8(0x94);
}

void PCSX::ix86::PFMINRtoR(sseRegister to, sseRegister from) {
    write16(0x0f0f);
    ModRM(3, to, from);
    write8(0x94);
}
