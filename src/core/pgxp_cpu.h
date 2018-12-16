/***************************************************************************
 *   Copyright (C) 2016 by iCatButler                                      *
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

/**************************************************************************
 *	pgxp_cpu.h
 *	PGXP - Parallel/Precision Geometry Xform Pipeline
 *
 *	Created on: 07 Jun 2016
 *      Author: iCatButler
 ***************************************************************************/

#ifndef _PGXP_CPU_H_
#define _PGXP_CPU_H_

#include "core/psxcommon.h"

#ifdef __cplusplus
extern "C" {
#endif

struct PGXP_value_Tag;
typedef struct PGXP_value_Tag PGXP_value;

extern PGXP_value* g_CPU_reg;
extern PGXP_value* g_CP0_reg;
#define CPU_Hi g_CPU_reg[33]
#define CPU_Lo g_CPU_reg[34]

void PGXP_InitCPU();

// -- CPU functions

// Load 32-bit word
void PGXP_CPU_LWL(u32 instr, u32 rtVal, u32 addr);
void PGXP_CPU_LW(u32 instr, u32 rtVal, u32 addr);
void PGXP_CPU_LWR(u32 instr, u32 rtVal, u32 addr);

// Load 16-bit
void PGXP_CPU_LH(u32 instr, u16 rtVal, u32 addr);
void PGXP_CPU_LHU(u32 instr, u16 rtVal, u32 addr);

// Load 8-bit
void PGXP_CPU_LB(u32 instr, u8 rtVal, u32 addr);
void PGXP_CPU_LBU(u32 instr, u8 rtVal, u32 addr);

// Store 32-bit word
void PGXP_CPU_SWL(u32 instr, u32 rtVal, u32 addr);
void PGXP_CPU_SW(u32 instr, u32 rtVal, u32 addr);
void PGXP_CPU_SWR(u32 instr, u32 rtVal, u32 addr);

// Store 16-bit
void PGXP_CPU_SH(u32 instr, u16 rtVal, u32 addr);

// Store 8-bit
void PGXP_CPU_SB(u32 instr, u8 rtVal, u32 addr);

// Arithmetic with immediate value
void PGXP_CPU_ADDI(u32 instr, u32 rtVal, u32 rsVal);
void PGXP_CPU_ADDIU(u32 instr, u32 rtVal, u32 rsVal);
void PGXP_CPU_ANDI(u32 instr, u32 rtVal, u32 rsVal);
void PGXP_CPU_ORI(u32 instr, u32 rtVal, u32 rsVal);
void PGXP_CPU_XORI(u32 instr, u32 rtVal, u32 rsVal);
void PGXP_CPU_SLTI(u32 instr, u32 rtVal, u32 rsVal);
void PGXP_CPU_SLTIU(u32 instr, u32 rtVal, u32 rsVal);

// Load Upper
void PGXP_CPU_LUI(u32 instr, u32 rtVal);

// Register Arithmetic
void PGXP_CPU_ADD(u32 instr, u32 rdVal, u32 rsVal, u32 rtVal);
void PGXP_CPU_ADDU(u32 instr, u32 rdVal, u32 rsVal, u32 rtVal);
void PGXP_CPU_SUB(u32 instr, u32 rdVal, u32 rsVal, u32 rtVal);
void PGXP_CPU_SUBU(u32 instr, u32 rdVal, u32 rsVal, u32 rtVal);
void PGXP_CPU_AND(u32 instr, u32 rdVal, u32 rsVal, u32 rtVal);
void PGXP_CPU_OR(u32 instr, u32 rdVal, u32 rsVal, u32 rtVal);
void PGXP_CPU_XOR(u32 instr, u32 rdVal, u32 rsVal, u32 rtVal);
void PGXP_CPU_NOR(u32 instr, u32 rdVal, u32 rsVal, u32 rtVal);
void PGXP_CPU_SLT(u32 instr, u32 rdVal, u32 rsVal, u32 rtVal);
void PGXP_CPU_SLTU(u32 instr, u32 rdVal, u32 rsVal, u32 rtVal);

// Register mult/div
void PGXP_CPU_MULT(u32 instr, u32 hiVal, u32 loVal, u32 rsVal, u32 rtVal);
void PGXP_CPU_MULTU(u32 instr, u32 hiVal, u32 loVal, u32 rsVal, u32 rtVal);
void PGXP_CPU_DIV(u32 instr, u32 hiVal, u32 loVal, u32 rsVal, u32 rtVal);
void PGXP_CPU_DIVU(u32 instr, u32 hiVal, u32 loVal, u32 rsVal, u32 rtVal);

// Shift operations (sa)
void PGXP_CPU_SLL(u32 instr, u32 rdVal, u32 rtVal);
void PGXP_CPU_SRL(u32 instr, u32 rdVal, u32 rtVal);
void PGXP_CPU_SRA(u32 instr, u32 rdVal, u32 rtVal);

// Shift operations variable
void PGXP_CPU_SLLV(u32 instr, u32 rdVal, u32 rtVal, u32 rsVal);
void PGXP_CPU_SRLV(u32 instr, u32 rdVal, u32 rtVal, u32 rsVal);
void PGXP_CPU_SRAV(u32 instr, u32 rdVal, u32 rtVal, u32 rsVal);

// Move registers
void PGXP_CPU_MFHI(u32 instr, u32 rdVal, u32 hiVal);
void PGXP_CPU_MTHI(u32 instr, u32 hiVal, u32 rdVal);
void PGXP_CPU_MFLO(u32 instr, u32 rdVal, u32 loVal);
void PGXP_CPU_MTLO(u32 instr, u32 loVal, u32 rdVal);

// CP0 Data transfer tracking
void PGXP_CP0_MFC0(u32 instr, u32 rtVal, u32 rdVal);
void PGXP_CP0_MTC0(u32 instr, u32 rdVal, u32 rtVal);
void PGXP_CP0_CFC0(u32 instr, u32 rtVal, u32 rdVal);
void PGXP_CP0_CTC0(u32 instr, u32 rdVal, u32 rtVal);
void PGXP_CP0_RFE(u32 instr);

#ifdef __cplusplus
}
#endif

#endif  //_PGXP_CPU_H_
