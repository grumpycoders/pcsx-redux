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
 *  pgxp_cpu.h
 *  PGXP - Parallel/Precision Geometry Xform Pipeline
 *
 *  Created on: 07 Jun 2016
 *      Author: iCatButler
 ***************************************************************************/

#ifndef _PGXP_CPU_H_
#define _PGXP_CPU_H_

#include "core/psxemulator.h"

struct PGXP_value_Tag;
typedef struct PGXP_value_Tag PGXP_value;

extern PGXP_value* g_CPU_reg;
extern PGXP_value* g_CP0_reg;
#define CPU_Hi g_CPU_reg[33]
#define CPU_Lo g_CPU_reg[34]

void PGXP_InitCPU();

// -- CPU functions

// Load 32-bit word
void PGXP_CPU_LWL(uint32_t instr, uint32_t rtVal, uint32_t addr);
void PGXP_CPU_LW(uint32_t instr, uint32_t rtVal, uint32_t addr);
void PGXP_CPU_LWR(uint32_t instr, uint32_t rtVal, uint32_t addr);

// Load 16-bit
void PGXP_CPU_LH(uint32_t instr, uint16_t rtVal, uint32_t addr);
void PGXP_CPU_LHU(uint32_t instr, uint16_t rtVal, uint32_t addr);

// Load 8-bit
void PGXP_CPU_LB(uint32_t instr, uint8_t rtVal, uint32_t addr);
void PGXP_CPU_LBU(uint32_t instr, uint8_t rtVal, uint32_t addr);

// Store 32-bit word
void PGXP_CPU_SWL(uint32_t instr, uint32_t rtVal, uint32_t addr);
void PGXP_CPU_SW(uint32_t instr, uint32_t rtVal, uint32_t addr);
void PGXP_CPU_SWR(uint32_t instr, uint32_t rtVal, uint32_t addr);

// Store 16-bit
void PGXP_CPU_SH(uint32_t instr, uint16_t rtVal, uint32_t addr);

// Store 8-bit
void PGXP_CPU_SB(uint32_t instr, uint8_t rtVal, uint32_t addr);

// Arithmetic with immediate value
void PGXP_CPU_ADDI(uint32_t instr, uint32_t rtVal, uint32_t rsVal);
void PGXP_CPU_ADDIU(uint32_t instr, uint32_t rtVal, uint32_t rsVal);
void PGXP_CPU_ANDI(uint32_t instr, uint32_t rtVal, uint32_t rsVal);
void PGXP_CPU_ORI(uint32_t instr, uint32_t rtVal, uint32_t rsVal);
void PGXP_CPU_XORI(uint32_t instr, uint32_t rtVal, uint32_t rsVal);
void PGXP_CPU_SLTI(uint32_t instr, uint32_t rtVal, uint32_t rsVal);
void PGXP_CPU_SLTIU(uint32_t instr, uint32_t rtVal, uint32_t rsVal);

// Load Upper
void PGXP_CPU_LUI(uint32_t instr, uint32_t rtVal);

// Register Arithmetic
void PGXP_CPU_ADD(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal);
void PGXP_CPU_ADDU(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal);
void PGXP_CPU_SUB(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal);
void PGXP_CPU_SUBU(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal);
void PGXP_CPU_AND(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal);
void PGXP_CPU_OR(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal);
void PGXP_CPU_XOR(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal);
void PGXP_CPU_NOR(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal);
void PGXP_CPU_SLT(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal);
void PGXP_CPU_SLTU(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal);

// Register mult/div
void PGXP_CPU_MULT(uint32_t instr, uint32_t hiVal, uint32_t loVal, uint32_t rsVal, uint32_t rtVal);
void PGXP_CPU_MULTU(uint32_t instr, uint32_t hiVal, uint32_t loVal, uint32_t rsVal, uint32_t rtVal);
void PGXP_CPU_DIV(uint32_t instr, uint32_t hiVal, uint32_t loVal, uint32_t rsVal, uint32_t rtVal);
void PGXP_CPU_DIVU(uint32_t instr, uint32_t hiVal, uint32_t loVal, uint32_t rsVal, uint32_t rtVal);

// Shift operations (sa)
void PGXP_CPU_SLL(uint32_t instr, uint32_t rdVal, uint32_t rtVal);
void PGXP_CPU_SRL(uint32_t instr, uint32_t rdVal, uint32_t rtVal);
void PGXP_CPU_SRA(uint32_t instr, uint32_t rdVal, uint32_t rtVal);

// Shift operations variable
void PGXP_CPU_SLLV(uint32_t instr, uint32_t rdVal, uint32_t rtVal, uint32_t rsVal);
void PGXP_CPU_SRLV(uint32_t instr, uint32_t rdVal, uint32_t rtVal, uint32_t rsVal);
void PGXP_CPU_SRAV(uint32_t instr, uint32_t rdVal, uint32_t rtVal, uint32_t rsVal);

// Move registers
void PGXP_CPU_MFHI(uint32_t instr, uint32_t rdVal, uint32_t hiVal);
void PGXP_CPU_MTHI(uint32_t instr, uint32_t hiVal, uint32_t rdVal);
void PGXP_CPU_MFLO(uint32_t instr, uint32_t rdVal, uint32_t loVal);
void PGXP_CPU_MTLO(uint32_t instr, uint32_t loVal, uint32_t rdVal);

// CP0 Data transfer tracking
void PGXP_CP0_MFC0(uint32_t instr, uint32_t rtVal, uint32_t rdVal);
void PGXP_CP0_MTC0(uint32_t instr, uint32_t rdVal, uint32_t rtVal);
void PGXP_CP0_CFC0(uint32_t instr, uint32_t rtVal, uint32_t rdVal);
void PGXP_CP0_CTC0(uint32_t instr, uint32_t rdVal, uint32_t rtVal);
void PGXP_CP0_RFE(uint32_t instr);

#endif  //_PGXP_CPU_H_
