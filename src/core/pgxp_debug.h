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
 *  pgxp_debug.h
 *  PGXP - Parallel/Precision Geometry Xform Pipeline
 *
 *  Created on: 07 Jun 2016
 *      Author: iCatButler
 ***************************************************************************/

#ifndef _PGXP_DEBUG_H_
#define _PGXP_DEBUG_H_

#include "psxemulator.h"

//#define PGXP_CPU_DEBUG
//#define PGXP_OUTPUT_ALL
//#define PGXP_FORCE_INPUT_VALUES
//#define PGXP_TEST_OUTPUT_VALUES

#define PGXP_DEBUG_TOLERANCE 2.f

// Debug wrappers
void PGXP_psxTraceOp(uint32_t eOp, uint32_t code);
void PGXP_psxTraceOp1(uint32_t eOp, uint32_t code, uint32_t op1);
void PGXP_psxTraceOp2(uint32_t eOp, uint32_t code, uint32_t op1, uint32_t op2);
void PGXP_psxTraceOp3(uint32_t eOp, uint32_t code, uint32_t op1, uint32_t op2, uint32_t op3);
void PGXP_psxTraceOp4(uint32_t eOp, uint32_t code, uint32_t op1, uint32_t op2, uint32_t op3, uint32_t op4);

extern unsigned int g_pgxp_debug;

// Op flags
enum PGXP_DBG_Enum {
    DBG_E_SPECIAL,
    DBG_E_REGIMM,
    DBG_E_J,
    DBG_E_JAL,
    DBG_E_BEQ,
    DBG_E_BNE,
    DBG_E_BLEZ,
    DBG_E_BGTZ,
    DBG_E_ADDI,
    DBG_E_ADDIU,
    DBG_E_SLTI,
    DBG_E_SLTIU,
    DBG_E_ANDI,
    DBG_E_ORI,
    DBG_E_XORI,
    DBG_E_LUI,
    DBG_E_COP0,
    DBG_E_COP2,
    DBG_E_LB,
    DBG_E_LH,
    DBG_E_LWL,
    DBG_E_LW,
    DBG_E_LBU,
    DBG_E_LHU,
    DBG_E_LWR,
    DBG_E_SB,
    DBG_E_SH,
    DBG_E_SWL,
    DBG_E_SW,
    DBG_E_SWR,
    DBG_E_LWC2,
    DBG_E_SWC2,
    DBG_E_HLE,
    DBG_E_SLL,
    DBG_E_SRL,
    DBG_E_SRA,
    DBG_E_SLLV,
    DBG_E_SRLV,
    DBG_E_SRAV,
    DBG_E_JR,
    DBG_E_JALR,
    DBG_E_SYSCALL,
    DBG_E_BREAK,
    DBG_E_MFHI,
    DBG_E_MTHI,
    DBG_E_MFLO,
    DBG_E_MTLO,
    DBG_E_MULT,
    DBG_E_MULTU,
    DBG_E_DIV,
    DBG_E_DIVU,
    DBG_E_ADD,
    DBG_E_ADDU,
    DBG_E_SUB,
    DBG_E_SUBU,
    DBG_E_AND,
    DBG_E_OR,
    DBG_E_XOR,
    DBG_E_NOR,
    DBG_E_SLT,
    DBG_E_SLTU,
    DBG_E_BLTZ,
    DBG_E_BGEZ,
    DBG_E_BLTZAL,
    DBG_E_BGEZAL,
    DBG_E_MFC0,
    DBG_E_CFC0,
    DBG_E_MTC0,
    DBG_E_CTC0,
    DBG_E_RFE,
    DBG_E_BASIC,
    DBG_E_RTPS,
    DBG_E_NCLIP,
    DBG_E_OP,
    DBG_E_DPCS,
    DBG_E_INTPL,
    DBG_E_MVMVA,
    DBG_E_NCDS,
    DBG_E_CDP,
    DBG_E_NCDT,
    DBG_E_NCCS,
    DBG_E_CC,
    DBG_E_NCS,
    DBG_E_NCT,
    DBG_E_SQR,
    DBG_E_DCPL,
    DBG_E_DPCT,
    DBG_E_AVSZ3,
    DBG_E_AVSZ4,
    DBG_E_RTPT,
    DBG_E_GPF,
    DBG_E_GPL,
    DBG_E_NCCT,
    DBG_E_MFC2,
    DBG_E_CFC2,
    DBG_E_MTC2,
    DBG_E_CTC2,
    DBG_E_NULL,
    DBG_E_ERROR
};

#endif  //_PGXP_DEBUG_H_
