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
 *	pgxp_gte.h
 *	PGXP - Parallel/Precision Geometry Xform Pipeline
 *
 *	Created on: 12 Mar 2016
 *      Author: iCatButler
 ***************************************************************************/

#ifndef _PGXP_GTE_H_
#define _PGXP_GTE_H_

#include "core/psxemulator.h"

struct PGXP_value_Tag;
typedef struct PGXP_value_Tag PGXP_value;

extern PGXP_value* g_GTE_data_reg;
extern PGXP_value* g_GTE_ctrl_reg;

void PGXP_InitGTE();

// -- GTE functions
// Transforms
void PGXP_pushSXYZ2f(float _x, float _y, float _z, unsigned int _v);
void PGXP_pushSXYZ2s(int64_t _x, int64_t _y, int64_t _z, uint32_t v);

void PGXP_RTPS(uint32_t _n, uint32_t _v);

int PGXP_NLCIP_valid(uint32_t sxy0, uint32_t sxy1, uint32_t sxy2);
float PGXP_NCLIP();

// Data transfer tracking
void PGXP_GTE_MFC2(uint32_t instr, uint32_t rtVal, uint32_t rdVal);  // copy GTE data reg to GPR reg (MFC2)
void PGXP_GTE_MTC2(uint32_t instr, uint32_t rdVal, uint32_t rtVal);  // copy GPR reg to GTE data reg (MTC2)
void PGXP_GTE_CFC2(uint32_t instr, uint32_t rtVal, uint32_t rdVal);  // copy GTE ctrl reg to GPR reg (CFC2)
void PGXP_GTE_CTC2(uint32_t instr, uint32_t rdVal, uint32_t rtVal);  // copy GPR reg to GTE ctrl reg (CTC2)
// Memory Access
void PGXP_GTE_LWC2(uint32_t instr, uint32_t rtVal, uint32_t addr);  // copy memory to GTE reg
void PGXP_GTE_SWC2(uint32_t instr, uint32_t rtVal, uint32_t addr);  // copy GTE reg to memory

#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#endif /* _PGXP_GTE_H_ */
