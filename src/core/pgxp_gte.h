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

#include "psxcommon.h"

struct PGXP_value_Tag;
typedef struct PGXP_value_Tag PGXP_value;

extern PGXP_value* g_GTE_data_reg;
extern PGXP_value* g_GTE_ctrl_reg;

void PGXP_InitGTE();

// -- GTE functions
// Transforms
void PGXP_pushSXYZ2f(float _x, float _y, float _z, unsigned int _v);
void PGXP_pushSXYZ2s(s64 _x, s64 _y, s64 _z, u32 v);

void PGXP_RTPS(u32 _n, u32 _v);

int PGXP_NLCIP_valid(u32 sxy0, u32 sxy1, u32 sxy2);
float PGXP_NCLIP();

// Data transfer tracking
void PGXP_GTE_MFC2(u32 instr, u32 rtVal, u32 rdVal);  // copy GTE data reg to GPR reg (MFC2)
void PGXP_GTE_MTC2(u32 instr, u32 rdVal, u32 rtVal);  // copy GPR reg to GTE data reg (MTC2)
void PGXP_GTE_CFC2(u32 instr, u32 rtVal, u32 rdVal);  // copy GTE ctrl reg to GPR reg (CFC2)
void PGXP_GTE_CTC2(u32 instr, u32 rdVal, u32 rtVal);  // copy GPR reg to GTE ctrl reg (CTC2)
// Memory Access
void PGXP_GTE_LWC2(u32 instr, u32 rtVal, u32 addr);  // copy memory to GTE reg
void PGXP_GTE_SWC2(u32 instr, u32 rtVal, u32 addr);  // copy GTE reg to memory

#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#endif /* _PGXP_GTE_H_ */
