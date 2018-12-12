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
 *	pgxp_mem.h
 *	PGXP - Parallel/Precision Geometry Xform Pipeline
 *
 *	Created on: 07 Jun 2016
 *      Author: iCatButler
 ***************************************************************************/

#ifndef _PGXP_MEM_H_
#define _PGXP_MEM_H_

#include "psxcommon.h"

void PGXP_Init();     // initialise memory
char* PGXP_GetMem();  // return pointer to precision memory
u32 PGXP_ConvertAddress(u32 addr);

struct PGXP_value_Tag;
typedef struct PGXP_value_Tag PGXP_value;

PGXP_value* GetPtr(u32 addr);
PGXP_value* ReadMem(u32 addr);

void ValidateAndCopyMem(PGXP_value* dest, u32 addr, u32 value);
void ValidateAndCopyMem16(PGXP_value* dest, u32 addr, u32 value, int sign);

void WriteMem(PGXP_value* value, u32 addr);
void WriteMem16(PGXP_value* src, u32 addr);

#endif  //_PGXP_MEM_H_