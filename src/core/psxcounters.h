/***************************************************************************
 *   Copyright (C) 2010 by Blade_Arma                                      *
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

#ifndef __PSXCOUNTERS_H__
#define __PSXCOUNTERS_H__

#include "core/plugins.h"
#include "core/psxcommon.h"
#include "core/psxmem.h"
#include "core/r3000a.h"

extern uint32_t g_psxNextCounter, g_psxNextsCounter;

void psxRcntInit();
void psxRcntUpdate();

void psxRcntWcount(uint32_t index, uint32_t value);
void psxRcntWmode(uint32_t index, uint32_t value);
void psxRcntWtarget(uint32_t index, uint32_t value);

uint32_t psxRcntRcount(uint32_t index);
uint32_t psxRcntRmode(uint32_t index);
uint32_t psxRcntRtarget(uint32_t index);

int32_t psxRcntFreeze(gzFile f, int32_t Mode);

#endif
