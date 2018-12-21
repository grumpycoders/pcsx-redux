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

#ifndef __MDEC_H__
#define __MDEC_H__

#include "core/psxdma.h"
#include "core/psxemulator.h"
#include "core/psxhw.h"
#include "core/r3000a.h"

void mdecInit();
void mdecWrite0(uint32_t data);
void mdecWrite1(uint32_t data);
uint32_t mdecRead0();
uint32_t mdecRead1();
void psxDma0(uint32_t madr, uint32_t bcr, uint32_t chcr);
void psxDma1(uint32_t madr, uint32_t bcr, uint32_t chcr);
void mdec1Interrupt();
int mdecFreeze(gzFile f, int Mode);

#endif
