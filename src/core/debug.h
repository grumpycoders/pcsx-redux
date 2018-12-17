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

#pragma once

#include "core/psxemulator.h"
#include "core/system.h"

enum breakpoint_types { BE, BR1, BR2, BR4, BW1, BW2, BW4 };

void StartDebugger();
void StopDebugger();

void DebugVSync();
void ProcessDebug();

void DebugCheckBP(uint32_t address, enum breakpoint_types type);

void PauseDebugger();
void ResumeDebugger();

extern const char *g_disRNameGPR[];
extern const char *g_disRNameCP2D[];
extern const char *g_disRNameCP2C[];
extern const char *g_disRNameCP0[];

char *disR3000AF(uint32_t code, uint32_t pc);
