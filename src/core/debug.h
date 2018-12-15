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

#ifndef __DEBUG_H__
#define __DEBUG_H__

#include "psxcommon.h"

#ifdef __cplusplus
extern "C" {
#endif

enum breakpoint_types { BE, BR1, BR2, BR4, BW1, BW2, BW4 };

void StartDebugger();
void StopDebugger();

void DebugVSync();
void ProcessDebug();

void DebugCheckBP(u32 address, enum breakpoint_types type);

void PauseDebugger();
void ResumeDebugger();

extern char *disRNameGPR[];
extern char *disRNameCP2D[];
extern char *disRNameCP2C[];
extern char *disRNameCP0[];

char *disR3000AF(u32 code, u32 pc);

/*
 * Specficies which logs should be activated.
 */

//#define LOG_STDOUT

//#define PAD_LOG  __Log
//#define SIO1_LOG  __Log
//#define GTE_LOG  __Log
//#define CDR_LOG  __Log("%8.8lx %8.8lx: ", g_psxRegs.pc, g_psxRegs.cycle); __Log
//#define CDR_LOG_IO  __Log("%8.8lx %8.8lx: ", g_psxRegs.pc, g_psxRegs.cycle); __Log

//#define PSXHW_LOG   __Log("%8.8lx %8.8lx: ", g_psxRegs.pc, g_psxRegs.cycle); __Log
//#define PSXBIOS_LOG __Log("%8.8lx %8.8lx: ", g_psxRegs.pc, g_psxRegs.cycle); __Log
//#define PSXDMA_LOG  __Log
//#define PSXMEM_LOG  __Log("%8.8lx %8.8lx: ", g_psxRegs.pc, g_psxRegs.cycle); __Log
//#define PSXCPU_LOG  __Log

#if defined(PSXCPU_LOG) || defined(PSXDMA_LOG) || defined(CDR_LOG) || defined(PSXHW_LOG) || defined(PSXBIOS_LOG) || \
    defined(PSXMEM_LOG) || defined(GTE_LOG) || defined(PAD_LOG) || defined(SIO1_LOG)
#define EMU_LOG __Log
#endif

#ifdef __cplusplus
}
#endif
#endif
