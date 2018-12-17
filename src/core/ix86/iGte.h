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

#ifndef __IGTE_H__
#define __IGTE_H__

#include "core/psxmem.h"
#include "core/r3000a.h"

#define CP2_FUNC(f)                                       \
    void gte##f();                                        \
    static void rec##f() {                                \
        iFlushRegs();                                     \
        MOV32ItoM((uint32_t)&PCSX::g_emulator.m_psxCpu->m_psxRegs.code, (uint32_t)PCSX::g_emulator.m_psxCpu->m_psxRegs.code); \
        CALLFunc((uint32_t)gte##f);                            \
        /*	branch = 2; */                                 \
    }

CP2_FUNC(MFC2);
CP2_FUNC(MTC2);
CP2_FUNC(CFC2);
CP2_FUNC(CTC2);
CP2_FUNC(LWC2);
CP2_FUNC(SWC2);
CP2_FUNC(RTPS);
CP2_FUNC(OP);
CP2_FUNC(NCLIP);
CP2_FUNC(DPCS);
CP2_FUNC(INTPL);
CP2_FUNC(MVMVA);
CP2_FUNC(NCDS);
CP2_FUNC(NCDT);
CP2_FUNC(CDP);
CP2_FUNC(NCCS);
CP2_FUNC(CC);
CP2_FUNC(NCS);
CP2_FUNC(NCT);
CP2_FUNC(SQR);
CP2_FUNC(DCPL);
CP2_FUNC(DPCT);
CP2_FUNC(AVSZ3);
CP2_FUNC(AVSZ4);
CP2_FUNC(RTPT);
CP2_FUNC(GPF);
CP2_FUNC(GPL);
CP2_FUNC(NCCT);

#endif
