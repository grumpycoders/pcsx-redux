/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include <cstdint>

#define INFO_TW 0
#define INFO_DRAWSTART 1
#define INFO_DRAWEND 2
#define INFO_DRAWOFF 3

#define SHADETEXBIT(x) ((x >> 24) & 0x1)
#define SEMITRANSBIT(x) ((x >> 25) & 0x1)
#define PSXRGB(r, g, b) ((g << 10) | (b << 5) | r)

#define DATAREGISTERMODES uint16_t

#define DR_NORMAL 0
#define DR_VRAMTRANSFER 1

#define GPUSTATUS_ODDLINES 0x80000000
#define GPUSTATUS_DMABITS 0x60000000  // Two bits
#define GPUSTATUS_READYFORCOMMANDS 0x10000000
#define GPUSTATUS_READYFORVRAM 0x08000000
#define GPUSTATUS_IDLE 0x04000000
#define GPUSTATUS_DISPLAYDISABLED 0x00800000
#define GPUSTATUS_INTERLACED 0x00400000
#define GPUSTATUS_RGB24 0x00200000
#define GPUSTATUS_PAL 0x00100000
#define GPUSTATUS_DOUBLEHEIGHT 0x00080000
#define GPUSTATUS_WIDTHBITS 0x00070000  // Three bits
#define GPUSTATUS_MASKENABLED 0x00001000
#define GPUSTATUS_MASKDRAWN 0x00000800
#define GPUSTATUS_DRAWINGALLOWED 0x00000400
#define GPUSTATUS_DITHER 0x00000200

#define GPUIsBusy (lGPUstatusRet &= ~GPUSTATUS_IDLE)
#define GPUIsIdle (lGPUstatusRet |= GPUSTATUS_IDLE)

#define GPUIsNotReadyForCommands (lGPUstatusRet &= ~GPUSTATUS_READYFORCOMMANDS)
#define GPUIsReadyForCommands (lGPUstatusRet |= GPUSTATUS_READYFORCOMMANDS)

/////////////////////////////////////////////////////////////////////////////

struct VRAMLoad_t {
    int16_t x;
    int16_t y;
    int16_t Width;
    int16_t Height;
    int16_t RowsRemaining;
    int16_t ColsRemaining;
    uint16_t *ImagePtr;
};

struct PSXPoint_t {
    int32_t x;
    int32_t y;
};

struct PSXSPoint_t {
    int16_t x;
    int16_t y;
};

struct PSXRect_t {
    int16_t x0;
    int16_t x1;
    int16_t y0;
    int16_t y1;
};

struct TWin_t {
    PSXRect_t Position;
};

struct PSXDisplay_t {
    PSXPoint_t DisplayModeNew;
    PSXPoint_t DisplayMode;
    PSXPoint_t DisplayPosition;
    PSXPoint_t DisplayEnd;

    int32_t Double;
    int32_t Height;
    int32_t PAL;
    int32_t InterlacedNew;
    int32_t Interlaced;
    int32_t RGB24New;
    int32_t RGB24;
    PSXSPoint_t DrawOffset;
    int32_t Disabled;
    PSXRect_t Range;
};

// draw.cc

namespace PCSX {
class GUI;
}

// prim.cc

extern uint32_t dwCfgFixes;
extern uint32_t dwActFixes;
extern uint32_t dwEmuFixes;
extern int iUseFixes;
extern bool bDoVSyncUpdate;

// gpu.cc
extern VRAMLoad_t VRAMWrite;
extern VRAMLoad_t VRAMRead;
extern DATAREGISTERMODES DataWriteMode;
extern DATAREGISTERMODES DataReadMode;
extern int iColDepth;
extern int iWindowMode;
extern char szDispBuf[];
extern char szMenuBuf[];
extern char szDebugText[];
extern int16_t sDispWidths[];
extern bool bDebugText;
extern PSXDisplay_t PSXDisplay;
extern PSXDisplay_t PreviousPSXDisplay;
extern bool bSkipNextFrame;
extern int32_t lGPUstatusRet;
extern int32_t drawingLines;
extern unsigned char *psxVSecure;
extern unsigned char *psxVub;
extern signed char *psxVsb;
extern uint16_t *psxVuw;
extern int16_t *psxVsw;
extern uint32_t *psxVul;
extern int32_t *psxVsl;
extern uint16_t *psxVuw_eom;
extern bool bChangeWinMode;
extern int32_t lSelectedSlot;
extern uint32_t dwLaceCnt;
extern uint32_t lGPUInfoVals[];
extern int iRumbleVal;
extern int iRumbleTime;

constexpr uint32_t dwGPUVersion = 0;
constexpr int iGPUHeight = 512;
constexpr int iGPUHeightMask = 511;
constexpr int iTileCheat = 0;
