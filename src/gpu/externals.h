/***************************************************************************
                        externals.h -  description
                             -------------------
    begin                : Sun Oct 28 2001
    copyright            : (C) 2001 by Pete Bernert
    email                : BlackDove@addcom.de
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version. See also the license.txt file for *
 *   additional informations.                                              *
 *                                                                         *
 ***************************************************************************/

//*************************************************************************//
// History of changes:
//
// 2005/04/15 - Pete
// - Changed user frame limit to floating point value
//
// 2004/01/31 - Pete
// - added zn stuff
//
// 2002/04/20 - linuzappz
// - added iFastFwd var
//
// 2001/12/22 - syo
// - added vsync & transparent vars
//
// 2001/12/16 - Pete
// - added iFPSEInterface variable
//
// 2001/12/05 - syo
// - added iSysMemory and iStopSaver
//
// 2001/10/28 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#pragma once

#include <stdint.h>

/////////////////////////////////////////////////////////////////////////////

#define INFO_TW 0
#define INFO_DRAWSTART 1
#define INFO_DRAWEND 2
#define INFO_DRAWOFF 3

#define SHADETEXBIT(x) ((x >> 24) & 0x1)
#define SEMITRANSBIT(x) ((x >> 25) & 0x1)
#define PSXRGB(r, g, b) ((g << 10) | (b << 5) | r)

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

/////////////////////////////////////////////////////////////////////////////

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

/////////////////////////////////////////////////////////////////////////////

struct TWin_t {
    PSXRect_t Position;
};

/////////////////////////////////////////////////////////////////////////////

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

/////////////////////////////////////////////////////////////////////////////

// draw.c

namespace PCSX {
class GUI;
}

extern PCSX::GUI *m_gui;
extern bool bVsync_Key;

extern int iFastFwd;
extern PSXPoint_t ptCursorPoint[];
extern uint16_t usCursorActive;

// prim.c

extern uint32_t dwCfgFixes;
extern uint32_t dwActFixes;
extern uint32_t dwEmuFixes;
extern int iUseFixes;
extern bool bDoVSyncUpdate;

// gpu.c
extern int iColDepth;
extern int iWindowMode;
extern int16_t sDispWidths[];
extern bool bDebugText;
// extern unsigned int   iMaxDMACommandCounter;
// extern uint32_t  dwDMAChainStop;
extern PSXDisplay_t PSXDisplay;
extern PSXDisplay_t PreviousPSXDisplay;
extern bool bSkipNextFrame;
extern int32_t drawingLines;
extern bool bChangeWinMode;
extern int32_t lSelectedSlot;
extern uint32_t dwLaceCnt;
extern int iRumbleVal;
extern int iRumbleTime;

// menu.c
// extern uint32_t dwCoreFlags;
// extern HFONT hGFont;
extern int iMPos;
extern bool bTransparent;

// key.c
// extern uint32_t ulKeybits;
// extern char szGPUKeys[];

// fps.c
extern bool bInitCap;
extern bool UseFrameLimit;
extern bool UseFrameSkip;
extern float fFrameRate;
extern int iFrameLimit;
extern float fFrameRateHz;
extern float fps_skip;
extern float fps_cur;
extern bool UsePerformanceCounter;
extern bool bSSSPSXLimit;

// key.c

// cfg.c
extern char *pConfigFile;

// zn.c
extern int iGPUHeightMask;
extern int GlobalTextIL;
extern int iTileCheat;
