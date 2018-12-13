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

#define INFO_TW        0
#define INFO_DRAWSTART 1
#define INFO_DRAWEND   2
#define INFO_DRAWOFF   3

#define SHADETEXBIT(x) ((x>>24) & 0x1)
#define SEMITRANSBIT(x) ((x>>25) & 0x1)
#define PSXRGB(r,g,b) ((g<<10)|(b<<5)|r)

#define DATAREGISTERMODES unsigned short

#define DR_NORMAL        0
#define DR_VRAMTRANSFER  1


#define GPUSTATUS_ODDLINES            0x80000000
#define GPUSTATUS_DMABITS             0x60000000 // Two bits
#define GPUSTATUS_READYFORCOMMANDS    0x10000000
#define GPUSTATUS_READYFORVRAM        0x08000000
#define GPUSTATUS_IDLE                0x04000000
#define GPUSTATUS_DISPLAYDISABLED     0x00800000
#define GPUSTATUS_INTERLACED          0x00400000
#define GPUSTATUS_RGB24               0x00200000
#define GPUSTATUS_PAL                 0x00100000
#define GPUSTATUS_DOUBLEHEIGHT        0x00080000
#define GPUSTATUS_WIDTHBITS           0x00070000 // Three bits
#define GPUSTATUS_MASKENABLED         0x00001000
#define GPUSTATUS_MASKDRAWN           0x00000800
#define GPUSTATUS_DRAWINGALLOWED      0x00000400
#define GPUSTATUS_DITHER              0x00000200

#define GPUIsBusy (lGPUstatusRet &= ~GPUSTATUS_IDLE)
#define GPUIsIdle (lGPUstatusRet |= GPUSTATUS_IDLE)

#define GPUIsNotReadyForCommands (lGPUstatusRet &= ~GPUSTATUS_READYFORCOMMANDS)
#define GPUIsReadyForCommands (lGPUstatusRet |= GPUSTATUS_READYFORCOMMANDS)

#ifdef _WIN32

#ifndef  STRICT
#define  STRICT
#endif
#define  D3D_OVERLOADS
#define  DIRECT3D_VERSION 0x600
#define  CINTERFACE
#ifndef  WINVER
#define  WINVER 0x0500
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <windows.h>
#include <windowsx.h>
#include <tchar.h>
//#include "resource.h"

#include "ddraw.h"
#include "d3dtypes.h"
#include "d3d.h"

#ifdef _MSC_VER
#pragma warning (disable:864)
#pragma warning (disable:4244)
#pragma warning (disable:4996)
#endif

#else

#define __X11_C_
//X11 render
#define __inline inline
#define CALLBACK

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#ifndef _MACGL
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/cursorfont.h>
#endif
#include <math.h>
#include <stdint.h>

#endif

/////////////////////////////////////////////////////////////////////////////

typedef struct VRAMLOADTTAG
{
 short x;
 short y;
 short Width;
 short Height;
 short RowsRemaining;
 short ColsRemaining;
 unsigned short *ImagePtr;
} VRAMLoad_t;

/////////////////////////////////////////////////////////////////////////////

typedef struct PSXPOINTTAG
{
 int32_t x;
 int32_t y;
} PSXPoint_t;

typedef struct PSXSPOINTTAG
{
 short x;
 short y;
} PSXSPoint_t;

typedef struct PSXRECTTAG
{
 short x0;
 short x1;
 short y0;
 short y1;
} PSXRect_t;

#ifdef _WIN32

typedef struct SDXTAG
{
 LPDIRECTDRAW                   DD;

 LPDIRECTDRAWSURFACE            DDSPrimary;
 LPDIRECTDRAWSURFACE            DDSRender;
 LPDIRECTDRAWSURFACE            DDSHelper;
 LPDIRECTDRAWSURFACE            DDSScreenPic;
 HWND                           hWnd;
} sDX;

#else

// linux defines for some windows stuff

#define FALSE 0
#define TRUE 1
#define BOOL unsigned short
#define LOWORD(l)           ((unsigned short)(l))
#define HIWORD(l)           ((unsigned short)(((uint32_t)(l) >> 16) & 0xFFFF))
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#define DWORD uint32_t
#define __int64 long long int

typedef struct RECTTAG
{
 int left;
 int top;
 int right;
 int bottom;
} RECT;

#endif

/////////////////////////////////////////////////////////////////////////////

typedef struct TWINTAG
{
 PSXRect_t  Position;
} TWin_t;

/////////////////////////////////////////////////////////////////////////////

typedef struct PSXDISPLAYTAG
{
 PSXPoint_t  DisplayModeNew;
 PSXPoint_t  DisplayMode;
 PSXPoint_t  DisplayPosition;
 PSXPoint_t  DisplayEnd;

 int32_t        Double;
 int32_t        Height;
 int32_t        PAL;
 int32_t        InterlacedNew;
 int32_t        Interlaced;
 int32_t        RGB24New;
 int32_t        RGB24;
 PSXSPoint_t DrawOffset;
 int32_t        Disabled;
 PSXRect_t   Range;

} PSXDisplay_t;

#ifdef _WIN32
extern HINSTANCE hInst;
extern HMODULE hDDrawDLL;
#endif

/////////////////////////////////////////////////////////////////////////////

// draw.c

#ifndef _IN_DRAW

#ifdef _WIN32
extern sDX            DX;
extern HWND           hWGPU;
extern GUID           guiDev;
extern int            iRefreshRate;
extern BOOL           bVsync;
extern BOOL           bVsync_Key;
#else
extern char *         pCaptionText;
#endif

extern int            iResX;
extern int            iResY;
extern int32_t           GlobalTextAddrX,GlobalTextAddrY,GlobalTextTP;
extern int32_t           GlobalTextREST,GlobalTextABR,GlobalTextPAGE;
extern short          ly0,lx0,ly1,lx1,ly2,lx2,ly3,lx3;
extern long           lLowerpart;
extern BOOL           bIsFirstFrame;
extern int            iWinSize;
extern BOOL           bCheckMask;
extern unsigned short sSetMask;
extern unsigned long  lSetMask;
extern BOOL           bDeviceOK;
extern short          g_m1;
extern short          g_m2;
extern short          g_m3;
extern short          DrawSemiTrans;
extern int            iUseGammaVal;
#ifdef _WIN32
extern int            iUseScanLines;
#endif
extern int            iMaintainAspect;
extern int            iDesktopCol;
extern int            iUseNoStretchBlt;
extern int            iShowFPS;
extern int            iFastFwd;
extern int            iDebugMode;
extern int            iFVDisplay;
extern PSXPoint_t     ptCursorPoint[];
extern unsigned short usCursorActive;

#ifdef _WIN32
extern int            iSysMemory;
#endif

#endif

// prim.c

#ifndef _IN_PRIMDRAW

extern BOOL           bUsingTWin;
extern TWin_t         TWin;
//extern unsigned long  clutid;
extern void (*primTableJ[256])(unsigned char *);
extern void (*primTableSkip[256])(unsigned char *);
extern unsigned short  usMirror;
extern int            iDither;
extern uint32_t  dwCfgFixes;
extern uint32_t  dwActFixes;
extern uint32_t  dwEmuFixes;
extern int            iUseFixes;
extern int            iUseDither;
extern BOOL           bDoVSyncUpdate;
extern int32_t           drawX;
extern int32_t           drawY;
extern int32_t           drawW;
extern int32_t           drawH;

#endif

// gpu.c

#ifndef _IN_GPU

extern VRAMLoad_t     VRAMWrite;
extern VRAMLoad_t     VRAMRead;
extern DATAREGISTERMODES DataWriteMode;
extern DATAREGISTERMODES DataReadMode;
extern int            iColDepth;
extern int            iWindowMode;
extern char           szDispBuf[];
extern char           szMenuBuf[];
extern char           szDebugText[];
extern short          sDispWidths[];
extern BOOL           bDebugText;
//extern unsigned int   iMaxDMACommandCounter;
//extern unsigned long  dwDMAChainStop;
extern PSXDisplay_t   PSXDisplay;
extern PSXDisplay_t   PreviousPSXDisplay;
extern BOOL           bSkipNextFrame;
extern long           lGPUstatusRet;
//extern long           drawingLines;
extern unsigned char  * psxVSecure;
extern unsigned char  * psxVub;
extern signed char    * psxVsb;
extern unsigned short * psxVuw;
extern signed short   * psxVsw;
extern uint32_t  * psxVul;
extern int32_t    * psxVsl;
extern unsigned short * psxVuw_eom;
extern BOOL           bChangeWinMode;
extern long           lSelectedSlot;
extern BOOL           bInitCap;
extern DWORD          dwLaceCnt;
extern uint32_t  lGPUInfoVals[];
extern uint32_t  ulStatusControl[];
extern uint32_t  vBlank;
extern int            iRumbleVal;
extern int            iRumbleTime;

#endif

// menu.c

#ifndef _IN_MENU

extern uint32_t dwCoreFlags;

#ifdef _WIN32
extern HFONT hGFont;
extern int   iMPos;
extern BOOL  bTransparent;
#endif

#endif

// key.c

#ifndef _IN_KEY

extern unsigned long  ulKeybits;

#ifdef _WIN32
extern char           szGPUKeys[];
#endif

#endif

// fps.c

#ifndef _IN_FPS

extern int            UseFrameLimit;
extern int            UseFrameSkip;
extern float          fFrameRate;
extern int            iFrameLimit;
extern float          fFrameRateHz;
extern float          fps_skip;
extern float          fps_cur;
#ifdef _WIN32
extern BOOL           IsPerformanceCounter;
extern int			  iStopSaver;
#endif

#endif

// key.c

#ifndef _IN_KEY

#endif

// cfg.c

#ifndef _IN_CFG

extern char * pConfigFile;

#endif

// zn.c

#ifndef _IN_ZN

extern uint32_t dwGPUVersion;
extern int           iGPUHeight;
extern int           iGPUHeightMask;
extern int           GlobalTextIL;
extern int           iTileCheat;

#endif
