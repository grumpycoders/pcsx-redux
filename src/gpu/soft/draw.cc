/***************************************************************************
                          draw.c  -  description
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
// 2008/05/17 - Pete
// - added "visual rumble" stuff to buffer swap func
//
// 2007/10/27 - MxC
// - added HQ2X/HQ3X MMX versions, and fixed stretching
//
// 2005/06/11 - MxC
// - added HQ2X,HQ3X,Scale3X screen filters
//
// 2004/01/31 - Pete
// - added zn stuff
//
// 2003/01/31 - stsp
// - added zn stuff
//
// 2003/12/30 - Stefan Sperling <stsp@guerila.com>
// - improved XF86VM fullscreen switching a little (refresh frequency issues).
//
// 2002/12/30 - Pete
// - added Scale2x display mode - Scale2x (C) 2002 Andrea Mazzoleni - http://scale2x.sourceforge.net
//
// 2002/12/29 - Pete
// - added gun cursor display
//
// 2002/12/21 - linuzappz
// - some more messages for DGA2 errors
// - improved XStretch funcs a little
// - fixed non-streched modes for DGA2
//
// 2002/11/10 - linuzappz
// - fixed 5bit masks for 2xSai/etc
//
// 2002/11/06 - Pete
// - added 2xSai, Super2xSaI, SuperEagle
//
// 2002/08/09 - linuzappz
// - added DrawString calls for DGA2 (FPS display)
//
// 2002/03/10 - lu
// - Initial SDL-only blitting function
// - Initial SDL stretch function (using an undocumented SDL 1.2 func)
// - Boht are triggered by -D_SDL -D_SDL2
//
// 2002/02/18 - linuzappz
// - NoStretch, PIC and Scanlines support for DGA2 (32bit modes untested)
// - Fixed PIC colors in CreatePic for 16/15 bit modes
//
// 2002/02/17 - linuzappz
// - Added DGA2 support, support only with no strecthing disabled (also no FPS display)
//
// 2002/01/13 - linuzappz
// - Added timing for the szDebugText (to 2 secs)
//
// 2002/01/05 - Pete
// - fixed linux stretch centering (no more garbled screens)
//
// 2001/12/30 - Pete
// - Added linux fullscreen desktop switching (non-SDL version, define USE_XF86VM in Makefile)
//
// 2001/12/19 - syo
// - support refresh rate change
// - added  wait VSYNC
//
// 2001/12/16 - Pete
// - Added Windows FPSE RGB24 mode switch
//
// 2001/12/05 - syo (syo68k@geocities.co.jp)
// - modified for "Use system memory" option
//   (Pete: fixed "system memory" save state pic surface)
//
// 2001/11/11 - lu
// - SDL additions
//
// 2001/10/28 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#include "stdafx.h"

#include <stdint.h>
#include "GL/gl3w.h"

#include "gpu/soft/draw.h"
#include "gpu/soft/externals.h"
#include "gpu/soft/gpu.h"
#include "gpu/soft/menu.h"
#include "gpu/soft/prim.h"

////////////////////////////////////////////////////////////////////////////////////
// misc globals
////////////////////////////////////////////////////////////////////////////////////
int iResX;
int iResY;
long lLowerpart;
BOOL bIsFirstFrame = TRUE;
BOOL bCheckMask = FALSE;
unsigned short sSetMask = 0;
unsigned long lSetMask = 0;
int iDesktopCol = 16;
int iShowFPS = 0;
int iWinSize;
int iUseScanLines = 0;
int iUseNoStretchBlt = 0;
int iFastFwd = 0;
int iDebugMode = 1;
int iFVDisplay = 1;
PSXPoint_t ptCursorPoint[8];
unsigned short usCursorActive = 0;

////////////////////////////////////////////////////////////////////////
// Win code starts here
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// own swap buffer func (window/fullscreen)
////////////////////////////////////////////////////////////////////////

// sDX DX;
// static DDSURFACEDESC ddsd;
GUID guiDev;
BOOL bDeviceOK;
unsigned int textureId;
int iSysMemory = 0;
int iFPSEInterface = 0;
int iRefreshRate;
BOOL bVsync = FALSE;
BOOL bVsync_Key = FALSE;

void (*BlitScreen)(unsigned char *, long, long);
void (*pExtraBltFunc)(void);
void (*p2XSaIFunc)(unsigned char *, DWORD, unsigned char *, int, int);

////////////////////////////////////////////////////////////////////////

static __inline void WaitVBlank(void) {
}

static const unsigned int pitch = 4096;

////////////////////////////////////////////////////////////////////////

void BlitScreen32(unsigned char *surf, long x, long y)  // BLIT IN 32bit COLOR MODE
{
    unsigned char *pD;
    unsigned long lu;
    unsigned short s;
    unsigned int startxy;
    short row, column;
    short dx = (short)PreviousPSXDisplay.Range.x1;
    short dy = (short)PreviousPSXDisplay.DisplayMode.y;

    if (iDebugMode && iFVDisplay) {
        dx = 1024;
        dy = iGPUHeight;
        x = 0;
        y = 0;

        for (column = 0; column < dy; column++) {
            startxy = ((1024) * (column + y)) + x;
            for (row = 0; row < dx; row++) {
                s = psxVuw[startxy++];
                *((unsigned long *)((surf) + (column * pitch) + row * 4)) =
                    ((((s << 19) & 0xf80000) | ((s << 6) & 0xf800) | ((s >> 7) & 0xf8)) & 0xffffff) | 0xff000000;
            }
        }
        return;
    }

    if (PreviousPSXDisplay.Range.y0)  // centering needed?
    {
        surf += PreviousPSXDisplay.Range.y0 * pitch;
        dy -= PreviousPSXDisplay.Range.y0;
    }

    surf += PreviousPSXDisplay.Range.x0 << 2;

    if (PSXDisplay.RGB24) {
        if (iFPSEInterface) {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;
                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned long *)((surf) + (column * pitch) + row * 4)) =
                        0xff000000 | (BLUE(lu) << 16) | (GREEN(lu) << 8) | (RED(lu));
                    pD += 3;
                }
            }
        } else {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;
                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned long *)((surf) + (column * pitch) + row * 4)) =
                        0xff000000 | (RED(lu) << 16) | (GREEN(lu) << 8) | (BLUE(lu));
                    pD += 3;
                }
            }
        }
    } else {
        for (column = 0; column < dy; column++) {
            startxy = ((1024) * (column + y)) + x;
            for (row = 0; row < dx; row++) {
                s = psxVuw[startxy++];
                *((unsigned long *)((surf) + (column * pitch) + row * 4)) =
                    ((((s << 19) & 0xf80000) | ((s << 6) & 0xf800) | ((s >> 7) & 0xf8)) & 0xffffff) | 0xff000000;
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////

void DoClearScreenBuffer(void)  // CLEAR DX BUFFER
{}

////////////////////////////////////////////////////////////////////////

void DoClearFrontBuffer(void)  // CLEAR PRIMARY BUFFER
{
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

void ShowGunCursor(unsigned char *surf) {
    unsigned short dx = (unsigned short)PreviousPSXDisplay.Range.x1;
    unsigned short dy = (unsigned short)PreviousPSXDisplay.DisplayMode.y;
    int x, y, iPlayer, sx, ex, sy, ey;

    if (PreviousPSXDisplay.Range.y0)  // centering needed?
    {
        surf += PreviousPSXDisplay.Range.y0 * pitch;
        dy -= PreviousPSXDisplay.Range.y0;
    }

    if (iUseNoStretchBlt >= 3 && iUseNoStretchBlt < 13)  // 2xsai is twice as big, of course
    {
        dx *= 2;
        dy *= 2;
    } else if (iUseNoStretchBlt >= 13) {
        dx *= 3;
        dy *= 3;
    }

    if (iDesktopCol == 32)  // 32 bit color depth
    {
        const unsigned long crCursorColor32[8] = {0xffff0000, 0xff00ff00, 0xff0000ff, 0xffff00ff,
                                                  0xffffff00, 0xff00ffff, 0xffffffff, 0xff7f7f7f};

        surf += PreviousPSXDisplay.Range.x0 << 2;  // -> add x left border

        for (iPlayer = 0; iPlayer < 8; iPlayer++)  // -> loop all possible players
        {
            if (usCursorActive & (1 << iPlayer))  // -> player active?
            {
                const int ty =
                    (ptCursorPoint[iPlayer].y * dy) / 256;  // -> calculate the cursor pos in the current display
                const int tx = (ptCursorPoint[iPlayer].x * dx) / 512;
                sx = tx - 5;
                if (sx < 0) {
                    if (sx & 1)
                        sx = 1;
                    else
                        sx = 0;
                }
                sy = ty - 5;
                if (sy < 0) {
                    if (sy & 1)
                        sy = 1;
                    else
                        sy = 0;
                }
                ex = tx + 6;
                if (ex > dx) ex = dx;
                ey = ty + 6;
                if (ey > dy) ey = dy;

                for (x = tx, y = sy; y < ey; y += 2)  // -> do dotted y line
                    *((unsigned long *)((surf) + (y * pitch) + x * 4)) = crCursorColor32[iPlayer];
                for (y = ty, x = sx; x < ex; x += 2)  // -> do dotted x line
                    *((unsigned long *)((surf) + (y * pitch) + x * 4)) = crCursorColor32[iPlayer];
            }
        }
    } else  // 16 bit color depth
    {
        const unsigned short crCursorColor16[8] = {0xf800, 0x07c0, 0x001f, 0xf81f, 0xffc0, 0x07ff, 0xffff, 0x7bdf};

        surf += PreviousPSXDisplay.Range.x0 << 1;  // -> same stuff as above

        for (iPlayer = 0; iPlayer < 8; iPlayer++) {
            if (usCursorActive & (1 << iPlayer)) {
                const int ty = (ptCursorPoint[iPlayer].y * dy) / 256;
                const int tx = (ptCursorPoint[iPlayer].x * dx) / 512;
                sx = tx - 5;
                if (sx < 0) {
                    if (sx & 1)
                        sx = 1;
                    else
                        sx = 0;
                }
                sy = ty - 5;
                if (sy < 0) {
                    if (sy & 1)
                        sy = 1;
                    else
                        sy = 0;
                }
                ex = tx + 6;
                if (ex > dx) ex = dx;
                ey = ty + 6;
                if (ey > dy) ey = dy;

                for (x = tx, y = sy; y < ey; y += 2)
                    *((unsigned short *)((surf) + (y * pitch) + x * 2)) = crCursorColor16[iPlayer];
                for (y = ty, x = sx; x < ex; x += 2)
                    *((unsigned short *)((surf) + (y * pitch) + x * 2)) = crCursorColor16[iPlayer];
            }
        }
    }
}


static uint8_t *textureMem = NULL;

void DoBufferSwap() {
    LONG x, y;
    x = PSXDisplay.DisplayPosition.x;
    y = PSXDisplay.DisplayPosition.y;
    BlitScreen32(textureMem, x, y);
    glBindTexture(GL_TEXTURE_2D, textureId);
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 1024, 512, GL_BGRA, GL_UNSIGNED_BYTE, textureMem);
}

////////////////////////////////////////////////////////////////////////
// GAMMA
////////////////////////////////////////////////////////////////////////

int iUseGammaVal = 2048;

////////////////////////////////////////////////////////////////////////
// MAIN DIRECT DRAW INIT
////////////////////////////////////////////////////////////////////////

BOOL ReStart = FALSE;

int DXinitialize() {
    InitMenu();  // menu init

    if (iShowFPS)  // fps on startup
    {
        ulKeybits |= KEY_SHOWFPS;
        szDispBuf[0] = 0;
        BuildDispMenu(0);
    }

    bIsFirstFrame = FALSE;  // done

    return 0;
}

////////////////////////////////////////////////////////////////////////
// clean up DX stuff
////////////////////////////////////////////////////////////////////////

void DXcleanup()  // DX CLEANUP
{
    CloseMenu();  // bye display lists
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

DWORD dwGPUStyle = 0;  // vars to store some wimdows stuff
HANDLE hGPUMenu = NULL;

unsigned long ulInitDisplay(void) {
    textureMem = (uint8_t *)malloc(1024 * 512 * 4);
    DXinitialize();  // init direct draw (not D3D... oh, well)
    return 1;
}

////////////////////////////////////////////////////////////////////////

void CloseDisplay(void) {
    DXcleanup();  // cleanup dx
}

////////////////////////////////////////////////////////////////////////

void CreatePic(unsigned char *pMem) {
}

///////////////////////////////////////////////////////////////////////////////////////

void DestroyPic(void) {
}

///////////////////////////////////////////////////////////////////////////////////////

void DisplayPic(void) {
}

///////////////////////////////////////////////////////////////////////////////////////

void ShowGpuPic(void) {
}

////////////////////////////////////////////////////////////////////////

void ShowTextGpuPic(void)  // CREATE TEXT SCREEN PIC
{                          // gets an Text and paints
}

////////////////////////////////////////////////////////////////////////
