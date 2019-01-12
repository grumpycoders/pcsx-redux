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

#include <SDL.h>
#include <stdint.h>
#include "GL/gl3w.h"
#include "stdafx.h"

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
int iFastFwd = 0;
int iDebugMode = 1;
int iFVDisplay = 1;
PSXPoint_t ptCursorPoint[8];
unsigned short usCursorActive = 0;

unsigned int textureId;
BOOL bVsync_Key = FALSE;

////////////////////////////////////////////////////////////////////////

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

static uint8_t *textureMem = NULL;

////////////////////////////////////////////////////////////////////////

void DoClearScreenBuffer(void)  // CLEAR DX BUFFER
{
    memset(textureMem, 0, 1024 * 512 * 4);
}

////////////////////////////////////////////////////////////////////////

void DoClearFrontBuffer(void)  // CLEAR PRIMARY BUFFER
{
    memset(textureMem, 0, 1024 * 512 * 4);
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

    const unsigned long crCursorColor32[8] = {0xffff0000, 0xff00ff00, 0xff0000ff, 0xffff00ff,
                                              0xffffff00, 0xff00ffff, 0xffffffff, 0xff7f7f7f};

    surf += PreviousPSXDisplay.Range.x0 << 2;  // -> add x left border

    for (iPlayer = 0; iPlayer < 8; iPlayer++)  // -> loop all possible players
    {
        if (usCursorActive & (1 << iPlayer))  // -> player active?
        {
            const int ty = (ptCursorPoint[iPlayer].y * dy) / 256;  // -> calculate the cursor pos in the current display
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
}

static bool f10pressed = false;

void DoBufferSwap() {
    const Uint8 *keys = SDL_GetKeyboardState(NULL);
    if (keys[SDL_SCANCODE_F10]) {
        if (!f10pressed) {
            memset(textureMem, 0, 1024 * 512 * 4);
            iDebugMode = !iDebugMode;
            f10pressed = true;
        }
    } else {
        f10pressed = false;
    }
    LONG x, y;
    x = PSXDisplay.DisplayPosition.x;
    y = PSXDisplay.DisplayPosition.y;
    BlitScreen32(textureMem, x, y);
    glBindTexture(GL_TEXTURE_2D, textureId);
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 1024, 512, GL_BGRA, GL_UNSIGNED_BYTE, textureMem);
}

////////////////////////////////////////////////////////////////////////
// MAIN DIRECT DRAW INIT
////////////////////////////////////////////////////////////////////////

int DXinitialize() {
    InitMenu();  // menu init

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

void CreatePic(unsigned char *pMem) {}

///////////////////////////////////////////////////////////////////////////////////////

void DestroyPic(void) {}

///////////////////////////////////////////////////////////////////////////////////////

void DisplayPic(void) {}

///////////////////////////////////////////////////////////////////////////////////////

void ShowGpuPic(void) {}

////////////////////////////////////////////////////////////////////////

void ShowTextGpuPic(void)  // CREATE TEXT SCREEN PIC
{                          // gets an Text and paints
}

////////////////////////////////////////////////////////////////////////
