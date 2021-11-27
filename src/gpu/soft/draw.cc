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

#include "gpu/soft/draw.h"

#include <stdint.h>

#include "GL/gl3w.h"
#include "gpu/soft/externals.h"
#include "gpu/soft/gpu.h"
#include "gpu/soft/menu.h"
#include "gpu/soft/prim.h"
#include "gui/gui.h"

////////////////////////////////////////////////////////////////////////////////////
// misc globals
////////////////////////////////////////////////////////////////////////////////////
int iFastFwd = 0;
PSXPoint_t ptCursorPoint[8];
uint16_t usCursorActive = 0;

PCSX::GUI *m_gui;
bool bVsync_Key = false;

////////////////////////////////////////////////////////////////////////

static const unsigned int pitch = 4096;

////////////////////////////////////////////////////////////////////////

void DoClearScreenBuffer(void)  // CLEAR DX BUFFER
{
    glClearColor(1, 0, 0, 0);
    glClear(GL_COLOR_BUFFER_BIT);
}

////////////////////////////////////////////////////////////////////////

void DoClearFrontBuffer(void)  // CLEAR PRIMARY BUFFER
{
    glClearColor(1, 0, 0, 0);
    glClear(GL_COLOR_BUFFER_BIT);
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

void ShowGunCursor(unsigned char *surf) {
    uint16_t dx = (uint16_t)PreviousPSXDisplay.Range.x1;
    uint16_t dy = (uint16_t)PreviousPSXDisplay.DisplayMode.y;
    int x, y, iPlayer, sx, ex, sy, ey;

    if (PreviousPSXDisplay.Range.y0)  // centering needed?
    {
        surf += PreviousPSXDisplay.Range.y0 * pitch;
        dy -= PreviousPSXDisplay.Range.y0;
    }

    const uint32_t crCursorColor32[8] = {0xffff0000, 0xff00ff00, 0xff0000ff, 0xffff00ff,
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
                *((uint32_t *)((surf) + (y * pitch) + x * 4)) = crCursorColor32[iPlayer];
            for (y = ty, x = sx; x < ex; x += 2)  // -> do dotted x line
                *((uint32_t *)((surf) + (y * pitch) + x * 4)) = crCursorColor32[iPlayer];
        }
    }
}

static GLuint vramTexture = 0;

void DoBufferSwap() {
    m_gui->setViewport();
    m_gui->bindVRAMTexture();
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 1024, 512, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, psxVuw);

    if (PSXDisplay.RGB24) {
        glBindTexture(GL_TEXTURE_2D, vramTexture);
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 682, 512, GL_RGB, GL_UNSIGNED_BYTE, psxVuw);
    }

    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

    float xRatio = PSXDisplay.RGB24 ? ((1.0f / 1.5f) * (1.0f / 1024.0f)) : (1.0f / 1024.0f);

    float startX = PSXDisplay.DisplayPosition.x * xRatio;
    float startY = PSXDisplay.DisplayPosition.y / 512.0f;
    float width = (PSXDisplay.DisplayEnd.x - PSXDisplay.DisplayPosition.x) / 1024.0f;
    float height = (PSXDisplay.DisplayEnd.y - PSXDisplay.DisplayPosition.y) / 512.0f;

    GLint textureID;

    glGetIntegerv(GL_TEXTURE_BINDING_2D, &textureID);
    m_gui->m_offscreenShaderEditor.render(m_gui, textureID, {1024.0f, 512.0f}, {startX, startY}, {width, height},
                                          m_gui->getRenderSize());

    glBindTexture(GL_TEXTURE_2D, 0);
    m_gui->flip();
}

////////////////////////////////////////////////////////////////////////
// MAIN DIRECT DRAW INIT
////////////////////////////////////////////////////////////////////////

int DXinitialize() {
    //    InitMenu();  // menu init

    return 0;
}

////////////////////////////////////////////////////////////////////////
// clean up DX stuff
////////////////////////////////////////////////////////////////////////

void DXcleanup()  // DX CLEANUP
{
    //    CloseMenu();  // bye display lists
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

uint32_t ulInitDisplay(void) {
    DXinitialize();  // init direct draw (not D3D... oh, well)
    glGenTextures(1, &vramTexture);
    glBindTexture(GL_TEXTURE_2D, vramTexture);
    glTexStorage2D(GL_TEXTURE_2D, 1, GL_RGB8, 1024, 512);
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
