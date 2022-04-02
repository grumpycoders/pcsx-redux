/***************************************************************************
                          gpu.c  -  description
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
// - added GPUvisualVibration and "visual rumble" stuff
//
// 2008/02/03 - Pete
// - added GPUsetframelimit and GPUsetfix ("fake gpu busy states")
//
// 2007/11/03 - Pete
// - new way to create save state picture (Vista)
//
// 2004/01/31 - Pete
// - added zn bits
//
// 2003/01/04 - Pete
// - the odd/even bit hack (CronoCross status screen) is now a special game fix
//
// 2003/01/04 - Pete
// - fixed wrapped y display position offset - Legend of Legaia
//
// 2002/11/24 - Pete
// - added new frameskip func support
//
// 2002/11/02 - Farfetch'd & Pete
// - changed the y display pos handling
//
// 2002/10/03 - Farfetch'd & Pete
// - added all kind of tiny stuff (gpureset, gpugetinfo, dmachain align, polylines...)
//
// 2002/10/03 - Pete
// - fixed gpuwritedatamem & now doing every data processing with it
//
// 2002/08/31 - Pete
// - delayed odd/even toggle for FF8 intro scanlines
//
// 2002/08/03 - Pete
// - "Sprite 1" command count added
//
// 2002/08/03 - Pete
// - handles "screen disable" correctly
//
// 2002/07/28 - Pete
// - changed dmachain handler (monkey hero)
//
// 2002/06/15 - Pete
// - removed dmachain fixes, added dma endless loop detection instead
//
// 2002/05/31 - Lewpy
// - Win95/NT "disable screensaver" fix
//
// 2002/05/30 - Pete
// - dmawrite/read wrap around
//
// 2002/05/15 - Pete
// - Added dmachain "0" check game fix
//
// 2002/04/20 - linuzappz
// - added iFastFwd stuff
//
// 2002/02/18 - linuzappz
// - Added DGA2 support to PIC stuff
//
// 2002/02/10 - Pete
// - Added dmacheck for The Mummy and T'ai Fu
//
// 2002/01/13 - linuzappz
// - Added timing in the GPUdisplayText func
//
// 2002/01/06 - lu
// - Added some #ifdef for the linux configurator
//
// 2002/01/05 - Pete
// - fixed unwanted screen clearing on horizontal centering (causing
//   flickering in linux version)
//
// 2001/12/10 - Pete
// - fix for Grandia in ChangeDispOffsetsX
//
// 2001/12/05 - syo (syo68k@geocities.co.jp)
// - added disable screen saver for "stop screen saver" option
//
// 2001/11/20 - linuzappz
// - added Soft and About DlgProc calls in GPUconfigure and
//   GPUabout, for linux
//
// 2001/11/09 - Darko Matesic
// - added recording frame in updateLace and stop recording
//   in GPUclose (if it is still recording)
//
// 2001/10/28 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#define NOMINMAX

#include <algorithm>
#include <cstdint>

#ifdef _WIN32
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#endif

#include "core/debug.h"
#include "core/psxemulator.h"
#include "gpu/soft/draw.h"
#include "gpu/soft/externals.h"
#include "gpu/soft/gpu.h"
#include "gpu/soft/interface.h"
#include "gpu/soft/prim.h"
#include "imgui.h"
#include "tracy/Tracy.hpp"

////////////////////////////////////////////////////////////////////////
// memory image of the PSX vram
////////////////////////////////////////////////////////////////////////

unsigned char *psxVSecure;
unsigned char *psxVub;
signed char *psxVsb;
uint16_t *psxVuw;
uint16_t *psxVuw_eom;
int16_t *psxVsw;
uint32_t *psxVul;
int32_t *psxVsl;
int GlobalTextIL = 0;

// GPU globals
int32_t lGPUstatusRet;
char szDispBuf[64];
char szMenuBuf[36];
char szDebugText[512];
uint32_t ulStatusControl[256];

static uint32_t gpuDataM[256];
static unsigned char gpuCommand = 0;
static int32_t gpuDataC = 0;
static int32_t gpuDataP = 0;

VRAMLoad_t VRAMWrite;
VRAMLoad_t VRAMRead;
DATAREGISTERMODES DataWriteMode;
DATAREGISTERMODES DataReadMode;

bool bSkipNextFrame = false;
uint32_t dwLaceCnt = 0;
int iColDepth;
int iWindowMode;
int16_t sDispWidths[8] = {256, 320, 512, 640, 368, 384, 512, 640};
PSXDisplay_t PSXDisplay;
PSXDisplay_t PreviousPSXDisplay;
int32_t lSelectedSlot = 0;
bool bChangeWinMode = false;
bool bDoLazyUpdate = false;
uint32_t lGPUInfoVals[16];
int iFakePrimBusy = 0;
int iRumbleVal = 0;
int iRumbleTime = 0;

// Snapshot func
char *pGetConfigInfos(int iCfg) {
    char *pB = (char *)malloc(32767);

    return pB;
}

void DoTextSnapShot(int iNum) {
    FILE *txtfile;
    char szTxt[256];
    char *pB;

#ifdef _WIN32
    sprintf(szTxt, "SNAP\\PEOPSSOFT%03d.txt", iNum);
#else
    sprintf(szTxt, "%s/peopssoft%03d.txt", getenv("HOME"), iNum);
#endif

    if ((txtfile = fopen(szTxt, "wb")) == nullptr) return;
    //----------------------------------------------------//
    pB = pGetConfigInfos(0);
    if (pB) {
        fwrite(pB, strlen(pB), 1, txtfile);
        free(pB);
    }
    fclose(txtfile);
}

// snapshot of whole vram
extern "C" void softGPUmakeSnapshot() {
    FILE *bmpfile;
    char filename[256];
    unsigned char header[0x36];
    int32_t size, height;
    unsigned char line[1024 * 3];
    int16_t i, j;
    unsigned char empty[2] = {0, 0};
    uint16_t color;
    uint32_t snapshotnr = 0;

    height = iGPUHeight;

    size = height * 1024 * 3 + 0x38;

    // fill in proper values for BMP

    // hardcoded BMP header
    memset(header, 0, 0x36);
    header[0] = 'B';
    header[1] = 'M';
    header[2] = size & 0xff;
    header[3] = (size >> 8) & 0xff;
    header[4] = (size >> 16) & 0xff;
    header[5] = (size >> 24) & 0xff;
    header[0x0a] = 0x36;
    header[0x0e] = 0x28;
    header[0x12] = 1024 % 256;
    header[0x13] = 1024 / 256;
    header[0x16] = height % 256;
    header[0x17] = height / 256;
    header[0x1a] = 0x01;
    header[0x1c] = 0x18;
    header[0x26] = 0x12;
    header[0x27] = 0x0B;
    header[0x2A] = 0x12;
    header[0x2B] = 0x0B;

    // increment snapshot value & try to get filename
    do {
        snapshotnr++;
#ifdef _WIN32
        sprintf(filename, "SNAP\\PEOPSSOFT%03d.bmp", snapshotnr);
#else
        sprintf(filename, "%s/peopssoft%03d.bmp", getenv("HOME"), snapshotnr);
#endif

        bmpfile = fopen(filename, "rb");
        if (bmpfile == nullptr) break;
        fclose(bmpfile);
    } while (true);

    // try opening new snapshot file
    if ((bmpfile = fopen(filename, "wb")) == nullptr) return;

    fwrite(header, 0x36, 1, bmpfile);
    for (i = height - 1; i >= 0; i--) {
        for (j = 0; j < 1024; j++) {
            color = psxVuw[i * 1024 + j];
            line[j * 3 + 2] = (color << 3) & 0xf1;
            line[j * 3 + 1] = (color >> 2) & 0xf1;
            line[j * 3 + 0] = (color >> 7) & 0xf1;
        }
        fwrite(line, 1024 * 3, 1, bmpfile);
    }
    fwrite(empty, 0x2, 1, bmpfile);
    fclose(bmpfile);

    DoTextSnapShot(snapshotnr);
}

int32_t PCSX::SoftGPU::impl::init() {
    memset(ulStatusControl, 0, 256 * sizeof(uint32_t));  // init save state scontrol field

    szDebugText[0] = 0;  // init debug text buffer

    psxVSecure = new uint8_t[(iGPUHeight * 2) * 1024 +
                             (1024 * 1024)]();  // always alloc one extra MB for soft drawing funcs security
    if (!psxVSecure) return -1;

    //!!! ATTENTION !!!
    psxVub = psxVSecure + 512 * 1024;  // security offset into double sized psx vram!

    psxVsb = (signed char *)psxVub;  // different ways of accessing PSX VRAM
    psxVsw = (int16_t *)psxVub;
    psxVsl = (int32_t *)psxVub;
    psxVuw = (uint16_t *)psxVub;
    psxVul = (uint32_t *)psxVub;

    psxVuw_eom = psxVuw + 1024 * iGPUHeight;  // pre-calc of end of vram

    memset(lGPUInfoVals, 0x00, 16 * sizeof(uint32_t));

    PSXDisplay.RGB24 = false;  // init some stuff
    PSXDisplay.Interlaced = false;
    PSXDisplay.DrawOffset.x = 0;
    PSXDisplay.DrawOffset.y = 0;
    PSXDisplay.DisplayMode.x = 320;
    PSXDisplay.DisplayMode.y = 240;
    PreviousPSXDisplay.DisplayMode.x = 320;
    PreviousPSXDisplay.DisplayMode.y = 240;
    PSXDisplay.Disabled = false;
    PreviousPSXDisplay.Range.x0 = 0;
    PreviousPSXDisplay.Range.y0 = 0;
    PSXDisplay.Range.x0 = 0;
    PSXDisplay.Range.x1 = 0;
    PreviousPSXDisplay.DisplayModeNew.y = 0;
    PSXDisplay.Double = 1;
    lGPUdataRet = 0x400;

    DataWriteMode = DR_NORMAL;

    // Reset transfer values, to prevent mis-transfer of data
    memset(&VRAMWrite, 0, sizeof(VRAMLoad_t));
    memset(&VRAMRead, 0, sizeof(VRAMLoad_t));

    // device initialised already !
    lGPUstatusRet = 0x14802000;
    GPUIsIdle;
    GPUIsReadyForCommands;
    bDoVSyncUpdate = true;

    return 0;
}

int32_t PCSX::SoftGPU::impl::open(GUI *gui) {
    m_gui = gui;
    bDoVSyncUpdate = true;
    InitDisplay();

    return 0;
}

int32_t PCSX::SoftGPU::impl::close() { return 0; }

////////////////////////////////////////////////////////////////////////
// I shot the sheriff
////////////////////////////////////////////////////////////////////////

int32_t PCSX::SoftGPU::impl::shutdown() {
    delete[] psxVSecure;
    return 0;  // nothing to do
}

void updateDisplay() {
    if (PSXDisplay.Disabled) {
        DoClearFrontBuffer();  // -> clear frontbuffer
        return;                // -> and bye
    }

    DoBufferSwap();
}

////////////////////////////////////////////////////////////////////////
// roughly emulated screen centering bits... not complete !!!
////////////////////////////////////////////////////////////////////////

void ChangeDispOffsetsX() {
    if (!PSXDisplay.Range.x1) return;

    int32_t l = PreviousPSXDisplay.DisplayMode.x;

    l *= (int32_t)PSXDisplay.Range.x1;
    l /= 2560;
    int32_t lx = l;
    l &= 0xfffffff8;

    if (l == PreviousPSXDisplay.Range.y1) return;  // abusing range.y1 for
    PreviousPSXDisplay.Range.y1 = (int16_t)l;      // storing last x range and test

    if (lx >= PreviousPSXDisplay.DisplayMode.x) {
        PreviousPSXDisplay.Range.x1 = (int16_t)PreviousPSXDisplay.DisplayMode.x;
        PreviousPSXDisplay.Range.x0 = 0;
    } else {
        PreviousPSXDisplay.Range.x1 = (int16_t)l;

        PreviousPSXDisplay.Range.x0 = (PSXDisplay.Range.x0 - 500) / 8;

        if (PreviousPSXDisplay.Range.x0 < 0) PreviousPSXDisplay.Range.x0 = 0;

        if ((PreviousPSXDisplay.Range.x0 + lx) > PreviousPSXDisplay.DisplayMode.x) {
            PreviousPSXDisplay.Range.x0 = (int16_t)(PreviousPSXDisplay.DisplayMode.x - lx);
            PreviousPSXDisplay.Range.x0 += 2;  //???

            PreviousPSXDisplay.Range.x1 += (int16_t)(lx - l);
        }
        DoClearScreenBuffer();
    }

    bDoVSyncUpdate = true;
}

void ChangeDispOffsetsY() {
    int iT, iO = PreviousPSXDisplay.Range.y0;
    int iOldYOffset = PreviousPSXDisplay.DisplayModeNew.y;

    if ((PreviousPSXDisplay.DisplayModeNew.x + PSXDisplay.DisplayModeNew.y) > iGPUHeight) {
        int dy1 = iGPUHeight - PreviousPSXDisplay.DisplayModeNew.x;
        int dy2 = (PreviousPSXDisplay.DisplayModeNew.x + PSXDisplay.DisplayModeNew.y) - iGPUHeight;

        if (dy1 >= dy2) {
            PreviousPSXDisplay.DisplayModeNew.y = -dy2;
        } else {
            PSXDisplay.DisplayPosition.y = 0;
            PreviousPSXDisplay.DisplayModeNew.y = -dy1;
        }
    } else
        PreviousPSXDisplay.DisplayModeNew.y = 0;

    if (PreviousPSXDisplay.DisplayModeNew.y != iOldYOffset)  // if old offset!=new offset: recalc height
    {
        PSXDisplay.Height = PSXDisplay.Range.y1 - PSXDisplay.Range.y0 + PreviousPSXDisplay.DisplayModeNew.y;
        PSXDisplay.DisplayModeNew.y = PSXDisplay.Height * PSXDisplay.Double;
    }

    if (PSXDisplay.PAL)
        iT = 48;
    else
        iT = 28;

    if (PSXDisplay.Range.y0 >= iT) {
        PreviousPSXDisplay.Range.y0 = (int16_t)((PSXDisplay.Range.y0 - iT - 4) * PSXDisplay.Double);
        if (PreviousPSXDisplay.Range.y0 < 0) PreviousPSXDisplay.Range.y0 = 0;
        PSXDisplay.DisplayModeNew.y += PreviousPSXDisplay.Range.y0;
    } else
        PreviousPSXDisplay.Range.y0 = 0;

    if (iO != PreviousPSXDisplay.Range.y0) {
        DoClearScreenBuffer();
    }
}

////////////////////////////////////////////////////////////////////////
// check if update needed
////////////////////////////////////////////////////////////////////////

void updateDisplayIfChanged() {
    if ((PSXDisplay.DisplayMode.y == PSXDisplay.DisplayModeNew.y) &&
        (PSXDisplay.DisplayMode.x == PSXDisplay.DisplayModeNew.x)) {
        if ((PSXDisplay.RGB24 == PSXDisplay.RGB24New) && (PSXDisplay.Interlaced == PSXDisplay.InterlacedNew)) return;
    }

    PSXDisplay.RGB24 = PSXDisplay.RGB24New;  // get new infos

    PSXDisplay.DisplayMode.y = PSXDisplay.DisplayModeNew.y;
    PSXDisplay.DisplayMode.x = PSXDisplay.DisplayModeNew.x;
    PreviousPSXDisplay.DisplayMode.x =            // previous will hold
        std::min(640, PSXDisplay.DisplayMode.x);  // max 640x512... that's
    PreviousPSXDisplay.DisplayMode.y =            // the size of my
        std::min(512, PSXDisplay.DisplayMode.y);  // back buffer surface
    PSXDisplay.Interlaced = PSXDisplay.InterlacedNew;

    PSXDisplay.DisplayEnd.x =  // calc end of display
        PSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
    PSXDisplay.DisplayEnd.y =
        PSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;
    PreviousPSXDisplay.DisplayEnd.x = PreviousPSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
    PreviousPSXDisplay.DisplayEnd.y =
        PreviousPSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;

    ChangeDispOffsetsX();
}

// TOGGLE FULLSCREEN - WINDOW
void ChangeWindowMode() {
    iWindowMode = !iWindowMode;
    bChangeWinMode = false;
    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////
// gun cursor func: player=0-7, x=0-511, y=0-255
////////////////////////////////////////////////////////////////////////

extern "C" void softGPUcursor(int iPlayer, int x, int y) {
    if (iPlayer < 0) return;
    if (iPlayer > 7) return;

    usCursorActive |= (1 << iPlayer);

    if (x < 0) x = 0;
    if (x > 511) x = 511;
    if (y < 0) y = 0;
    if (y > 255) y = 255;

    ptCursorPoint[iPlayer].x = x;
    ptCursorPoint[iPlayer].y = y;
}

////////////////////////////////////////////////////////////////////////
// update lace is called every VSync
////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::impl::updateLace() {
    if (m_dumpFile) {
        uint32_t data = 0x02000000;
        fwrite(&data, sizeof(data), 1, (FILE *)m_dumpFile);
    }
    if (!(dwActFixes & 1)) lGPUstatusRet ^= 0x80000000;  // odd/even bit

    if (PSXDisplay.Interlaced)  // interlaced mode?
    {
        if (bDoVSyncUpdate && PSXDisplay.DisplayMode.x > 0 && PSXDisplay.DisplayMode.y > 0) {
            updateDisplay();
        }
    } else  // non-interlaced?
    {
        if (dwActFixes & 64)  // lazy screen update fix
        {
            if (bDoLazyUpdate) updateDisplay();
            bDoLazyUpdate = false;
        } else {
            // some primitives drawn?
            if (bDoVSyncUpdate) updateDisplay();  // -> update display
        }
    }

    bDoVSyncUpdate = false;  // vsync done
}

////////////////////////////////////////////////////////////////////////
// process read request from GPU status register
////////////////////////////////////////////////////////////////////////

uint32_t PCSX::SoftGPU::impl::readStatus() {
    if (dwActFixes & 1) {
        static int iNumRead = 0;  // odd/even hack
        if ((iNumRead++) == 2) {
            iNumRead = 0;
            lGPUstatusRet ^= 0x80000000;  // interlaced bit toggle... we do it on every 3 read status... needed by some
                                          // games (like ChronoCross) with old epsxe versions (1.5.2 and older)
        }
    }

    // if(GetAsyncKeyState(VK_SHIFT)&32768) auxprintf("1 %08x\n",lGPUstatusRet);

    if (iFakePrimBusy)  // 27.10.2007 - PETE : emulating some 'busy' while drawing... pfff
    {
        iFakePrimBusy--;

        if (iFakePrimBusy & 1)  // we do a busy-idle-busy-idle sequence after/while drawing prims
        {
            GPUIsBusy;
            GPUIsNotReadyForCommands;
        } else {
            GPUIsIdle;
            GPUIsReadyForCommands;
        }
        //   auxprintf("2 %08x\n",lGPUstatusRet);
    }

    return lGPUstatusRet;
}

// processes data send to GPU status register
// these are always single packet commands.
void PCSX::SoftGPU::impl::writeStatus(uint32_t gdata) {
    ZoneScoped;
    if (m_dumpFile) {
        uint32_t data = 0x01000001;
        fwrite(&data, sizeof(data), 1, (FILE *)m_dumpFile);
        fwrite(&gdata, sizeof(gdata), 1, (FILE *)m_dumpFile);
    }

    uint32_t lCommand = (gdata >> 24) & 0xff;

    ulStatusControl[lCommand] = gdata;  // store command for freezing

    switch (lCommand) {
        //--------------------------------------------------//
        // reset gpu
        case 0x00:
            memset(lGPUInfoVals, 0x00, 16 * sizeof(uint32_t));
            lGPUstatusRet = 0x14802000;
            PSXDisplay.Disabled = 1;
            DataWriteMode = DataReadMode = DR_NORMAL;
            PSXDisplay.DrawOffset.x = PSXDisplay.DrawOffset.y = 0;
            m_softPrim.reset();
            PSXDisplay.RGB24 = false;
            PSXDisplay.Interlaced = false;
            return;
        //--------------------------------------------------//
        // dis/enable display
        case 0x03:

            PreviousPSXDisplay.Disabled = PSXDisplay.Disabled;
            PSXDisplay.Disabled = (gdata & 1);

            if (PSXDisplay.Disabled)
                lGPUstatusRet |= GPUSTATUS_DISPLAYDISABLED;
            else
                lGPUstatusRet &= ~GPUSTATUS_DISPLAYDISABLED;
            return;

        //--------------------------------------------------//
        // setting transfer mode
        case 0x04:
            gdata &= 0x03;  // Only want the lower two bits

            DataWriteMode = DataReadMode = DR_NORMAL;
            if (gdata == 0x02) DataWriteMode = DR_VRAMTRANSFER;
            if (gdata == 0x03) DataReadMode = DR_VRAMTRANSFER;
            lGPUstatusRet &= ~GPUSTATUS_DMABITS;  // Clear the current settings of the DMA bits
            lGPUstatusRet |= (gdata << 29);       // Set the DMA bits according to the received data

            return;
        //--------------------------------------------------//
        // setting display position
        case 0x05: {
            PreviousPSXDisplay.DisplayPosition.x = PSXDisplay.DisplayPosition.x;
            PreviousPSXDisplay.DisplayPosition.y = PSXDisplay.DisplayPosition.y;

            ////////
            /*
                 PSXDisplay.DisplayPosition.y = (int16_t)((gdata>>10)&0x3ff);
                 if (PSXDisplay.DisplayPosition.y & 0x200)
                  PSXDisplay.DisplayPosition.y |= 0xfffffc00;
                 if(PSXDisplay.DisplayPosition.y<0)
                  {
                   PreviousPSXDisplay.DisplayModeNew.y=PSXDisplay.DisplayPosition.y/PSXDisplay.Double;
                   PSXDisplay.DisplayPosition.y=0;
                  }
                 else PreviousPSXDisplay.DisplayModeNew.y=0;
            */

            // new
            if (iGPUHeight == 1024) {
                if (dwGPUVersion == 2)
                    PSXDisplay.DisplayPosition.y = (int16_t)((gdata >> 12) & 0x3ff);
                else
                    PSXDisplay.DisplayPosition.y = (int16_t)((gdata >> 10) & 0x3ff);
            } else
                PSXDisplay.DisplayPosition.y = (int16_t)((gdata >> 10) & 0x1ff);

            // store the same val in some helper var, we need it on later compares
            PreviousPSXDisplay.DisplayModeNew.x = PSXDisplay.DisplayPosition.y;

            if ((PSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y) > iGPUHeight) {
                int dy1 = iGPUHeight - PSXDisplay.DisplayPosition.y;
                int dy2 = (PSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y) - iGPUHeight;

                if (dy1 >= dy2) {
                    PreviousPSXDisplay.DisplayModeNew.y = -dy2;
                } else {
                    PSXDisplay.DisplayPosition.y = 0;
                    PreviousPSXDisplay.DisplayModeNew.y = -dy1;
                }
            } else
                PreviousPSXDisplay.DisplayModeNew.y = 0;
            // eon

            PSXDisplay.DisplayPosition.x = (int16_t)(gdata & 0x3ff);
            PSXDisplay.DisplayEnd.x = PSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
            PSXDisplay.DisplayEnd.y =
                PSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;
            PreviousPSXDisplay.DisplayEnd.x = PreviousPSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
            PreviousPSXDisplay.DisplayEnd.y =
                PreviousPSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;

            bDoVSyncUpdate = true;

            if (!(PSXDisplay.Interlaced))  // stupid frame skipping option
            {
                if (dwActFixes & 64) bDoLazyUpdate = true;
            }
        }
            return;
        //--------------------------------------------------//
        // setting width
        case 0x06:

            PSXDisplay.Range.x0 = (int16_t)(gdata & 0x7ff);
            PSXDisplay.Range.x1 = (int16_t)((gdata >> 12) & 0xfff);

            PSXDisplay.Range.x1 -= PSXDisplay.Range.x0;

            ChangeDispOffsetsX();

            return;
        //--------------------------------------------------//
        // setting height
        case 0x07: {
            PSXDisplay.Range.y0 = (int16_t)(gdata & 0x3ff);
            PSXDisplay.Range.y1 = (int16_t)((gdata >> 10) & 0x3ff);

            PreviousPSXDisplay.Height = PSXDisplay.Height;

            PSXDisplay.Height = PSXDisplay.Range.y1 - PSXDisplay.Range.y0 + PreviousPSXDisplay.DisplayModeNew.y;

            if (PreviousPSXDisplay.Height != PSXDisplay.Height) {
                PSXDisplay.DisplayModeNew.y = PSXDisplay.Height * PSXDisplay.Double;

                ChangeDispOffsetsY();

                updateDisplayIfChanged();
            }
            return;
        }
        //--------------------------------------------------//
        // setting display infos
        case 0x08:

            PSXDisplay.DisplayModeNew.x = sDispWidths[(gdata & 0x03) | ((gdata & 0x40) >> 4)];

            if (gdata & 0x04)
                PSXDisplay.Double = 2;
            else
                PSXDisplay.Double = 1;

            PSXDisplay.DisplayModeNew.y = PSXDisplay.Height * PSXDisplay.Double;

            ChangeDispOffsetsY();

            PSXDisplay.PAL = (gdata & 0x08) ? true : false;            // if 1 - PAL mode, else NTSC
            PSXDisplay.RGB24New = (gdata & 0x10) ? true : false;       // if 1 - TrueColor
            PSXDisplay.InterlacedNew = (gdata & 0x20) ? true : false;  // if 1 - Interlace

            if (g_emulator->settings.get<PCSX::Emulator::SettingAutoVideo>()) {
                if (PSXDisplay.PAL) {
                    g_emulator->settings.get<Emulator::SettingVideo>() = Emulator::PSX_TYPE_PAL;
                } else {
                    g_emulator->settings.get<Emulator::SettingVideo>() = Emulator::PSX_TYPE_NTSC;
                }
            }

            lGPUstatusRet &= ~GPUSTATUS_WIDTHBITS;                               // Clear the width bits
            lGPUstatusRet |= (((gdata & 0x03) << 17) | ((gdata & 0x40) << 10));  // Set the width bits

            if (PSXDisplay.InterlacedNew) {
                if (!PSXDisplay.Interlaced) {
                    PreviousPSXDisplay.DisplayPosition.x = PSXDisplay.DisplayPosition.x;
                    PreviousPSXDisplay.DisplayPosition.y = PSXDisplay.DisplayPosition.y;
                }
                lGPUstatusRet |= GPUSTATUS_INTERLACED;
            } else
                lGPUstatusRet &= ~GPUSTATUS_INTERLACED;

            if (PSXDisplay.PAL)
                lGPUstatusRet |= GPUSTATUS_PAL;
            else
                lGPUstatusRet &= ~GPUSTATUS_PAL;

            if (PSXDisplay.Double == 2)
                lGPUstatusRet |= GPUSTATUS_DOUBLEHEIGHT;
            else
                lGPUstatusRet &= ~GPUSTATUS_DOUBLEHEIGHT;

            if (PSXDisplay.RGB24New)
                lGPUstatusRet |= GPUSTATUS_RGB24;
            else
                lGPUstatusRet &= ~GPUSTATUS_RGB24;

            updateDisplayIfChanged();

            return;
        //--------------------------------------------------//
        // ask about GPU version and other stuff
        case 0x10:

            gdata &= 0xff;

            switch (gdata) {
                case 0x02:
                    lGPUdataRet = lGPUInfoVals[INFO_TW];  // tw infos
                    return;
                case 0x03:
                    lGPUdataRet = lGPUInfoVals[INFO_DRAWSTART];  // draw start
                    return;
                case 0x04:
                    lGPUdataRet = lGPUInfoVals[INFO_DRAWEND];  // draw end
                    return;
                case 0x05:
                case 0x06:
                    lGPUdataRet = lGPUInfoVals[INFO_DRAWOFF];  // draw offset
                    return;
                case 0x07:
                    if (dwGPUVersion == 2)
                        lGPUdataRet = 0x01;
                    else
                        lGPUdataRet = 0x02;  // gpu type
                    return;
                case 0x08:
                case 0x0F:  // some bios addr?
                    lGPUdataRet = 0xBFC03720;
                    return;
            }
            return;
            //--------------------------------------------------//
    }
}

// vram read/write helpers, needed by LEWPY's optimized vram read/write :)

__inline void FinishedVRAMWrite() {
    /*
    // NEWX
     if(!PSXDisplay.Interlaced && g_useFrameSkip)            // stupid frame skipping
      {
       VRAMWrite.Width +=VRAMWrite.x;
       VRAMWrite.Height+=VRAMWrite.y;
       if(VRAMWrite.x<PSXDisplay.DisplayEnd.x &&
          VRAMWrite.Width >=PSXDisplay.DisplayPosition.x &&
          VRAMWrite.y<PSXDisplay.DisplayEnd.y &&
          VRAMWrite.Height>=PSXDisplay.DisplayPosition.y)
        updateDisplay();
      }
    */

    // Set register to NORMAL operation
    DataWriteMode = DR_NORMAL;
    // Reset transfer values, to prevent mis-transfer of data
    VRAMWrite.x = 0;
    VRAMWrite.y = 0;
    VRAMWrite.Width = 0;
    VRAMWrite.Height = 0;
    VRAMWrite.ColsRemaining = 0;
    VRAMWrite.RowsRemaining = 0;
}

__inline void FinishedVRAMRead() {
    // Set register to NORMAL operation
    DataReadMode = DR_NORMAL;
    // Reset transfer values, to prevent mis-transfer of data
    VRAMRead.x = 0;
    VRAMRead.y = 0;
    VRAMRead.Width = 0;
    VRAMRead.Height = 0;
    VRAMRead.ColsRemaining = 0;
    VRAMRead.RowsRemaining = 0;

    // Indicate GPU is no longer ready for VRAM data in the STATUS REGISTER
    lGPUstatusRet &= ~GPUSTATUS_READYFORVRAM;
}

// core read from vram
void PCSX::SoftGPU::impl::readDataMem(uint32_t *pMem, int iSize) {
    if (DataReadMode != DR_VRAMTRANSFER) return;

    GPUIsBusy;

    // adjust read ptr, if necessary
    while (VRAMRead.ImagePtr >= psxVuw_eom) VRAMRead.ImagePtr -= iGPUHeight * 1024;
    while (VRAMRead.ImagePtr < psxVuw) VRAMRead.ImagePtr += iGPUHeight * 1024;

    for (int i = 0; i < iSize; i++) {
        // do 2 seperate 16bit reads for compatibility (wrap issues)
        if ((VRAMRead.ColsRemaining > 0) && (VRAMRead.RowsRemaining > 0)) {
            // lower 16 bit
            lGPUdataRet = (uint32_t)*VRAMRead.ImagePtr;

            VRAMRead.ImagePtr++;
            if (VRAMRead.ImagePtr >= psxVuw_eom) VRAMRead.ImagePtr -= iGPUHeight * 1024;
            VRAMRead.RowsRemaining--;

            if (VRAMRead.RowsRemaining <= 0) {
                VRAMRead.RowsRemaining = VRAMRead.Width;
                VRAMRead.ColsRemaining--;
                VRAMRead.ImagePtr += 1024 - VRAMRead.Width;
                if (VRAMRead.ImagePtr >= psxVuw_eom) VRAMRead.ImagePtr -= iGPUHeight * 1024;
            }

            // higher 16 bit (always, even if it's an odd width)
            lGPUdataRet |= (uint32_t)(*VRAMRead.ImagePtr) << 16;

            *pMem++ = lGPUdataRet;

            if (VRAMRead.ColsRemaining <= 0) {
                FinishedVRAMRead();
                goto ENDREAD;
            }

            VRAMRead.ImagePtr++;
            if (VRAMRead.ImagePtr >= psxVuw_eom) VRAMRead.ImagePtr -= iGPUHeight * 1024;
            VRAMRead.RowsRemaining--;
            if (VRAMRead.RowsRemaining <= 0) {
                VRAMRead.RowsRemaining = VRAMRead.Width;
                VRAMRead.ColsRemaining--;
                VRAMRead.ImagePtr += 1024 - VRAMRead.Width;
                if (VRAMRead.ImagePtr >= psxVuw_eom) VRAMRead.ImagePtr -= iGPUHeight * 1024;
            }
            if (VRAMRead.ColsRemaining <= 0) {
                FinishedVRAMRead();
                goto ENDREAD;
            }
        } else {
            FinishedVRAMRead();
            goto ENDREAD;
        }
    }

ENDREAD:
    GPUIsIdle;
}

// processes data send to GPU data register
// extra table entries for fixing polyline troubles
const unsigned char primTableCX[256] = {
    // 00
    0, 0, 3, 0, 0, 0, 0, 0,
    // 08
    0, 0, 0, 0, 0, 0, 0, 0,
    // 10
    0, 0, 0, 0, 0, 0, 0, 0,
    // 18
    0, 0, 0, 0, 0, 0, 0, 0,
    // 20
    4, 4, 4, 4, 7, 7, 7, 7,
    // 28
    5, 5, 5, 5, 9, 9, 9, 9,
    // 30
    6, 6, 6, 6, 9, 9, 9, 9,
    // 38
    8, 8, 8, 8, 12, 12, 12, 12,
    // 40
    3, 3, 3, 3, 0, 0, 0, 0,
    // 48
    //  5,5,5,5,6,6,6,6,    // FLINE
    254, 254, 254, 254, 254, 254, 254, 254,
    // 50
    4, 4, 4, 4, 0, 0, 0, 0,
    // 58
    //  7,7,7,7,9,9,9,9,    // GLINE
    255, 255, 255, 255, 255, 255, 255, 255,
    // 60
    3, 3, 3, 3, 4, 4, 4, 4,
    // 68
    2, 2, 2, 2, 3, 3, 3, 3,  // 3=SPRITE1???
                             // 70
    2, 2, 2, 2, 3, 3, 3, 3,
    // 78
    2, 2, 2, 2, 3, 3, 3, 3,
    // 80
    4, 0, 0, 0, 0, 0, 0, 0,
    // 88
    0, 0, 0, 0, 0, 0, 0, 0,
    // 90
    0, 0, 0, 0, 0, 0, 0, 0,
    // 98
    0, 0, 0, 0, 0, 0, 0, 0,
    // a0
    3, 0, 0, 0, 0, 0, 0, 0,
    // a8
    0, 0, 0, 0, 0, 0, 0, 0,
    // b0
    0, 0, 0, 0, 0, 0, 0, 0,
    // b8
    0, 0, 0, 0, 0, 0, 0, 0,
    // c0
    3, 0, 0, 0, 0, 0, 0, 0,
    // c8
    0, 0, 0, 0, 0, 0, 0, 0,
    // d0
    0, 0, 0, 0, 0, 0, 0, 0,
    // d8
    0, 0, 0, 0, 0, 0, 0, 0,
    // e0
    0, 1, 1, 1, 1, 1, 1, 0,
    // e8
    0, 0, 0, 0, 0, 0, 0, 0,
    // f0
    0, 0, 0, 0, 0, 0, 0, 0,
    // f8
    0, 0, 0, 0, 0, 0, 0, 0};

void PCSX::SoftGPU::impl::startDump() {
    if (m_dumpFile) return;
    m_dumpFile = fopen("gpu.dump", "wb");
    fwrite(psxVuw, 1024, 1024, (FILE *)m_dumpFile);
    uint32_t data = 0;
    fwrite(&data, sizeof(data), 1, (FILE *)m_dumpFile);
    data = 0xffffffff;
    fwrite(&data, sizeof(data), 1, (FILE *)m_dumpFile);
    data = 0x01000009;
    fwrite(&data, sizeof(data), 1, (FILE *)m_dumpFile);
    fwrite(&ulStatusControl[0], sizeof(ulStatusControl[0]), 1, (FILE *)m_dumpFile);
    fwrite(&ulStatusControl[1], sizeof(ulStatusControl[1]), 1, (FILE *)m_dumpFile);
    fwrite(&ulStatusControl[2], sizeof(ulStatusControl[2]), 1, (FILE *)m_dumpFile);
    fwrite(&ulStatusControl[3], sizeof(ulStatusControl[3]), 1, (FILE *)m_dumpFile);
    fwrite(&ulStatusControl[8], sizeof(ulStatusControl[8]), 1, (FILE *)m_dumpFile);
    fwrite(&ulStatusControl[6], sizeof(ulStatusControl[6]), 1, (FILE *)m_dumpFile);
    fwrite(&ulStatusControl[7], sizeof(ulStatusControl[7]), 1, (FILE *)m_dumpFile);
    fwrite(&ulStatusControl[5], sizeof(ulStatusControl[5]), 1, (FILE *)m_dumpFile);
    fwrite(&ulStatusControl[4], sizeof(ulStatusControl[4]), 1, (FILE *)m_dumpFile);
}

void PCSX::SoftGPU::impl::stopDump() {
    if (!m_dumpFile) return;
    fclose((FILE *)m_dumpFile);
    m_dumpFile = nullptr;
}

void PCSX::SoftGPU::impl::writeDataMem(uint32_t *pMem, int iSize) {
    ZoneScoped;
    unsigned char command;
    uint32_t gdata = 0;
    int i = 0;

    if (m_dumpFile) {
        uint32_t data;
        data = iSize;
        fwrite(&data, sizeof(data), 1, (FILE *)m_dumpFile);
        fwrite(pMem, 4, iSize, (FILE *)m_dumpFile);
    }

    GPUIsBusy;
    GPUIsNotReadyForCommands;

STARTVRAM:

    if (DataWriteMode == DR_VRAMTRANSFER) {
        bool bFinished = false;

        // make sure we are in vram
        while (VRAMWrite.ImagePtr >= psxVuw_eom) VRAMWrite.ImagePtr -= iGPUHeight * 1024;
        while (VRAMWrite.ImagePtr < psxVuw) VRAMWrite.ImagePtr += iGPUHeight * 1024;

        // now do the loop
        while (VRAMWrite.ColsRemaining > 0) {
            while (VRAMWrite.RowsRemaining > 0) {
                if (i >= iSize) {
                    goto ENDVRAM;
                }
                i++;

                gdata = *pMem++;

                *VRAMWrite.ImagePtr++ = (uint16_t)gdata;
                if (VRAMWrite.ImagePtr >= psxVuw_eom) VRAMWrite.ImagePtr -= iGPUHeight * 1024;
                VRAMWrite.RowsRemaining--;

                if (VRAMWrite.RowsRemaining <= 0) {
                    VRAMWrite.ColsRemaining--;
                    if (VRAMWrite.ColsRemaining <= 0)  // last pixel is odd width
                    {
                        gdata = (gdata & 0xFFFF) | (((uint32_t)(*VRAMWrite.ImagePtr)) << 16);
                        FinishedVRAMWrite();
                        bDoVSyncUpdate = true;
                        goto ENDVRAM;
                    }
                    VRAMWrite.RowsRemaining = VRAMWrite.Width;
                    VRAMWrite.ImagePtr += 1024 - VRAMWrite.Width;
                }

                *VRAMWrite.ImagePtr++ = (uint16_t)(gdata >> 16);
                if (VRAMWrite.ImagePtr >= psxVuw_eom) VRAMWrite.ImagePtr -= iGPUHeight * 1024;
                VRAMWrite.RowsRemaining--;
            }

            VRAMWrite.RowsRemaining = VRAMWrite.Width;
            VRAMWrite.ColsRemaining--;
            VRAMWrite.ImagePtr += 1024 - VRAMWrite.Width;
            bFinished = true;
        }

        FinishedVRAMWrite();
        if (bFinished) bDoVSyncUpdate = true;
    }

ENDVRAM:

    if (DataWriteMode == DR_NORMAL) {
        for (; i < iSize;) {
            if (DataWriteMode == DR_VRAMTRANSFER) goto STARTVRAM;

            gdata = *pMem++;
            i++;

            if (gpuDataC == 0) {
                command = (unsigned char)((gdata >> 24) & 0xff);

                // if(command>=0xb0 && command<0xc0) auxprintf("b0 %x!!!!!!!!!\n",command);

                if (primTableCX[command]) {
                    gpuDataC = primTableCX[command];
                    gpuCommand = command;
                    gpuDataM[0] = gdata;
                    gpuDataP = 1;
                } else
                    continue;
            } else {
                gpuDataM[gpuDataP] = gdata;
                if (gpuDataC > 128) {
                    if ((gpuDataC == 254 && gpuDataP >= 3) || (gpuDataC == 255 && gpuDataP >= 4 && !(gpuDataP & 1))) {
                        if ((gpuDataM[gpuDataP] & 0xF000F000) == 0x50005000) gpuDataP = gpuDataC - 1;
                    }
                }
                gpuDataP++;
            }

            if (gpuDataP == gpuDataC) {
                gpuDataC = gpuDataP = 0;
                m_softPrim.callFunc(gpuCommand, (unsigned char *)gpuDataM);

                if (dwEmuFixes & 0x0001 || dwActFixes & 0x0400)  // hack for emulating "gpu busy" in some games
                    iFakePrimBusy = 4;
            }
        }
    }

    lGPUdataRet = gdata;

    GPUIsReadyForCommands;
    GPUIsIdle;
}

void SetFixes() {
    if (dwActFixes & 0x02)
        sDispWidths[4] = 384;
    else
        sDispWidths[4] = 368;
}

// process gpu commands
uint32_t lUsedAddr[3];

__inline bool CheckForEndlessLoop(uint32_t laddr) {
    if (laddr == lUsedAddr[1]) return true;
    if (laddr == lUsedAddr[2]) return true;

    if (laddr < lUsedAddr[0])
        lUsedAddr[1] = laddr;
    else
        lUsedAddr[2] = laddr;
    lUsedAddr[0] = laddr;
    return false;
}

int32_t PCSX::SoftGPU::impl::dmaChain(uint32_t *baseAddrL, uint32_t addr) {
    uint32_t dmaMem;
    unsigned char *baseAddrB;
    int16_t count;
    unsigned int DMACommandCounter = 0;

    GPUIsBusy;

    lUsedAddr[0] = lUsedAddr[1] = lUsedAddr[2] = 0xffffff;

    baseAddrB = (unsigned char *)baseAddrL;

    do {
        if (iGPUHeight == 512) addr &= 0x1FFFFC;
        if (DMACommandCounter++ > 2000000) break;
        if (::CheckForEndlessLoop(addr)) break;

        count = baseAddrB[addr + 3];

        dmaMem = addr + 4;

        if (g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::Debug>()) {
            g_emulator->m_debug->checkDMAread(2, addr, (count + 1) * 4);
        }
        if (count > 0) writeDataMem(&baseAddrL[dmaMem >> 2], count);

        addr = baseAddrL[addr >> 2] & 0xffffff;
    } while (!(addr & 0x800000));  // contrary to some documentation, the end-of-linked-list marker is not actually
                                   // 0xFF'FFFF any pointer with bit 23 set will do.

    GPUIsIdle;

    return 0;
}

void PCSX::SoftGPU::impl::save(SaveStates::GPU &gpu) {
    gpu.get<SaveStates::GPUStatus>().value = lGPUstatusRet;
    gpu.get<SaveStates::GPUControl>().copyFrom(reinterpret_cast<uint8_t *>(ulStatusControl));
    gpu.get<SaveStates::GPUVRam>().copyFrom(psxVub);
}

void PCSX::SoftGPU::impl::load(const SaveStates::GPU &gpu) {
    lGPUstatusRet = gpu.get<SaveStates::GPUStatus>().value;
    gpu.get<SaveStates::GPUControl>().copyTo(reinterpret_cast<uint8_t *>(ulStatusControl));
    gpu.get<SaveStates::GPUVRam>().copyTo(psxVub);

    // RESET TEXTURE STORE HERE, IF YOU USE SOMETHING LIKE THAT

    writeStatus(ulStatusControl[0]);
    writeStatus(ulStatusControl[1]);
    writeStatus(ulStatusControl[2]);
    writeStatus(ulStatusControl[3]);
    writeStatus(ulStatusControl[8]);  // try to repair things
    writeStatus(ulStatusControl[6]);
    writeStatus(ulStatusControl[7]);
    writeStatus(ulStatusControl[5]);
    writeStatus(ulStatusControl[4]);
}

void GPUsetfix(uint32_t dwFixBits) { dwEmuFixes = dwFixBits; }

bool PCSX::SoftGPU::impl::configure() {
    if (!m_showCfg) return false;
    bool changed = false;
    ImGui::SetNextWindowPos(ImVec2(60, 60), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(300, 200), ImGuiCond_FirstUseEver);
    static const char *ditherValues[] = {"No dithering (fastest)", "Game-dependent dithering (slow)",
                                         "Always dither g-shaded polygons (slowest)"};

    if (ImGui::Begin(_("Soft GPU configuration"), &m_showCfg)) {
        if (ImGui::Combo("Dithering", &m_softPrim.m_useDither, ditherValues, 3)) {
            changed = true;
            g_emulator->settings.get<Emulator::SettingDither>() = m_softPrim.m_useDither;
        }

        ImGui::End();
    }

    return changed;
}
