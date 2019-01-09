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

#include "stdafx.h"

#ifdef _WIN32

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resource.h"

#endif

#define _IN_GPU

#ifdef _WIN32
#include "gpu/soft/record.h"
#endif

#include "gpu/soft/cfg.h"
#include "gpu/soft/draw.h"
#include "gpu/soft/externals.h"
#include "gpu/soft/fps.h"
#include "gpu/soft/gpu.h"
#include "gpu/soft/interface.h"
#include "gpu/soft/key.h"
#include "gpu/soft/menu.h"
#include "gpu/soft/prim.h"
#include "gpu/soft/psemu.h"

//#define SMALLDEBUG
//#include <dbgout.h>

////////////////////////////////////////////////////////////////////////
// PPDK developer must change libraryName field and can change revision and build
////////////////////////////////////////////////////////////////////////

const unsigned char version = 1;  // do not touch - library for PSEmu 1.x
const unsigned char revision = 1;
const unsigned char build = 18;  // increase that with each version

#ifdef _WIN32
static const char *libraryName = "P.E.Op.S. Soft Driver";
#else
#ifndef _SDL
static char *libraryName = "P.E.Op.S. SoftX Driver";
static char *libraryInfo = "P.E.Op.S. SoftX Driver V1.18\nCoded by Pete Bernert and the P.E.Op.S. team\n";
#else
static char *libraryName = "P.E.Op.S. SoftSDL Driver";
static char *libraryInfo = "P.E.Op.S. SoftSDL Driver V1.18\nCoded by Pete Bernert and the P.E.Op.S. team\n";
#endif
#endif

static const char *PluginAuthor = "Pete Bernert and the P.E.Op.S. team";

////////////////////////////////////////////////////////////////////////
// memory image of the PSX vram
////////////////////////////////////////////////////////////////////////

unsigned char *psxVSecure;
unsigned char *psxVub;
signed char *psxVsb;
unsigned short *psxVuw;
unsigned short *psxVuw_eom;
signed short *psxVsw;
unsigned long *psxVul;
signed long *psxVsl;

////////////////////////////////////////////////////////////////////////
// GPU globals
////////////////////////////////////////////////////////////////////////

long lGPUstatusRet;
char szDispBuf[64];
char szMenuBuf[36];
char szDebugText[512];
unsigned long ulStatusControl[256];

static unsigned long gpuDataM[256];
static unsigned char gpuCommand = 0;
static long gpuDataC = 0;
static long gpuDataP = 0;

VRAMLoad_t VRAMWrite;
VRAMLoad_t VRAMRead;
DATAREGISTERMODES DataWriteMode;
DATAREGISTERMODES DataReadMode;

BOOL bSkipNextFrame = FALSE;
DWORD dwLaceCnt = 0;
int iColDepth;
int iWindowMode;
short sDispWidths[8] = {256, 320, 512, 640, 368, 384, 512, 640};
PSXDisplay_t PSXDisplay;
PSXDisplay_t PreviousPSXDisplay;
long lSelectedSlot = 0;
BOOL bChangeWinMode = FALSE;
BOOL bDoLazyUpdate = FALSE;
unsigned long lGPUInfoVals[16];
int iFakePrimBusy = 0;
int iRumbleVal = 0;
int iRumbleTime = 0;

#ifdef _WIN32

////////////////////////////////////////////////////////////////////////
// screensaver stuff: dynamically load kernel32.dll to avoid export dependeny
////////////////////////////////////////////////////////////////////////

int iStopSaver = 0;
HINSTANCE kernel32LibHandle = NULL;

// A stub function, that does nothing .... but it does "nothing" well :)
EXECUTION_STATE WINAPI STUB_SetThreadExecutionState(EXECUTION_STATE esFlags) { return esFlags; }

// The dynamic version of the system call is prepended with a "D_"
EXECUTION_STATE(WINAPI *D_SetThreadExecutionState)(EXECUTION_STATE esFlags) = STUB_SetThreadExecutionState;

BOOL LoadKernel32(void) {
    // Get a handle to the kernel32.dll (which is actually already loaded)
    kernel32LibHandle = LoadLibrary("kernel32.dll");

    // If we've got a handle, then locate the entry point for the SetThreadExecutionState function
    if (kernel32LibHandle != NULL) {
        if ((D_SetThreadExecutionState = (EXECUTION_STATE(WINAPI *)(EXECUTION_STATE))GetProcAddress(
                 kernel32LibHandle, "SetThreadExecutionState")) == NULL)
            D_SetThreadExecutionState = STUB_SetThreadExecutionState;
    }

    return TRUE;
}

BOOL FreeKernel32(void) {
    // Release the handle to kernel32.dll
    if (kernel32LibHandle != NULL) FreeLibrary(kernel32LibHandle);

    // Set to stub function, to avoid nasty suprises if called :)
    D_SetThreadExecutionState = STUB_SetThreadExecutionState;

    return TRUE;
}
#else

// Linux: Stub the functions
BOOL LoadKernel32(void) { return TRUE; }

BOOL FreeKernel32(void) { return TRUE; }

#endif

////////////////////////////////////////////////////////////////////////
// some misc external display funcs
////////////////////////////////////////////////////////////////////////

/*
unsigned long PCADDR;
void GPUdebugSetPC(unsigned long addr)
{
 PCADDR=addr;
}
*/

#include <time.h>
time_t tStart;

extern "C" void softGPUdisplayText(char *pText)  // some debug func
{
    if (!pText) {
        szDebugText[0] = 0;
        return;
    }
    if (strlen(pText) > 511) return;
    time(&tStart);
    strcpy(szDebugText, pText);
}

////////////////////////////////////////////////////////////////////////

extern "C" void softGPUdisplayFlags(unsigned long dwFlags)  // some info func
{
    dwCoreFlags = dwFlags;
    BuildDispMenu(0);
}

////////////////////////////////////////////////////////////////////////
// stuff to make this a true PDK module
////////////////////////////////////////////////////////////////////////

const char *PSEgetLibName(void) { return libraryName; }

unsigned long PSEgetLibType(void) { return PSE_LT_GPU; }

unsigned long PSEgetLibVersion(void) { return version << 16 | revision << 8 | build; }

#ifndef _WIN32
char *GPUgetLibInfos(void) { return libraryInfo; }
#endif

////////////////////////////////////////////////////////////////////////
// Snapshot func
////////////////////////////////////////////////////////////////////////

char *pGetConfigInfos(int iCfg) {
    char szO[2][4] = {"off", "on "};
    char szTxt[256];
    char *pB = (char *)malloc(32767);

    if (!pB) return NULL;
    *pB = 0;
    //----------------------------------------------------//
    sprintf(szTxt, "Plugin: %s %d.%d.%d\r\n", libraryName, version, revision, build);
    strcat(pB, szTxt);
    sprintf(szTxt, "Author: %s\r\n\r\n", PluginAuthor);
    strcat(pB, szTxt);
    //----------------------------------------------------//
    if (iCfg && iWindowMode)
        sprintf(szTxt, "Resolution/Color:\r\n- %dx%d ", LOWORD(iWinSize), HIWORD(iWinSize));
    else
        sprintf(szTxt, "Resolution/Color:\r\n- %dx%d ", iResX, iResY);
    strcat(pB, szTxt);
    if (iWindowMode && iCfg)
        strcpy(szTxt, "Window mode\r\n");
    else if (iWindowMode)
        sprintf(szTxt, "Window mode - [%d Bit]\r\n", iDesktopCol);
    else
        sprintf(szTxt, "Fullscreen - [%d Bit]\r\n", iColDepth);
    strcat(pB, szTxt);

    sprintf(szTxt, "Stretch mode: %d\r\n", iUseNoStretchBlt);
    strcat(pB, szTxt);
    sprintf(szTxt, "Dither mode: %d\r\n\r\n", iUseDither);
    strcat(pB, szTxt);
    //----------------------------------------------------//
    sprintf(szTxt, "Framerate:\r\n- FPS limit: %s\r\n", szO[UseFrameLimit]);
    strcat(pB, szTxt);
    sprintf(szTxt, "- Frame skipping: %s", szO[UseFrameSkip]);
    strcat(pB, szTxt);
    if (iFastFwd) strcat(pB, " (fast forward)");
    strcat(pB, "\r\n");
    if (iFrameLimit == 2)
        strcpy(szTxt, "- FPS limit: Auto\r\n\r\n");
    else
        sprintf(szTxt, "- FPS limit: %.1f\r\n\r\n", fFrameRate);
    strcat(pB, szTxt);
    //----------------------------------------------------//
    strcpy(szTxt, "Misc:\r\n- Scanlines: ");
    if (iUseScanLines == 0)
        strcat(szTxt, "disabled");
    else if (iUseScanLines == 1)
        strcat(szTxt, "standard");
    else if (iUseScanLines == 2)
        strcat(szTxt, "double blitting");
    strcat(szTxt, "\r\n");
    strcat(pB, szTxt);
    sprintf(szTxt, "- Game fixes: %s [%08lx]\r\n", szO[iUseFixes], dwCfgFixes);
    strcat(pB, szTxt);
    //----------------------------------------------------//
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

    if ((txtfile = fopen(szTxt, "wb")) == NULL) return;
    //----------------------------------------------------//
    pB = pGetConfigInfos(0);
    if (pB) {
        fwrite(pB, strlen(pB), 1, txtfile);
        free(pB);
    }
    fclose(txtfile);
}

////////////////////////////////////////////////////////////////////////

extern "C" void softGPUmakeSnapshot(void)  // snapshot of whole vram
{
    FILE *bmpfile;
    char filename[256];
    unsigned char header[0x36];
    long size, height;
    unsigned char line[1024 * 3];
    short i, j;
    unsigned char empty[2] = {0, 0};
    unsigned short color;
    unsigned long snapshotnr = 0;

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
        sprintf(filename, "%s/peopssoft%03ld.bmp", getenv("HOME"), snapshotnr);
#endif

        bmpfile = fopen(filename, "rb");
        if (bmpfile == NULL) break;
        fclose(bmpfile);
    } while (TRUE);

    // try opening new snapshot file
    if ((bmpfile = fopen(filename, "wb")) == NULL) return;

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

////////////////////////////////////////////////////////////////////////
// INIT, will be called after lib load... well, just do some var init...
////////////////////////////////////////////////////////////////////////

long PCSX::SoftGPU::impl::init()  // GPU INIT
{
    memset(ulStatusControl, 0, 256 * sizeof(unsigned long));  // init save state scontrol field

    szDebugText[0] = 0;  // init debug text buffer

    psxVSecure = (unsigned char *)malloc((iGPUHeight * 2) * 1024 +
                                         (1024 * 1024));  // always alloc one extra MB for soft drawing funcs security
    if (!psxVSecure) return -1;

    //!!! ATTENTION !!!
    psxVub = psxVSecure + 512 * 1024;  // security offset into double sized psx vram!

    psxVsb = (signed char *)psxVub;  // different ways of accessing PSX VRAM
    psxVsw = (signed short *)psxVub;
    psxVsl = (signed long *)psxVub;
    psxVuw = (unsigned short *)psxVub;
    psxVul = (unsigned long *)psxVub;

    psxVuw_eom = psxVuw + 1024 * iGPUHeight;  // pre-calc of end of vram

    memset(psxVSecure, 0x00, (iGPUHeight * 2) * 1024 + (1024 * 1024));
    memset(lGPUInfoVals, 0x00, 16 * sizeof(unsigned long));

    SetFPSHandler();

    PSXDisplay.RGB24 = FALSE;  // init some stuff
    PSXDisplay.Interlaced = FALSE;
    PSXDisplay.DrawOffset.x = 0;
    PSXDisplay.DrawOffset.y = 0;
    PSXDisplay.DisplayMode.x = 320;
    PSXDisplay.DisplayMode.y = 240;
    PreviousPSXDisplay.DisplayMode.x = 320;
    PreviousPSXDisplay.DisplayMode.y = 240;
    PSXDisplay.Disabled = FALSE;
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

    // Get a handle for kernel32.dll, and access the required export function
    LoadKernel32();

    return 0;
}

////////////////////////////////////////////////////////////////////////
// Here starts all...
////////////////////////////////////////////////////////////////////////

#ifdef _WIN32
long PCSX::SoftGPU::impl::open(unsigned int textureIdGPU)  // GPU OPEN
{
    textureId = textureIdGPU;  // store hwnd

    SetKeyHandler();  // sub-class window

    if (bChangeWinMode)
        ReadWinSizeConfig();  // alt+enter toggle?
    else                      // or first time startup?
    {
        ReadConfig();  // read registry
        InitFPS();
    }

    bIsFirstFrame = TRUE;  // we have to init later
    bDoVSyncUpdate = true;

    ulInitDisplay();  // setup direct draw

    if (iStopSaver) D_SetThreadExecutionState(ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED | ES_CONTINUOUS);

    return 0;
}

#else

long GPUopen(unsigned long *disp, char *CapText, char *CfgFile) {
    unsigned long d;

    pCaptionText = CapText;

#ifndef _FPSE
    pConfigFile = CfgFile;
#endif

    ReadConfig();  // read registry

    InitFPS();

    bIsFirstFrame = TRUE;  // we have to init later
    bDoVSyncUpdate = true;

    d = ulInitDisplay();  // setup x

    if (disp) *disp = d;  // wanna x pointer? ok

    if (d) return 0;
    return -1;
}

#endif

////////////////////////////////////////////////////////////////////////
// time to leave...
////////////////////////////////////////////////////////////////////////

long PCSX::SoftGPU::impl::close()  // GPU CLOSE
{
#if 0
    if (RECORD_RECORDING == TRUE) {
        RECORD_Stop();
        RECORD_RECORDING = FALSE;
        BuildDispMenu(0);
    }
#endif

    ReleaseKeyHandler();  // de-subclass window

    CloseDisplay();  // shutdown direct draw

#ifdef _WIN32
    if (iStopSaver) D_SetThreadExecutionState(ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED);
#endif

    return 0;
}

////////////////////////////////////////////////////////////////////////
// I shot the sheriff
////////////////////////////////////////////////////////////////////////

long PCSX::SoftGPU::impl::shutdown()  // GPU SHUTDOWN
{
    // screensaver: release the handle for kernel32.dll
    FreeKernel32();

    free(psxVSecure);

    return 0;  // nothinh to do
}

////////////////////////////////////////////////////////////////////////
// Update display (swap buffers)
////////////////////////////////////////////////////////////////////////

void updateDisplay(void)  // UPDATE DISPLAY
{
    if (PSXDisplay.Disabled)  // disable?
    {
        DoClearFrontBuffer();  // -> clear frontbuffer
        return;                // -> and bye
    }

    if (dwActFixes & 32)  // pc fps calculation fix
    {
        if (UseFrameLimit) PCFrameCap();  // -> brake
        if (UseFrameSkip || ulKeybits & KEY_SHOWFPS) PCcalcfps();
    }

    if (ulKeybits & KEY_SHOWFPS)  // make fps display buf
    {
        sprintf(szDispBuf, "FPS %06.2f", fps_cur);
    }

    if (iFastFwd)  // fastfwd ?
    {
        static int fpscount;
        UseFrameSkip = 1;

        if (!bSkipNextFrame) DoBufferSwap();  // -> to skip or not to skip
        if (fpscount % 6)                     // -> skip 6/7 frames
            bSkipNextFrame = TRUE;
        else
            bSkipNextFrame = FALSE;
        fpscount++;
        if (fpscount >= (int)fFrameRateHz) fpscount = 0;
        return;
    }

    if (UseFrameSkip)  // skip ?
    {
        if (!bSkipNextFrame) DoBufferSwap();  // -> to skip or not to skip
        if (dwActFixes & 0xa0)                // -> pc fps calculation fix/old skipping fix
        {
            if ((fps_skip < fFrameRateHz) && !(bSkipNextFrame))  // -> skip max one in a row
            {
                bSkipNextFrame = TRUE;
                fps_skip = fFrameRateHz;
            } else
                bSkipNextFrame = FALSE;
        } else
            FrameSkip();
    } else  // no skip ?
    {
        DoBufferSwap();  // -> swap
    }
}

////////////////////////////////////////////////////////////////////////
// roughly emulated screen centering bits... not complete !!!
////////////////////////////////////////////////////////////////////////

void ChangeDispOffsetsX(void)  // X CENTER
{
    long lx, l;

    if (!PSXDisplay.Range.x1) return;

    l = PreviousPSXDisplay.DisplayMode.x;

    l *= (long)PSXDisplay.Range.x1;
    l /= 2560;
    lx = l;
    l &= 0xfffffff8;

    if (l == PreviousPSXDisplay.Range.y1) return;  // abusing range.y1 for
    PreviousPSXDisplay.Range.y1 = (short)l;        // storing last x range and test

    if (lx >= PreviousPSXDisplay.DisplayMode.x) {
        PreviousPSXDisplay.Range.x1 = (short)PreviousPSXDisplay.DisplayMode.x;
        PreviousPSXDisplay.Range.x0 = 0;
    } else {
        PreviousPSXDisplay.Range.x1 = (short)l;

        PreviousPSXDisplay.Range.x0 = (PSXDisplay.Range.x0 - 500) / 8;

        if (PreviousPSXDisplay.Range.x0 < 0) PreviousPSXDisplay.Range.x0 = 0;

        if ((PreviousPSXDisplay.Range.x0 + lx) > PreviousPSXDisplay.DisplayMode.x) {
            PreviousPSXDisplay.Range.x0 = (short)(PreviousPSXDisplay.DisplayMode.x - lx);
            PreviousPSXDisplay.Range.x0 += 2;  //???

            PreviousPSXDisplay.Range.x1 += (short)(lx - l);
#ifndef _WIN32
            PreviousPSXDisplay.Range.x1 -= 2;  // makes linux stretching easier
#endif
        }

#ifndef _WIN32
        // some linux alignment security
        PreviousPSXDisplay.Range.x0 = PreviousPSXDisplay.Range.x0 >> 1;
        PreviousPSXDisplay.Range.x0 = PreviousPSXDisplay.Range.x0 << 1;
        PreviousPSXDisplay.Range.x1 = PreviousPSXDisplay.Range.x1 >> 1;
        PreviousPSXDisplay.Range.x1 = PreviousPSXDisplay.Range.x1 << 1;
#endif

        DoClearScreenBuffer();
    }

    bDoVSyncUpdate = true;
}

////////////////////////////////////////////////////////////////////////

void ChangeDispOffsetsY(void)  // Y CENTER
{
    int iT, iO = PreviousPSXDisplay.Range.y0;
    int iOldYOffset = PreviousPSXDisplay.DisplayModeNew.y;

    // new

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

    // eon

    if (PreviousPSXDisplay.DisplayModeNew.y != iOldYOffset)  // if old offset!=new offset: recalc height
    {
        PSXDisplay.Height = PSXDisplay.Range.y1 - PSXDisplay.Range.y0 + PreviousPSXDisplay.DisplayModeNew.y;
        PSXDisplay.DisplayModeNew.y = PSXDisplay.Height * PSXDisplay.Double;
    }

    //

    if (PSXDisplay.PAL)
        iT = 48;
    else
        iT = 28;

    if (PSXDisplay.Range.y0 >= iT) {
        PreviousPSXDisplay.Range.y0 = (short)((PSXDisplay.Range.y0 - iT - 4) * PSXDisplay.Double);
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

void updateDisplayIfChanged(void)  // UPDATE DISPLAY IF CHANGED
{
    if ((PSXDisplay.DisplayMode.y == PSXDisplay.DisplayModeNew.y) &&
        (PSXDisplay.DisplayMode.x == PSXDisplay.DisplayModeNew.x)) {
        if ((PSXDisplay.RGB24 == PSXDisplay.RGB24New) && (PSXDisplay.Interlaced == PSXDisplay.InterlacedNew)) return;
    }

    PSXDisplay.RGB24 = PSXDisplay.RGB24New;  // get new infos

    PSXDisplay.DisplayMode.y = PSXDisplay.DisplayModeNew.y;
    PSXDisplay.DisplayMode.x = PSXDisplay.DisplayModeNew.x;
    PreviousPSXDisplay.DisplayMode.x =       // previous will hold
        min(640, PSXDisplay.DisplayMode.x);  // max 640x512... that's
    PreviousPSXDisplay.DisplayMode.y =       // the size of my
        min(512, PSXDisplay.DisplayMode.y);  // back buffer surface
    PSXDisplay.Interlaced = PSXDisplay.InterlacedNew;

    PSXDisplay.DisplayEnd.x =  // calc end of display
        PSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
    PSXDisplay.DisplayEnd.y =
        PSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;
    PreviousPSXDisplay.DisplayEnd.x = PreviousPSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
    PreviousPSXDisplay.DisplayEnd.y =
        PreviousPSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;

    ChangeDispOffsetsX();

    if (iFrameLimit == 2) SetAutoFrameCap();  // -> set it

    if (UseFrameSkip) updateDisplay();  // stupid stuff when frame skipping enabled
}

////////////////////////////////////////////////////////////////////////

#ifdef _WIN32
void ChangeWindowMode(void)  // TOGGLE FULLSCREEN - WINDOW
{
    //    softGPUclose();
    iWindowMode = !iWindowMode;
    //    softGPUopen(textureId);
    bChangeWinMode = FALSE;
    bDoVSyncUpdate = true;
}
#endif

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
// update lace is called evry VSync
////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::impl::updateLace()  // VSYNC
{
    if (!(dwActFixes & 1)) lGPUstatusRet ^= 0x80000000;  // odd/even bit

    if (!(dwActFixes & 32))  // std fps limitation?
        CheckFrameRate();

    if (PSXDisplay.Interlaced)  // interlaced mode?
    {
        if (bDoVSyncUpdate && PSXDisplay.DisplayMode.x > 0 && PSXDisplay.DisplayMode.y > 0) {
            updateDisplay();
        }
    } else  // non-interlaced?
    {
        if (dwActFixes & 64)  // lazy screen update fix
        {
            if (bDoLazyUpdate && !UseFrameSkip) updateDisplay();
            bDoLazyUpdate = FALSE;
        } else {
            if (bDoVSyncUpdate && !UseFrameSkip)  // some primitives drawn?
                updateDisplay();                  // -> update display
        }
    }

#if 0

    if (RECORD_RECORDING)
        if (RECORD_WriteFrame() == FALSE) {
            RECORD_RECORDING = FALSE;
            RECORD_Stop();
        }

    if (bChangeWinMode) ChangeWindowMode();  // toggle full - window mode

#endif

    bDoVSyncUpdate = false;  // vsync done
}

////////////////////////////////////////////////////////////////////////
// process read request from GPU status register
////////////////////////////////////////////////////////////////////////

uint32_t PCSX::SoftGPU::impl::readStatus(void)  // READ STATUS
{
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

////////////////////////////////////////////////////////////////////////
// processes data send to GPU status register
// these are always single packet commands.
////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::impl::writeStatus(uint32_t gdata)  // WRITE STATUS
{
    unsigned long lCommand = (gdata >> 24) & 0xff;

    ulStatusControl[lCommand] = gdata;  // store command for freezing

    switch (lCommand) {
        //--------------------------------------------------//
        // reset gpu
        case 0x00:
            memset(lGPUInfoVals, 0x00, 16 * sizeof(unsigned long));
            lGPUstatusRet = 0x14802000;
            PSXDisplay.Disabled = 1;
            DataWriteMode = DataReadMode = DR_NORMAL;
            PSXDisplay.DrawOffset.x = PSXDisplay.DrawOffset.y = 0;
            drawX = drawY = 0;
            drawW = drawH = 0;
            sSetMask = 0;
            lSetMask = 0;
            bCheckMask = FALSE;
            usMirror = 0;
            m_prim.reset();
            PSXDisplay.RGB24 = FALSE;
            PSXDisplay.Interlaced = FALSE;
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
                 PSXDisplay.DisplayPosition.y = (short)((gdata>>10)&0x3ff);
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
                    PSXDisplay.DisplayPosition.y = (short)((gdata >> 12) & 0x3ff);
                else
                    PSXDisplay.DisplayPosition.y = (short)((gdata >> 10) & 0x3ff);
            } else
                PSXDisplay.DisplayPosition.y = (short)((gdata >> 10) & 0x1ff);

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

            PSXDisplay.DisplayPosition.x = (short)(gdata & 0x3ff);
            PSXDisplay.DisplayEnd.x = PSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
            PSXDisplay.DisplayEnd.y =
                PSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;
            PreviousPSXDisplay.DisplayEnd.x = PreviousPSXDisplay.DisplayPosition.x + PSXDisplay.DisplayMode.x;
            PreviousPSXDisplay.DisplayEnd.y =
                PreviousPSXDisplay.DisplayPosition.y + PSXDisplay.DisplayMode.y + PreviousPSXDisplay.DisplayModeNew.y;

            bDoVSyncUpdate = true;

            if (!(PSXDisplay.Interlaced))  // stupid frame skipping option
            {
                if (UseFrameSkip) updateDisplay();
                if (dwActFixes & 64) bDoLazyUpdate = TRUE;
            }
        }
            return;
        //--------------------------------------------------//
        // setting width
        case 0x06:

            PSXDisplay.Range.x0 = (short)(gdata & 0x7ff);
            PSXDisplay.Range.x1 = (short)((gdata >> 12) & 0xfff);

            PSXDisplay.Range.x1 -= PSXDisplay.Range.x0;

            ChangeDispOffsetsX();

            return;
        //--------------------------------------------------//
        // setting height
        case 0x07: {
            PSXDisplay.Range.y0 = (short)(gdata & 0x3ff);
            PSXDisplay.Range.y1 = (short)((gdata >> 10) & 0x3ff);

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

            PSXDisplay.PAL = (gdata & 0x08) ? TRUE : FALSE;            // if 1 - PAL mode, else NTSC
            PSXDisplay.RGB24New = (gdata & 0x10) ? TRUE : FALSE;       // if 1 - TrueColor
            PSXDisplay.InterlacedNew = (gdata & 0x20) ? TRUE : FALSE;  // if 1 - Interlace

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

////////////////////////////////////////////////////////////////////////
// vram read/write helpers, needed by LEWPY's optimized vram read/write :)
////////////////////////////////////////////////////////////////////////

__inline void FinishedVRAMWrite(void) {
    /*
    // NEWX
     if(!PSXDisplay.Interlaced && UseFrameSkip)            // stupid frame skipping
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

__inline void FinishedVRAMRead(void) {
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

////////////////////////////////////////////////////////////////////////
// core read from vram
////////////////////////////////////////////////////////////////////////

void PCSX::SoftGPU::impl::readDataMem(uint32_t *pMem, int iSize) {
    int i;

    if (DataReadMode != DR_VRAMTRANSFER) return;

    GPUIsBusy;

    // adjust read ptr, if necessary
    while (VRAMRead.ImagePtr >= psxVuw_eom) VRAMRead.ImagePtr -= iGPUHeight * 1024;
    while (VRAMRead.ImagePtr < psxVuw) VRAMRead.ImagePtr += iGPUHeight * 1024;

    for (i = 0; i < iSize; i++) {
        // do 2 seperate 16bit reads for compatibility (wrap issues)
        if ((VRAMRead.ColsRemaining > 0) && (VRAMRead.RowsRemaining > 0)) {
            // lower 16 bit
            lGPUdataRet = (unsigned long)*VRAMRead.ImagePtr;

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
            lGPUdataRet |= (unsigned long)(*VRAMRead.ImagePtr) << 16;

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

////////////////////////////////////////////////////////////////////////
// processes data send to GPU data register
// extra table entries for fixing polyline troubles
////////////////////////////////////////////////////////////////////////

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

void PCSX::SoftGPU::impl::writeDataMem(uint32_t *pMem, int iSize) {
    unsigned char command;
    unsigned long gdata = 0;
    int i = 0;

    GPUIsBusy;
    GPUIsNotReadyForCommands;

STARTVRAM:

    if (DataWriteMode == DR_VRAMTRANSFER) {
        BOOL bFinished = FALSE;

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

                *VRAMWrite.ImagePtr++ = (unsigned short)gdata;
                if (VRAMWrite.ImagePtr >= psxVuw_eom) VRAMWrite.ImagePtr -= iGPUHeight * 1024;
                VRAMWrite.RowsRemaining--;

                if (VRAMWrite.RowsRemaining <= 0) {
                    VRAMWrite.ColsRemaining--;
                    if (VRAMWrite.ColsRemaining <= 0)  // last pixel is odd width
                    {
                        gdata = (gdata & 0xFFFF) | (((unsigned long)(*VRAMWrite.ImagePtr)) << 16);
                        FinishedVRAMWrite();
                        bDoVSyncUpdate = true;
                        goto ENDVRAM;
                    }
                    VRAMWrite.RowsRemaining = VRAMWrite.Width;
                    VRAMWrite.ImagePtr += 1024 - VRAMWrite.Width;
                }

                *VRAMWrite.ImagePtr++ = (unsigned short)(gdata >> 16);
                if (VRAMWrite.ImagePtr >= psxVuw_eom) VRAMWrite.ImagePtr -= iGPUHeight * 1024;
                VRAMWrite.RowsRemaining--;
            }

            VRAMWrite.RowsRemaining = VRAMWrite.Width;
            VRAMWrite.ColsRemaining--;
            VRAMWrite.ImagePtr += 1024 - VRAMWrite.Width;
            bFinished = TRUE;
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
                m_prim.callFunc(gpuCommand, (unsigned char *)gpuDataM);

                if (dwEmuFixes & 0x0001 || dwActFixes & 0x0400)  // hack for emulating "gpu busy" in some games
                    iFakePrimBusy = 4;
            }
        }
    }

    lGPUdataRet = gdata;

    GPUIsReadyForCommands;
    GPUIsIdle;
}

////////////////////////////////////////////////////////////////////////
// this functions will be removed soon (or 'soonish')... not really needed, but some emus want them
////////////////////////////////////////////////////////////////////////

extern "C" void softGPUsetMode(unsigned long gdata) {
    // Peops does nothing here...
    // DataWriteMode=(gdata&1)?DR_VRAMTRANSFER:DR_NORMAL;
    // DataReadMode =(gdata&2)?DR_VRAMTRANSFER:DR_NORMAL;
}

extern "C" long softGPUgetMode(void) {
    long iT = 0;

    if (DataWriteMode == DR_VRAMTRANSFER) iT |= 0x1;
    if (DataReadMode == DR_VRAMTRANSFER) iT |= 0x2;
    return iT;
}

////////////////////////////////////////////////////////////////////////
// call config dlg
////////////////////////////////////////////////////////////////////////

extern "C" long softGPUconfigure(void) {
#ifdef _WIN32
    HWND hWP = GetActiveWindow();

    DialogBox(0, MAKEINTRESOURCE(IDD_CFGSOFT), hWP, (DLGPROC)SoftDlgProc);
#else  // LINUX
    SoftDlgProc();
#endif

    return 0;
}

////////////////////////////////////////////////////////////////////////
// sets all kind of act fixes
////////////////////////////////////////////////////////////////////////

void SetFixes(void) {
#ifdef _WIN32
    BOOL bOldPerformanceCounter = IsPerformanceCounter;  // store curr timer mode

    if (dwActFixes & 0x10)  // check fix 0x10
        IsPerformanceCounter = FALSE;
    else
        SetFPSHandler();

    if (bOldPerformanceCounter != IsPerformanceCounter)  // we have change it?
        InitFPS();                                       // -> init fps again
#endif

    if (dwActFixes & 0x02)
        sDispWidths[4] = 384;
    else
        sDispWidths[4] = 368;
}

////////////////////////////////////////////////////////////////////////
// process gpu commands
////////////////////////////////////////////////////////////////////////

unsigned long lUsedAddr[3];

__inline BOOL CheckForEndlessLoop(unsigned long laddr) {
    if (laddr == lUsedAddr[1]) return TRUE;
    if (laddr == lUsedAddr[2]) return TRUE;

    if (laddr < lUsedAddr[0])
        lUsedAddr[1] = laddr;
    else
        lUsedAddr[2] = laddr;
    lUsedAddr[0] = laddr;
    return FALSE;
}

long PCSX::SoftGPU::impl::dmaChain(uint32_t *baseAddrL, uint32_t addr) {
    unsigned long dmaMem;
    unsigned char *baseAddrB;
    short count;
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

        if (count > 0) writeDataMem(&baseAddrL[dmaMem >> 2], count);

        addr = baseAddrL[addr >> 2] & 0xffffff;
    } while (addr != 0xffffff);

    GPUIsIdle;

    return 0;
}

////////////////////////////////////////////////////////////////////////
// show about dlg
////////////////////////////////////////////////////////////////////////

#ifdef _WIN32
BOOL AboutDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDOK:
                    EndDialog(hW, TRUE);
                    return TRUE;
            }
        }
    }
    return FALSE;
}
#endif

extern "C" void softGPUabout(void)  // ABOUT
{
#ifdef _WIN32
    HWND hWP = GetActiveWindow();  // to be sure
    DialogBox(0, MAKEINTRESOURCE(IDD_ABOUT), hWP, (DLGPROC)AboutDlgProc);
#else  // LINUX
#ifndef _FPSE
    AboutDlgProc();
#endif
#endif
    return;
}

////////////////////////////////////////////////////////////////////////
// We are ever fine ;)
////////////////////////////////////////////////////////////////////////

extern "C" long softGPUtest(void) {
    // if test fails this function should return negative value for error (unable to continue)
    // and positive value for warning (can continue but output might be crappy)
    return 0;
}

////////////////////////////////////////////////////////////////////////
// Freeze
////////////////////////////////////////////////////////////////////////

typedef struct GPUFREEZETAG {
    unsigned long ulFreezeVersion;           // should be always 1 for now (set by main emu)
    unsigned long ulStatus;                  // current gpu status
    unsigned long ulControl[256];            // latest control register values
    unsigned char psxVRam[1024 * 1024 * 2];  // current VRam image (full 2 MB for ZN)
} GPUFreeze_t;

////////////////////////////////////////////////////////////////////////

long PCSX::SoftGPU::impl::freeze(unsigned long ulGetFreezeData, GPUFreeze_t *pF) {
    //----------------------------------------------------//
    if (ulGetFreezeData == 2)  // 2: info, which save slot is selected? (just for display)
    {
        long lSlotNum = *((long *)pF);
        if (lSlotNum < 0) return 0;
        if (lSlotNum > 8) return 0;
        lSelectedSlot = lSlotNum + 1;
        BuildDispMenu(0);
        return 1;
    }
    //----------------------------------------------------//
    if (!pF) return 0;  // some checks
    if (pF->ulFreezeVersion != 1) return 0;

    if (ulGetFreezeData == 1)  // 1: get data
    {
        pF->ulStatus = lGPUstatusRet;
        memcpy(pF->ulControl, ulStatusControl, 256 * sizeof(unsigned long));
        memcpy(pF->psxVRam, psxVub, 1024 * iGPUHeight * 2);

        return 1;
    }

    if (ulGetFreezeData != 0) return 0;  // 0: set data

    lGPUstatusRet = pF->ulStatus;
    memcpy(ulStatusControl, pF->ulControl, 256 * sizeof(unsigned long));
    memcpy(psxVub, pF->psxVRam, 1024 * iGPUHeight * 2);

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

    return 1;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// SAVE STATE DISPLAY STUFF
////////////////////////////////////////////////////////////////////////

// font 0-9, 24x20 pixels, 1 byte = 4 dots
// 00 = black
// 01 = white
// 10 = red
// 11 = transparent

unsigned char cFont[10][120] = {
    // 0
    {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x05, 0x54, 0x00, 0x00,
     0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00,
     0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00,
     0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x05, 0x54, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
    // 1
    {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x50, 0x00, 0x00,
     0x80, 0x00, 0x05, 0x50, 0x00, 0x00, 0x80, 0x00, 0x00, 0x50, 0x00, 0x00, 0x80, 0x00, 0x00, 0x50, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x50, 0x00, 0x00, 0x80, 0x00, 0x00, 0x50, 0x00, 0x00, 0x80, 0x00, 0x00, 0x50, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x50, 0x00, 0x00, 0x80, 0x00, 0x00, 0x50, 0x00, 0x00, 0x80, 0x00, 0x05, 0x55, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
    // 2
    {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x05, 0x54, 0x00, 0x00,
     0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00, 0x05, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x14, 0x00, 0x00, 0x80, 0x00, 0x00, 0x50, 0x00, 0x00, 0x80, 0x00, 0x01, 0x40, 0x00, 0x00,
     0x80, 0x00, 0x05, 0x00, 0x00, 0x00, 0x80, 0x00, 0x14, 0x00, 0x00, 0x00, 0x80, 0x00, 0x15, 0x55, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
    // 3
    {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x05, 0x54, 0x00, 0x00,
     0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00, 0x05, 0x00, 0x00,
     0x80, 0x00, 0x01, 0x54, 0x00, 0x00, 0x80, 0x00, 0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00, 0x05, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x05, 0x54, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
    // 4
    {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x14, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x54, 0x00, 0x00, 0x80, 0x00, 0x01, 0x54, 0x00, 0x00, 0x80, 0x00, 0x01, 0x54, 0x00, 0x00,
     0x80, 0x00, 0x05, 0x14, 0x00, 0x00, 0x80, 0x00, 0x14, 0x14, 0x00, 0x00, 0x80, 0x00, 0x15, 0x55, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x14, 0x00, 0x00, 0x80, 0x00, 0x00, 0x14, 0x00, 0x00, 0x80, 0x00, 0x00, 0x55, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
    // 5
    {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x15, 0x55, 0x00, 0x00,
     0x80, 0x00, 0x14, 0x00, 0x00, 0x00, 0x80, 0x00, 0x14, 0x00, 0x00, 0x00, 0x80, 0x00, 0x14, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x15, 0x54, 0x00, 0x00, 0x80, 0x00, 0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00, 0x05, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x05, 0x54, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
    // 6
    {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x01, 0x54, 0x00, 0x00,
     0x80, 0x00, 0x05, 0x00, 0x00, 0x00, 0x80, 0x00, 0x14, 0x00, 0x00, 0x00, 0x80, 0x00, 0x14, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x15, 0x54, 0x00, 0x00, 0x80, 0x00, 0x15, 0x05, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00,
     0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x05, 0x54, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
    // 7
    {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x15, 0x55, 0x00, 0x00,
     0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00, 0x14, 0x00, 0x00, 0x80, 0x00, 0x00, 0x14, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x50, 0x00, 0x00, 0x80, 0x00, 0x00, 0x50, 0x00, 0x00, 0x80, 0x00, 0x01, 0x40, 0x00, 0x00,
     0x80, 0x00, 0x01, 0x40, 0x00, 0x00, 0x80, 0x00, 0x05, 0x00, 0x00, 0x00, 0x80, 0x00, 0x05, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
    // 8
    {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x05, 0x54, 0x00, 0x00,
     0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00,
     0x80, 0x00, 0x05, 0x54, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00,
     0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x05, 0x54, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
    // 9
    {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x05, 0x54, 0x00, 0x00,
     0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00, 0x80, 0x00, 0x14, 0x05, 0x00, 0x00,
     0x80, 0x00, 0x14, 0x15, 0x00, 0x00, 0x80, 0x00, 0x05, 0x55, 0x00, 0x00, 0x80, 0x00, 0x00, 0x05, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x00, 0x14, 0x00, 0x00, 0x80, 0x00, 0x05, 0x50, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}};

////////////////////////////////////////////////////////////////////////

void PaintPicDot(unsigned char *p, unsigned char c) {
    if (c == 0) {
        *p++ = 0x00;
        *p++ = 0x00;
        *p = 0x00;
        return;
    }  // black
    if (c == 1) {
        *p++ = 0xff;
        *p++ = 0xff;
        *p = 0xff;
        return;
    }  // white
    if (c == 2) {
        *p++ = 0x00;
        *p++ = 0x00;
        *p = 0xff;
        return;
    }  // red
       // transparent
}

////////////////////////////////////////////////////////////////////////
// the main emu allocs 128x96x3 bytes, and passes a ptr
// to it in pMem... the plugin has to fill it with
// 8-8-8 bit BGR screen data (Win 24 bit BMP format
// without header).
// Beware: the func can be called at any time,
// so you have to use the frontbuffer to get a fully
// rendered picture

#ifdef _WIN32
extern "C" void softGPUgetScreenPic(unsigned char *pMem) {
#if 0
                 HRESULT ddrval;DDSURFACEDESC xddsd;unsigned char * pf;
 int x,y,c,v,iCol;RECT r,rt;
 float XS,YS;

 //----------------------------------------------------// Pete: creating a temp surface, blitting primary surface into it, get data from temp, and finally delete temp... seems to be better in VISTA
 DDPIXELFORMAT dd;LPDIRECTDRAWSURFACE DDSSave;

 memset(&xddsd, 0, sizeof(DDSURFACEDESC));
 xddsd.dwSize = sizeof(DDSURFACEDESC);
 xddsd.dwFlags = DDSD_WIDTH | DDSD_HEIGHT | DDSD_CAPS;
 xddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_SYSTEMMEMORY;
 xddsd.dwWidth        = iResX;
 xddsd.dwHeight       = iResY;

 if(IDirectDraw_CreateSurface(DX.DD,&xddsd, &DDSSave, NULL)) // create temp surface
  return;

 dd.dwSize=sizeof(DDPIXELFORMAT);                      // check out, what color we have
 IDirectDrawSurface_GetPixelFormat(DDSSave,&dd);

 if(dd.dwRBitMask==0x00007c00 &&
    dd.dwGBitMask==0x000003e0 &&
    dd.dwBBitMask==0x0000001f)       iCol=15;
 else
 if(dd.dwRBitMask==0x0000f800 &&
    dd.dwGBitMask==0x000007e0 &&
    dd.dwBBitMask==0x0000001f)       iCol=16;
 else                                iCol=32;

 r.left=0; r.right =iResX;                             // get blitting rects
 r.top=0;  r.bottom=iResY;
 rt.left=0; rt.right =iResX;
 rt.top=0;  rt.bottom=iResY;
 if(iWindowMode)
  {
   POINT Point={0,0};
   ClientToScreen(DX.hWnd,&Point);
   rt.left+=Point.x;rt.right+=Point.x;
   rt.top+=Point.y;rt.bottom+=Point.y;
  }

 IDirectDrawSurface_Blt(DDSSave,&r,DX.DDSPrimary,&rt,  // and blit from primary into temp
                        DDBLT_WAIT,NULL);

 //----------------------------------------------------//

 memset(&xddsd, 0, sizeof(DDSURFACEDESC));
 xddsd.dwSize   = sizeof(DDSURFACEDESC);
 xddsd.dwFlags  = DDSD_WIDTH | DDSD_HEIGHT;
 xddsd.dwWidth  = iResX;
 xddsd.dwHeight = iResY;

 XS=(float)iResX/128;
 YS=(float)iResY/96;

 ddrval=IDirectDrawSurface_Lock(DDSSave,NULL, &xddsd, DDLOCK_WAIT|DDLOCK_READONLY, NULL);

 if(ddrval==DDERR_SURFACELOST) IDirectDrawSurface_Restore(DDSSave);

 pf=pMem;

 if(ddrval==DD_OK)
  {
   unsigned char * ps=(unsigned char *)xddsd.lpSurface;

   if(iCol==16)
    {
     unsigned short sx;
     for(y=0;y<96;y++)
      {
       for(x=0;x<128;x++)
        {
         sx=*((unsigned short *)((ps)+
              r.top*xddsd.lPitch+
              (((int)((float)y*YS))*xddsd.lPitch)+
               r.left*2+
               ((int)((float)x*XS))*2));
         *(pf+0)=(sx&0x1f)<<3;
         *(pf+1)=(sx&0x7e0)>>3;
         *(pf+2)=(sx&0xf800)>>8;
         pf+=3;
        }
      }
    }
   else
   if(iCol==15)
    {
     unsigned short sx;
     for(y=0;y<96;y++)
      {
       for(x=0;x<128;x++)
        {
         sx=*((unsigned short *)((ps)+
              r.top*xddsd.lPitch+
              (((int)((float)y*YS))*xddsd.lPitch)+
               r.left*2+
               ((int)((float)x*XS))*2));
         *(pf+0)=(sx&0x1f)<<3;
         *(pf+1)=(sx&0x3e0)>>2;
         *(pf+2)=(sx&0x7c00)>>7;
         pf+=3;
        }
      }
    }
   else
    {
     unsigned long sx;
     for(y=0;y<96;y++)
      {
       for(x=0;x<128;x++)
        {
         sx=*((unsigned long *)((ps)+
              r.top*xddsd.lPitch+
              (((int)((float)y*YS))*xddsd.lPitch)+
               r.left*4+
               ((int)((float)x*XS))*4));
         *(pf+0)=(unsigned char)((sx&0xff));
         *(pf+1)=(unsigned char)((sx&0xff00)>>8);
         *(pf+2)=(unsigned char)((sx&0xff0000)>>16);
         pf+=3;
        }
      }
    }
  }

 IDirectDrawSurface_Unlock(DDSSave,&xddsd);
 IDirectDrawSurface_Release(DDSSave);

/*
 HRESULT ddrval;DDSURFACEDESC xddsd;unsigned char * pf;
 int x,y,c,v;RECT r;
 float XS,YS;

 memset(&xddsd, 0, sizeof(DDSURFACEDESC));
 xddsd.dwSize   = sizeof(DDSURFACEDESC);
 xddsd.dwFlags  = DDSD_WIDTH | DDSD_HEIGHT;
 xddsd.dwWidth  = iResX;
 xddsd.dwHeight = iResY;

 r.left=0; r.right =iResX;
 r.top=0;  r.bottom=iResY;

 if(iWindowMode)
  {
   POINT Point={0,0};
   ClientToScreen(DX.hWnd,&Point);
   r.left+=Point.x;r.right+=Point.x;
   r.top+=Point.y;r.bottom+=Point.y;
  }

 XS=(float)iResX/128;
 YS=(float)iResY/96;

 ddrval=IDirectDrawSurface_Lock(DX.DDSPrimary,NULL, &xddsd, DDLOCK_WAIT|DDLOCK_READONLY, NULL);

 if(ddrval==DDERR_SURFACELOST) IDirectDrawSurface_Restore(DX.DDSPrimary);

 pf=pMem;

 if(ddrval==DD_OK)
  {
   unsigned char * ps=(unsigned char *)xddsd.lpSurface;

   if(iDesktopCol==16)
    {
     unsigned short sx;
     for(y=0;y<96;y++)
      {
       for(x=0;x<128;x++)
        {
         sx=*((unsigned short *)((ps)+
              r.top*xddsd.lPitch+
              (((int)((float)y*YS))*xddsd.lPitch)+
               r.left*2+
               ((int)((float)x*XS))*2));
         *(pf+0)=(sx&0x1f)<<3;
         *(pf+1)=(sx&0x7e0)>>3;
         *(pf+2)=(sx&0xf800)>>8;
         pf+=3;
        }
      }
    }
   else
   if(iDesktopCol==15)
    {
     unsigned short sx;
     for(y=0;y<96;y++)
      {
       for(x=0;x<128;x++)
        {
         sx=*((unsigned short *)((ps)+
              r.top*xddsd.lPitch+
              (((int)((float)y*YS))*xddsd.lPitch)+
               r.left*2+
               ((int)((float)x*XS))*2));
         *(pf+0)=(sx&0x1f)<<3;
         *(pf+1)=(sx&0x3e0)>>2;
         *(pf+2)=(sx&0x7c00)>>7;
         pf+=3;
        }
      }
    }
   else
    {
     unsigned long sx;
     for(y=0;y<96;y++)
      {
       for(x=0;x<128;x++)
        {
         sx=*((unsigned long *)((ps)+
              r.top*xddsd.lPitch+
              (((int)((float)y*YS))*xddsd.lPitch)+
               r.left*4+
               ((int)((float)x*XS))*4));
         *(pf+0)=(unsigned char)((sx&0xff));
         *(pf+1)=(unsigned char)((sx&0xff00)>>8);
         *(pf+2)=(unsigned char)((sx&0xff0000)>>16);
         pf+=3;
        }
      }
    }
  }

 IDirectDrawSurface_Unlock(DX.DDSPrimary,&xddsd);
*/

 /////////////////////////////////////////////////////////////////////
 // generic number/border painter

 pf=pMem+(103*3);                                      // offset to number rect

 for(y=0;y<20;y++)                                     // loop the number rect pixel
  {
   for(x=0;x<6;x++)
    {
     c=cFont[lSelectedSlot][x+y*6];                    // get 4 char dot infos at once (number depends on selected slot)
     v=(c&0xc0)>>6;
     PaintPicDot(pf,(unsigned char)v);pf+=3;                // paint the dots into the rect
     v=(c&0x30)>>4;
     PaintPicDot(pf,(unsigned char)v);pf+=3;
     v=(c&0x0c)>>2;
     PaintPicDot(pf,(unsigned char)v);pf+=3;
     v=c&0x03;
     PaintPicDot(pf,(unsigned char)v);pf+=3;
    }
   pf+=104*3;                                          // next rect y line
  }

 pf=pMem;                                              // ptr to first pos in 128x96 pic
 for(x=0;x<128;x++)                                    // loop top/bottom line
  {
   *(pf+(95*128*3))=0x00;*pf++=0x00;
   *(pf+(95*128*3))=0x00;*pf++=0x00;                   // paint it red
   *(pf+(95*128*3))=0xff;*pf++=0xff;
  }
 pf=pMem;                                              // ptr to first pos
 for(y=0;y<96;y++)                                     // loop left/right line
  {
   *(pf+(127*3))=0x00;*pf++=0x00;
   *(pf+(127*3))=0x00;*pf++=0x00;                      // paint it red
   *(pf+(127*3))=0xff;*pf++=0xff;
   pf+=127*3;                                          // offset to next line
  }

#endif  // 0
}

#else
// LINUX version:

#ifdef USE_DGA2
#include <X11/extensions/xf86dga.h>
extern XDGADevice *dgaDev;
#endif
extern char *Xpixels;

void GPUgetScreenPic(unsigned char *pMem) {
    unsigned short c;
    unsigned char *pf;
    int x, y;

    float XS = (float)iResX / 128;
    float YS = (float)iResY / 96;

    pf = pMem;

    memset(pMem, 0, 128 * 96 * 3);

    if (Xpixels) {
        unsigned char *ps = (unsigned char *)Xpixels;

        if (iDesktopCol == 16) {
            long lPitch = iResX << 1;
            unsigned short sx;
#ifdef USE_DGA2
            if (!iWindowMode) lPitch += (dgaDev->mode.imageWidth - dgaDev->mode.viewportWidth) * 2;
#endif
            for (y = 0; y < 96; y++) {
                for (x = 0; x < 128; x++) {
                    sx = *((unsigned short *)((ps) + (((int)((float)y * YS)) * lPitch) + ((int)((float)x * XS)) * 2));
                    *(pf + 0) = (sx & 0x1f) << 3;
                    *(pf + 1) = (sx & 0x7e0) >> 3;
                    *(pf + 2) = (sx & 0xf800) >> 8;
                    pf += 3;
                }
            }
        } else if (iDesktopCol == 15) {
            long lPitch = iResX << 1;
            unsigned short sx;
#ifdef USE_DGA2
            if (!iWindowMode) lPitch += (dgaDev->mode.imageWidth - dgaDev->mode.viewportWidth) * 2;
#endif
            for (y = 0; y < 96; y++) {
                for (x = 0; x < 128; x++) {
                    sx = *((unsigned short *)((ps) + (((int)((float)y * YS)) * lPitch) + ((int)((float)x * XS)) * 2));
                    *(pf + 0) = (sx & 0x1f) << 3;
                    *(pf + 1) = (sx & 0x3e0) >> 2;
                    *(pf + 2) = (sx & 0x7c00) >> 7;
                    pf += 3;
                }
            }
        } else {
            long lPitch = iResX << 2;
            unsigned long sx;
#ifdef USE_DGA2
            if (!iWindowMode) lPitch += (dgaDev->mode.imageWidth - dgaDev->mode.viewportWidth) * 4;
#endif
            for (y = 0; y < 96; y++) {
                for (x = 0; x < 128; x++) {
                    sx = *((unsigned long *)((ps) + (((int)((float)y * YS)) * lPitch) + ((int)((float)x * XS)) * 4));
                    *(pf + 0) = (sx & 0xff);
                    *(pf + 1) = (sx & 0xff00) >> 8;
                    *(pf + 2) = (sx & 0xff0000) >> 16;
                    pf += 3;
                }
            }
        }
    }

    /////////////////////////////////////////////////////////////////////
    // generic number/border painter

    pf = pMem + (103 * 3);  // offset to number rect

    for (y = 0; y < 20; y++)  // loop the number rect pixel
    {
        for (x = 0; x < 6; x++) {
            c = cFont[lSelectedSlot][x + y * 6];  // get 4 char dot infos at once (number depends on selected slot)
            PaintPicDot(pf, (c & 0xc0) >> 6);
            pf += 3;  // paint the dots into the rect
            PaintPicDot(pf, (c & 0x30) >> 4);
            pf += 3;
            PaintPicDot(pf, (c & 0x0c) >> 2);
            pf += 3;
            PaintPicDot(pf, (c & 0x03));
            pf += 3;
        }
        pf += 104 * 3;  // next rect y line
    }

    pf = pMem;                 // ptr to first pos in 128x96 pic
    for (x = 0; x < 128; x++)  // loop top/bottom line
    {
        *(pf + (95 * 128 * 3)) = 0x00;
        *pf++ = 0x00;
        *(pf + (95 * 128 * 3)) = 0x00;
        *pf++ = 0x00;  // paint it red
        *(pf + (95 * 128 * 3)) = 0xff;
        *pf++ = 0xff;
    }
    pf = pMem;                // ptr to first pos
    for (y = 0; y < 96; y++)  // loop left/right line
    {
        *(pf + (127 * 3)) = 0x00;
        *pf++ = 0x00;
        *(pf + (127 * 3)) = 0x00;
        *pf++ = 0x00;  // paint it red
        *(pf + (127 * 3)) = 0xff;
        *pf++ = 0xff;
        pf += 127 * 3;  // offset to next line
    }
}
#endif

////////////////////////////////////////////////////////////////////////
// func will be called with 128x96x3 BGR data.
// the plugin has to store the data and display
// it in the upper right corner.
// If the func is called with a NULL ptr, you can
// release your picture data and stop displaying
// the screen pic

extern "C" void softGPUshowScreenPic(unsigned char *pMem) {
    DestroyPic();           // destroy old pic data
    if (pMem == 0) return;  // done
    CreatePic(pMem);        // create new pic... don't free pMem or something like that... just read from it
}

////////////////////////////////////////////////////////////////////////

void GPUsetfix(unsigned long dwFixBits) { dwEmuFixes = dwFixBits; }

////////////////////////////////////////////////////////////////////////

void GPUsetframelimit(unsigned long option) {
    bInitCap = TRUE;

    if (option == 1) {
        UseFrameLimit = 1;
        UseFrameSkip = 0;
        iFrameLimit = 2;
        SetAutoFrameCap();
        BuildDispMenu(0);
    } else {
        UseFrameLimit = 0;
    }
}

////////////////////////////////////////////////////////////////////////

#ifdef _WIN32

extern "C" void softGPUvisualVibration(unsigned long iSmall, unsigned long iBig) {
    int iVibVal;

    if (PreviousPSXDisplay.DisplayMode.x)  // calc min "shake pixel" from screen width
        iVibVal = max(1, iResX / PreviousPSXDisplay.DisplayMode.x);
    else
        iVibVal = 1;
    // big rumble: 4...15 sp ; small rumble 1...3 sp
    if (iBig)
        iRumbleVal = max(4 * iVibVal, min(15 * iVibVal, ((int)iBig * iVibVal) / 10));
    else
        iRumbleVal = max(1 * iVibVal, min(3 * iVibVal, ((int)iSmall * iVibVal) / 10));

    srand(timeGetTime());  // init rand (will be used in BufferSwap)

    iRumbleTime = 15;  // let the rumble last 16 buffer swaps
}

#endif

////////////////////////////////////////////////////////////////////////
