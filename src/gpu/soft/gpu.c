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

#if !defined(_MACGL) && !defined(_WIN32)
//#include "config.h"
#endif

#define _IN_GPU

#include "gpu.h"
#include "cfg.h"
#include "draw.h"
#include "externals.h"
#include "fps.h"
#include "key.h"
#include "menu.h"
#include "prim.h"
#include "psemu_plugin_defs.h"
#include "stdint.h"
#include "swap.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#include <locale.h>
#define _(x) gettext(x)
#define N_(x) (x)

// If running under Mac OS X, use the Localizable.strings file instead.
#elif defined(_MACOSX)
#ifdef PCSXRCORE
__private_extern char *Pcsxr_locale_text(char *toloc);
#define _(String) Pcsxr_locale_text(String)
#define N_(String) String
#else
#ifndef PCSXRPLUG
#warning please define the plug being built to use Mac OS X localization!
#define _(msgid) msgid
#define N_(msgid) msgid
#else
// Kludge to get the preprocessor to accept PCSXRPLUG as a variable.
#define PLUGLOC_x(x, y) x##y
#define PLUGLOC_y(x, y) PLUGLOC_x(x, y)
#define PLUGLOC PLUGLOC_y(PCSXRPLUG, _locale_text)
__private_extern char *PLUGLOC(char *toloc);
#define _(String) PLUGLOC(String)
#define N_(String) String
#endif
#endif
#else
#define _(x) (x)
#define N_(x) (x)
#endif

#ifdef _WIN32
//#include "resource.h"
//#include "record.h"
#endif

////////////////////////////////////////////////////////////////////////
// PPDK developer must change libraryName field and can change revision and build
////////////////////////////////////////////////////////////////////////

const unsigned char version = 1;  // do not touch - library for PSEmu 1.x
const unsigned char revision = 1;
const unsigned char build = 17;  // increase that with each version

#if defined(_WIN32)
static char *libraryName = N_("Soft Driver");
static char *libraryInfo = N_("P.E.Op.S. Soft Driver V1.17\nCoded by Pete Bernert and the P.E.Op.S. team\n");
#elif defined(_MACGL)
static char *libraryName = N_("SoftGL Driver");
static char *libraryInfo = N_("P.E.Op.S. SoftGL Driver V1.17\nCoded by Pete Bernert and the P.E.Op.S. team\n");
#else
static char *libraryName = N_("XVideo Driver");
static char *libraryInfo = N_("P.E.Op.S. Xvideo Driver V1.17\nCoded by Pete Bernert and the P.E.Op.S. team\n");
#endif

static char *PluginAuthor = N_("Pete Bernert and the P.E.Op.S. team");

////////////////////////////////////////////////////////////////////////
// memory image of the PSX vram
////////////////////////////////////////////////////////////////////////

unsigned char *psxVSecure;
unsigned char *psxVub;
signed char *psxVsb;
unsigned short *psxVuw;
unsigned short *psxVuw_eom;
signed short *psxVsw;
uint32_t *psxVul;
int32_t *psxVsl;

////////////////////////////////////////////////////////////////////////
// GPU globals
////////////////////////////////////////////////////////////////////////

static long lGPUdataRet;
long lGPUstatusRet;
char szDispBuf[64];
char szMenuBuf[36];
char szDebugText[512];
uint32_t ulStatusControl[256];

static uint32_t gpuDataM[256];
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
uint32_t lGPUInfoVals[16];
static int iFakePrimBusy = 0;
uint32_t vBlank = 0;
int iRumbleVal = 0;
int iRumbleTime = 0;
BOOL oddLines;

uint32_t dwGPUVersion = 0;
int iGPUHeight = 512;
int iGPUHeightMask = 511;
int GlobalTextIL = 0;
int iTileCheat = 0;

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

#include <time.h>
time_t tStart;

void CALLBACK softGPUdisplayText(char *pText)  // some debug func
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

void CALLBACK softGPUdisplayFlags(unsigned long dwFlags)  // some info func
{
    dwCoreFlags = dwFlags;
    BuildDispMenu(0);
}

////////////////////////////////////////////////////////////////////////
// stuff to make this a true PDK module
////////////////////////////////////////////////////////////////////////

char *CALLBACK PSEgetLibName(void) { return _(libraryName); }

unsigned long CALLBACK PSEgetLibType(void) { return PSE_LT_GPU; }

unsigned long CALLBACK PSEgetLibVersion(void) { return version << 16 | revision << 8 | build; }

char *GPUgetLibInfos(void) { return _(libraryInfo); }

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
#if !defined(_MACGL) && !defined(_WIN32)
    strcpy(szTxt, "Misc:\r\n- MaintainAspect: ");
    if (iMaintainAspect == 0)
        strcat(szTxt, "disabled");
    else if (iMaintainAspect == 1)
        strcat(szTxt, "enabled");
    strcat(szTxt, "\r\n");
    strcat(pB, szTxt);
#endif
    sprintf(szTxt, "- Game fixes: %s [%08x]\r\n", szO[iUseFixes], dwCfgFixes);
    strcat(pB, szTxt);
    //----------------------------------------------------//
    return pB;
}

static void DoTextSnapShot(int iNum) {
    FILE *txtfile;
    char szTxt[256];
    char *pB;

#ifdef _WIN32
    sprintf(szTxt, "snap\\pcsxr%04d.txt", iNum);
#else
    sprintf(szTxt, "%s/pcsxr%04d.txt", getenv("HOME"), iNum);
#endif

    if ((txtfile = fopen(szTxt, "wb")) == NULL) return;

    pB = pGetConfigInfos(0);
    if (pB) {
        fwrite(pB, strlen(pB), 1, txtfile);
        free(pB);
    }
    fclose(txtfile);
}

void CALLBACK softGPUmakeSnapshot(void) {
    FILE *bmpfile;
    char filename[256];
    unsigned char header[0x36];
    long size, height;
    unsigned char line[1024 * 3];
    short i, j;
    unsigned char empty[2] = {0, 0};
    unsigned short color;
    unsigned long snapshotnr = 0;
    unsigned char *pD;

    height = PreviousPSXDisplay.DisplayMode.y;

    size = height * PreviousPSXDisplay.Range.x1 * 3 + 0x38;

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
    header[0x12] = PreviousPSXDisplay.Range.x1 % 256;
    header[0x13] = PreviousPSXDisplay.Range.x1 / 256;
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
        sprintf(filename, "snap\\pcsxr%04ld.bmp", snapshotnr);
#else
        sprintf(filename, "%s/pcsxr%04ld.bmp", getenv("HOME"), snapshotnr);
#endif

        bmpfile = fopen(filename, "rb");
        if (bmpfile == NULL) break;

        fclose(bmpfile);
    } while (TRUE);

    // try opening new snapshot file
    if ((bmpfile = fopen(filename, "wb")) == NULL) return;

    fwrite(header, 0x36, 1, bmpfile);
    for (i = height + PSXDisplay.DisplayPosition.y - 1; i >= PSXDisplay.DisplayPosition.y; i--) {
        pD = (unsigned char *)&psxVuw[i * 1024 + PSXDisplay.DisplayPosition.x];
        for (j = 0; j < PreviousPSXDisplay.Range.x1; j++) {
            if (PSXDisplay.RGB24) {
                uint32_t lu = *(uint32_t *)pD;
                line[j * 3 + 2] = (unsigned char)RED(lu);
                line[j * 3 + 1] = (unsigned char)GREEN(lu);
                line[j * 3 + 0] = (unsigned char)BLUE(lu);
                pD += 3;
            } else {
                color = GETLE16(pD);
                line[j * 3 + 2] = (color << 3) & 0xf1;
                line[j * 3 + 1] = (color >> 2) & 0xf1;
                line[j * 3 + 0] = (color >> 7) & 0xf1;
                pD += 2;
            }
        }
        fwrite(line, PreviousPSXDisplay.Range.x1 * 3, 1, bmpfile);
    }
    fwrite(empty, 0x2, 1, bmpfile);
    fclose(bmpfile);

    DoTextSnapShot(snapshotnr);
}

////////////////////////////////////////////////////////////////////////
// INIT, will be called after lib load... well, just do some var init...
////////////////////////////////////////////////////////////////////////

long CALLBACK softGPUinit()  // GPU INIT
{
    memset(ulStatusControl, 0, 256 * sizeof(uint32_t));  // init save state scontrol field

    szDebugText[0] = 0;  // init debug text buffer

    psxVSecure = (unsigned char *)malloc((iGPUHeight * 2) * 1024 +
                                         (1024 * 1024));  // always alloc one extra MB for soft drawing funcs security
    if (!psxVSecure) return -1;

    //!!! ATTENTION !!!
    psxVub = psxVSecure + 512 * 1024;  // security offset into double sized psx vram!

    psxVsb = (signed char *)psxVub;  // different ways of accessing PSX VRAM
    psxVsw = (signed short *)psxVub;
    psxVsl = (int32_t *)psxVub;
    psxVuw = (unsigned short *)psxVub;
    psxVul = (uint32_t *)psxVub;

    psxVuw_eom = psxVuw + 1024 * iGPUHeight;  // pre-calc of end of vram

    memset(psxVSecure, 0x00, (iGPUHeight * 2) * 1024 + (1024 * 1024));
    memset(lGPUInfoVals, 0x00, 16 * sizeof(uint32_t));

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
    bDoVSyncUpdate = TRUE;
    vBlank = 0;
    oddLines = FALSE;

    // Get a handle for kernel32.dll, and access the required export function
    LoadKernel32();

    return 0;
}

////////////////////////////////////////////////////////////////////////
// Here starts all...
////////////////////////////////////////////////////////////////////////

#ifdef _WIN32
long CALLBACK softGPUopen(HWND hwndGPU)  // GPU OPEN
{
    hWGPU = hwndGPU;  // store hwnd

    SetKeyHandler();  // sub-class window

    if (bChangeWinMode)
        ReadWinSizeConfig();  // alt+enter toggle?
    else                      // or first time startup?
    {
        ReadConfig();  // read registry
        InitFPS();
    }

    bIsFirstFrame = TRUE;  // we have to init later
    bDoVSyncUpdate = TRUE;

    ulInitDisplay();  // setup direct draw

    if (iStopSaver) D_SetThreadExecutionState(ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED | ES_CONTINUOUS);

    return 0;
}

#else

long GPUopen(unsigned long *disp, char *CapText, char *CfgFile) {
    unsigned long d;

    pCaptionText = CapText;

    ReadConfig();  // read registry

    InitFPS();

    bIsFirstFrame = TRUE;  // we have to init later
    bDoVSyncUpdate = TRUE;

    d = ulInitDisplay();  // setup x

    if (disp) *disp = d;  // wanna x pointer? ok

    if (d) return 0;
    return -1;
}

#endif

////////////////////////////////////////////////////////////////////////
// time to leave...
////////////////////////////////////////////////////////////////////////

long CALLBACK softGPUclose()  // GPU CLOSE
{
#ifdef _WIN32
// if(RECORD_RECORDING==TRUE) {RECORD_Stop();RECORD_RECORDING=FALSE;BuildDispMenu(0);}
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

long CALLBACK softGPUshutdown()  // GPU SHUTDOWN
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
        sprintf(szDispBuf, "FPS %06.1f", fps_cur);
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

    bDoVSyncUpdate = TRUE;
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

#if defined(_WIN32)

void ChangeWindowMode(void)  // TOGGLE FULLSCREEN - WINDOW
{
    softGPUclose();
    iWindowMode = !iWindowMode;
    softGPUopen(hWGPU);
    bChangeWinMode = FALSE;
    bDoVSyncUpdate = TRUE;
}

#elif !defined(_MACGL)

#include "draw.h"

void ChangeWindowMode(void)  // TOGGLE FULLSCREEN - WINDOW
{
    extern Display *display;
    extern Window window;
    extern int root_window_id;
    extern Screen *screen;
    XSizeHints hints;
    MotifWmHints mwmhints;
    Atom mwmatom;

    screen = DefaultScreenOfDisplay(display);
    iWindowMode = !iWindowMode;

    if (!iWindowMode)  // fullscreen
    {
        mwmhints.flags = MWM_HINTS_DECORATIONS;
        mwmhints.functions = 0;
        mwmhints.decorations = 0;
        mwmhints.input_mode = 0;
        mwmatom = XInternAtom(display, "_MOTIF_WM_HINTS", 0);
        XChangeProperty(display, window, mwmatom, mwmatom, 32, PropModeReplace, (unsigned char *)&mwmhints, 5);

        XResizeWindow(display, window, screen->width, screen->height);

        hints.min_width = hints.max_width = hints.base_width = screen->width;
        hints.min_height = hints.max_height = hints.base_height = screen->height;

        XSetWMNormalHints(display, window, &hints);

        {
            XEvent xev;

            memset(&xev, 0, sizeof(xev));
            xev.xclient.type = ClientMessage;
            xev.xclient.serial = 0;
            xev.xclient.send_event = 1;
            xev.xclient.message_type = XInternAtom(display, "_NET_WM_STATE", 0);
            xev.xclient.window = window;
            xev.xclient.format = 32;
            xev.xclient.data.l[0] = 1;
            xev.xclient.data.l[1] = XInternAtom(display, "_NET_WM_STATE_FULLSCREEN", 0);
            xev.xclient.data.l[2] = 0;
            xev.xclient.data.l[3] = 0;
            xev.xclient.data.l[4] = 0;

            XSendEvent(display, root_window_id, 0, SubstructureRedirectMask | SubstructureNotifyMask, &xev);
        }
    } else {
        {
            XEvent xev;

            memset(&xev, 0, sizeof(xev));
            xev.xclient.type = ClientMessage;
            xev.xclient.serial = 0;
            xev.xclient.send_event = 1;
            xev.xclient.message_type = XInternAtom(display, "_NET_WM_STATE", 0);
            xev.xclient.window = window;
            xev.xclient.format = 32;
            xev.xclient.data.l[0] = 0;
            xev.xclient.data.l[1] = XInternAtom(display, "_NET_WM_STATE_FULLSCREEN", 0);
            xev.xclient.data.l[2] = 0;
            xev.xclient.data.l[3] = 0;
            xev.xclient.data.l[4] = 0;

            XSendEvent(display, root_window_id, 0, SubstructureRedirectMask | SubstructureNotifyMask, &xev);
        }

        mwmhints.flags = MWM_HINTS_DECORATIONS;
        mwmhints.functions = 0;
        mwmhints.decorations = 1;
        mwmhints.input_mode = 0;
        mwmatom = XInternAtom(display, "_MOTIF_WM_HINTS", 0);

        // This shouldn't work on 64 bit longs, but it does...in fact, it breaks when I change all the mwmhints to int.
        // I don't pretend to understand it.
        XChangeProperty(display, window, mwmatom, mwmatom, 32, PropModeReplace, (unsigned char *)&mwmhints, 5);

        hints.flags = USPosition | USSize;
        hints.base_width = iResX;
        hints.base_height = iResY;
        XSetWMNormalHints(display, window, &hints);

        XResizeWindow(display, window, iResX, iResY);
    }

    DoClearScreenBuffer();

    bChangeWinMode = FALSE;
    bDoVSyncUpdate = TRUE;
}

#endif

////////////////////////////////////////////////////////////////////////
// gun cursor func: player=0-7, x=0-511, y=0-255
////////////////////////////////////////////////////////////////////////

void CALLBACK softGPUcursor(int iPlayer, int x, int y) {
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

void CALLBACK softGPUupdateLace(void)  // VSYNC
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

#ifdef _WIN32
// if(RECORD_RECORDING)
//  if(RECORD_WriteFrame()==FALSE)
//   {RECORD_RECORDING=FALSE;RECORD_Stop();}
#endif

#ifndef _MACGL
    if (bChangeWinMode) ChangeWindowMode();  // toggle full - window mode
#endif

    bDoVSyncUpdate = FALSE;  // vsync done
}

////////////////////////////////////////////////////////////////////////
// process read request from GPU status register
////////////////////////////////////////////////////////////////////////

uint32_t CALLBACK softGPUreadStatus(void)  // READ STATUS
{
    if (vBlank || oddLines == FALSE) {  // vblank or even lines
        lGPUstatusRet &= ~(0x80000000);
    } else {  // Oddlines and not vblank
        lGPUstatusRet |= 0x80000000;
    }

    if (dwActFixes & 1) {
        static int iNumRead = 0;  // odd/even hack
        if ((iNumRead++) == 2) {
            iNumRead = 0;
            lGPUstatusRet ^= 0x80000000;  // interlaced bit toggle... we do it on every 3 read status... needed by some
                                          // games (like ChronoCross) with old epsxe versions (1.5.2 and older)
        }
    }

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
    }
    return lGPUstatusRet;
}

////////////////////////////////////////////////////////////////////////
// processes data send to GPU status register
// these are always single packet commands.
////////////////////////////////////////////////////////////////////////

void CALLBACK softGPUwriteStatus(uint32_t gdata)  // WRITE STATUS
{
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
            drawX = drawY = 0;
            drawW = drawH = 0;
            sSetMask = 0;
            lSetMask = 0;
            bCheckMask = FALSE;
            usMirror = 0;
            GlobalTextAddrX = 0;
            GlobalTextAddrY = 0;
            GlobalTextTP = 0;
            GlobalTextABR = 0;
            PSXDisplay.RGB24 = FALSE;
            PSXDisplay.Interlaced = FALSE;
            bUsingTWin = FALSE;
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

            bDoVSyncUpdate = TRUE;

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

static __inline void FinishedVRAMWrite(void) {
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

static __inline void FinishedVRAMRead(void) {
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

void CALLBACK softGPUreadDataMem(uint32_t *pMem, int iSize) {
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
            lGPUdataRet = (uint32_t)GETLE16(VRAMRead.ImagePtr);

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
            lGPUdataRet |= (uint32_t)GETLE16(VRAMRead.ImagePtr) << 16;
            PUTLE32(pMem, lGPUdataRet);
            pMem++;

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

uint32_t CALLBACK softGPUreadData(void) {
    uint32_t l;
    softGPUreadDataMem(&l, 1);
    return lGPUdataRet;
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

void CALLBACK softGPUwriteDataMem(uint32_t *pMem, int iSize) {
    unsigned char command;
    uint32_t gdata = 0;
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

                gdata = GETLE32(pMem);
                pMem++;

                // Write odd pixel - Wrap from beginning to next index if going past GPU width
                if (VRAMWrite.Width + VRAMWrite.x - VRAMWrite.RowsRemaining >= 1024) {
                    PUTLE16(VRAMWrite.ImagePtr - 1024, (unsigned short)gdata);
                    VRAMWrite.ImagePtr++;
                } else {
                    PUTLE16(VRAMWrite.ImagePtr, (unsigned short)gdata);
                    VRAMWrite.ImagePtr++;
                }
                if (VRAMWrite.ImagePtr >= psxVuw_eom)
                    VRAMWrite.ImagePtr -= iGPUHeight * 1024;  // Check if went past framebuffer
                VRAMWrite.RowsRemaining--;

                // Check if end at odd pixel drawn
                if (VRAMWrite.RowsRemaining <= 0) {
                    VRAMWrite.ColsRemaining--;
                    if (VRAMWrite.ColsRemaining <= 0)  // last pixel is odd width
                    {
                        gdata = (gdata & 0xFFFF) | (((uint32_t)GETLE16(VRAMWrite.ImagePtr)) << 16);
                        FinishedVRAMWrite();
                        bDoVSyncUpdate = TRUE;
                        goto ENDVRAM;
                    }
                    VRAMWrite.RowsRemaining = VRAMWrite.Width;
                    VRAMWrite.ImagePtr += 1024 - VRAMWrite.Width;
                }

                // Write even pixel - Wrap from beginning to next index if going past GPU width
                if (VRAMWrite.Width + VRAMWrite.x - VRAMWrite.RowsRemaining >= 1024) {
                    PUTLE16(VRAMWrite.ImagePtr - 1024, (unsigned short)(gdata >> 16));
                    VRAMWrite.ImagePtr++;
                } else {
                    PUTLE16(VRAMWrite.ImagePtr, (unsigned short)(gdata >> 16));
                    VRAMWrite.ImagePtr++;
                }
                if (VRAMWrite.ImagePtr >= psxVuw_eom)
                    VRAMWrite.ImagePtr -= iGPUHeight * 1024;  // Check if went past framebuffer
                VRAMWrite.RowsRemaining--;
            }

            VRAMWrite.RowsRemaining = VRAMWrite.Width;
            VRAMWrite.ColsRemaining--;
            VRAMWrite.ImagePtr += 1024 - VRAMWrite.Width;
            bFinished = TRUE;
        }

        FinishedVRAMWrite();
        if (bFinished) bDoVSyncUpdate = TRUE;
    }

ENDVRAM:

    if (DataWriteMode == DR_NORMAL) {
        void (**primFunc)(unsigned char *);
        if (bSkipNextFrame)
            primFunc = primTableSkip;
        else
            primFunc = primTableJ;

        for (; i < iSize;) {
            if (DataWriteMode == DR_VRAMTRANSFER) goto STARTVRAM;

            gdata = GETLE32(pMem);
            pMem++;
            i++;

            if (gpuDataC == 0) {
                command = (unsigned char)((gdata >> 24) & 0xff);

                // if(command>=0xb0 && command<0xc0) auxprintf("b0 %x!!!!!!!!!\n",command);

                if (primTableCX[command]) {
                    gpuDataC = primTableCX[command];
                    gpuCommand = command;
                    PUTLE32(&gpuDataM[0], gdata);
                    gpuDataP = 1;
                } else
                    continue;
            } else {
                PUTLE32(&gpuDataM[gpuDataP], gdata);
                if (gpuDataC > 128) {
                    if ((gpuDataC == 254 && gpuDataP >= 3) || (gpuDataC == 255 && gpuDataP >= 4 && !(gpuDataP & 1))) {
                        if ((gpuDataM[gpuDataP] & 0xF000F000) == 0x50005000) gpuDataP = gpuDataC - 1;
                    }
                }
                gpuDataP++;
            }

            if (gpuDataP == gpuDataC) {
                gpuDataC = gpuDataP = 0;
                primFunc[gpuCommand]((unsigned char *)gpuDataM);
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

void CALLBACK softGPUwriteData(uint32_t gdata) {
    PUTLE32(&gdata, gdata);
    softGPUwriteDataMem(&gdata, 1);
}

////////////////////////////////////////////////////////////////////////
// this functions will be removed soon (or 'soonish')... not really needed, but some emus want them
////////////////////////////////////////////////////////////////////////

void CALLBACK softGPUsetMode(unsigned long gdata) {
    // Peops does nothing here...
    // DataWriteMode=(gdata&1)?DR_VRAMTRANSFER:DR_NORMAL;
    // DataReadMode =(gdata&2)?DR_VRAMTRANSFER:DR_NORMAL;
}

long CALLBACK softGPUgetMode(void) {
    long iT = 0;

    if (DataWriteMode == DR_VRAMTRANSFER) iT |= 0x1;
    if (DataReadMode == DR_VRAMTRANSFER) iT |= 0x2;
    return iT;
}

////////////////////////////////////////////////////////////////////////
// call config dlg
////////////////////////////////////////////////////////////////////////

long CALLBACK softGPUconfigure(void) {
#ifdef _WIN32
    HWND hWP = GetActiveWindow();

// DialogBox(hInst,MAKEINTRESOURCE(IDD_CFGSOFT),
//           hWP,(DLGPROC)SoftDlgProc);
#else
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

static __inline BOOL CheckForEndlessLoop(unsigned long laddr) {
    if (laddr == lUsedAddr[1]) return TRUE;
    if (laddr == lUsedAddr[2]) return TRUE;

    if (laddr < lUsedAddr[0])
        lUsedAddr[1] = laddr;
    else
        lUsedAddr[2] = laddr;
    lUsedAddr[0] = laddr;
    return FALSE;
}

long CALLBACK softGPUdmaChain(uint32_t *baseAddrL, uint32_t addr) {
    uint32_t dmaMem;
    unsigned char *baseAddrB;
    short count;
    unsigned int DMACommandCounter = 0;

    GPUIsBusy;

    lUsedAddr[0] = lUsedAddr[1] = lUsedAddr[2] = 0xffffff;

    baseAddrB = (unsigned char *)baseAddrL;

    do {
        if (iGPUHeight == 512) addr &= 0x1FFFFC;
        if (DMACommandCounter++ > 2000000) break;
        if (CheckForEndlessLoop(addr)) break;

        count = baseAddrB[addr + 3];

        dmaMem = addr + 4;

        if (count > 0) softGPUwriteDataMem(&baseAddrL[dmaMem >> 2], count);

        addr = GETLE32(&baseAddrL[addr >> 2]) & 0xffffff;
    } while (addr != 0xffffff);

    GPUIsIdle;

    return 0;
}

////////////////////////////////////////////////////////////////////////
// show about dlg
////////////////////////////////////////////////////////////////////////

#if 0
BOOL CALLBACK AboutDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
 switch(uMsg)
  {
   case WM_COMMAND:
    {
     switch(LOWORD(wParam))
      {case IDOK:     EndDialog(hW,TRUE);return TRUE;}
    }
  }
 return FALSE;
}
#endif

void CALLBACK softGPUabout(void)  // ABOUT
{
#ifdef _WIN32
    HWND hWP = GetActiveWindow();  // to be sure
// DialogBox(hInst,MAKEINTRESOURCE(IDD_ABOUT),
//           hWP,(DLGPROC)AboutDlgProc);
#else
    AboutDlgProc();
#endif

    return;
}

////////////////////////////////////////////////////////////////////////
// We are ever fine ;)
////////////////////////////////////////////////////////////////////////

long CALLBACK softGPUtest(void) {
    // if test fails this function should return negative value for error (unable to continue)
    // and positive value for warning (can continue but output might be crappy)
    return 0;
}

////////////////////////////////////////////////////////////////////////
// Freeze
////////////////////////////////////////////////////////////////////////

typedef struct GPUFREEZETAG {
    uint32_t ulFreezeVersion;                // should be always 1 for now (set by main emu)
    uint32_t ulStatus;                       // current gpu status
    uint32_t ulControl[256];                 // latest control register values
    unsigned char psxVRam[1024 * 1024 * 2];  // current VRam image (full 2 MB for ZN)
} GPUFreeze_t;

////////////////////////////////////////////////////////////////////////

long CALLBACK softGPUfreeze(uint32_t ulGetFreezeData, GPUFreeze_t *pF) {
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
        memcpy(pF->ulControl, ulStatusControl, 256 * sizeof(uint32_t));
        memcpy(pF->psxVRam, psxVub, 1024 * iGPUHeight * 2);

        return 1;
    }

    if (ulGetFreezeData != 0) return 0;  // 0: set data

    lGPUstatusRet = pF->ulStatus;
    memcpy(ulStatusControl, pF->ulControl, 256 * sizeof(uint32_t));
    memcpy(psxVub, pF->psxVRam, 1024 * iGPUHeight * 2);

    // RESET TEXTURE STORE HERE, IF YOU USE SOMETHING LIKE THAT

    softGPUwriteStatus(ulStatusControl[0]);
    softGPUwriteStatus(ulStatusControl[1]);
    softGPUwriteStatus(ulStatusControl[2]);
    softGPUwriteStatus(ulStatusControl[3]);
    softGPUwriteStatus(ulStatusControl[8]);  // try to repair things
    softGPUwriteStatus(ulStatusControl[6]);
    softGPUwriteStatus(ulStatusControl[7]);
    softGPUwriteStatus(ulStatusControl[5]);
    softGPUwriteStatus(ulStatusControl[4]);

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

void CALLBACK softGPUgetScreenPic(unsigned char *pMem) {
    HRESULT ddrval;
    DDSURFACEDESC xddsd;
    unsigned char *pf;
    int x, y, c, v;
    RECT r;
    float XS, YS;

    memset(&xddsd, 0, sizeof(DDSURFACEDESC));
    xddsd.dwSize = sizeof(DDSURFACEDESC);
    xddsd.dwFlags = DDSD_WIDTH | DDSD_HEIGHT;
    xddsd.dwWidth = iResX;
    xddsd.dwHeight = iResY;

    r.left = 0;
    r.right = iResX;
    r.top = 0;
    r.bottom = iResY;

    if (iWindowMode) {
        POINT Point = {0, 0};
        ClientToScreen(DX.hWnd, &Point);
        r.left += Point.x;
        r.right += Point.x;
        r.top += Point.y;
        r.bottom += Point.y;
    }

    XS = (float)iResX / 128;
    YS = (float)iResY / 96;

    ddrval = IDirectDrawSurface_Lock(DX.DDSPrimary, NULL, &xddsd, DDLOCK_WAIT | DDLOCK_READONLY, NULL);

    if (ddrval == DDERR_SURFACELOST) IDirectDrawSurface_Restore(DX.DDSPrimary);

    pf = pMem;

    if (ddrval == DD_OK) {
        unsigned char *ps = (unsigned char *)xddsd.lpSurface;

        if (iDesktopCol == 16) {
            unsigned short sx;
            for (y = 0; y < 96; y++) {
                for (x = 0; x < 128; x++) {
                    sx = *((unsigned short *)((ps) + r.top * xddsd.lPitch + (((int)((float)y * YS)) * xddsd.lPitch) +
                                              r.left * 2 + ((int)((float)x * XS)) * 2));
                    *(pf + 0) = (sx & 0x1f) << 3;
                    *(pf + 1) = (sx & 0x7e0) >> 3;
                    *(pf + 2) = (sx & 0xf800) >> 8;
                    pf += 3;
                }
            }
        } else if (iDesktopCol == 15) {
            unsigned short sx;
            for (y = 0; y < 96; y++) {
                for (x = 0; x < 128; x++) {
                    sx = *((unsigned short *)((ps) + r.top * xddsd.lPitch + (((int)((float)y * YS)) * xddsd.lPitch) +
                                              r.left * 2 + ((int)((float)x * XS)) * 2));
                    *(pf + 0) = (sx & 0x1f) << 3;
                    *(pf + 1) = (sx & 0x3e0) >> 2;
                    *(pf + 2) = (sx & 0x7c00) >> 7;
                    pf += 3;
                }
            }
        } else {
            unsigned long sx;
            for (y = 0; y < 96; y++) {
                for (x = 0; x < 128; x++) {
                    sx = *((unsigned long *)((ps) + r.top * xddsd.lPitch + (((int)((float)y * YS)) * xddsd.lPitch) +
                                             r.left * 4 + ((int)((float)x * XS)) * 4));
                    *(pf + 0) = (unsigned char)((sx & 0xff));
                    *(pf + 1) = (unsigned char)((sx & 0xff00) >> 8);
                    *(pf + 2) = (unsigned char)((sx & 0xff0000) >> 16);
                    pf += 3;
                }
            }
        }
    }

    IDirectDrawSurface_Unlock(DX.DDSPrimary, &xddsd);

    /////////////////////////////////////////////////////////////////////
    // generic number/border painter

    pf = pMem + (103 * 3);  // offset to number rect

    for (y = 0; y < 20; y++)  // loop the number rect pixel
    {
        for (x = 0; x < 6; x++) {
            c = cFont[lSelectedSlot][x + y * 6];  // get 4 char dot infos at once (number depends on selected slot)
            v = (c & 0xc0) >> 6;
            PaintPicDot(pf, (unsigned char)v);
            pf += 3;  // paint the dots into the rect
            v = (c & 0x30) >> 4;
            PaintPicDot(pf, (unsigned char)v);
            pf += 3;
            v = (c & 0x0c) >> 2;
            PaintPicDot(pf, (unsigned char)v);
            pf += 3;
            v = c & 0x03;
            PaintPicDot(pf, (unsigned char)v);
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

#else

// LINUX version:

void GPUgetScreenPic(unsigned char *pMem) {
    unsigned char *pf = pMem;
    unsigned char *buf, *line, *pD;

    int w = PreviousPSXDisplay.Range.x1, h = PreviousPSXDisplay.DisplayMode.y;
    int x, y;
    float XS = w / 128.0, YS = h / 96.0;
    line = pf;
    for (y = 0; y < 96; ++y) {
        for (x = 0; x < 128; ++x) {
            float r = 0, g = 0, b = 0, sr, sg, sb;
            uint32_t cnt = 0, i, j;
            for (j = 0; j < (int)((y + 1) * YS) - (int)(y * YS); ++j) {
                for (i = 0; i < (int)((x + 1) * XS) - (int)(x * XS); ++i) {
                    pD = (unsigned char *)&psxVuw[(int)(y * YS + PSXDisplay.DisplayPosition.y - 1 + j) * 1024 +
                                                  PSXDisplay.DisplayPosition.x] +
                         (PSXDisplay.RGB24 ? 3 : 2) * (int)(x * XS + i);
                    if (PSXDisplay.RGB24) {
                        uint32_t lu = *(uint32_t *)pD;
                        sr = RED(lu);
                        sg = GREEN(lu);
                        sb = BLUE(lu);
                    } else {
                        int32_t color = GETLE16(pD);
                        sr = (color << 3) & 0xf1;
                        sg = (color >> 2) & 0xf1;
                        sb = (color >> 7) & 0xf1;
                    }
                    r += sr * sr;
                    g += sg * sg;
                    b += sb * sb;
                    cnt += 1;
                }
                line[x * 3 + 2] = sqrt(r / cnt);
                line[x * 3 + 1] = sqrt(g / cnt);
                line[x * 3 + 0] = sqrt(b / cnt);
            }
        }
        line += 128 * 3;
    }

    /////////////////////////////////////////////////////////////////////
    // generic number/border painter

    unsigned short c;
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

void CALLBACK softGPUshowScreenPic(unsigned char *pMem) {
    DestroyPic();           // destroy old pic data
    if (pMem == 0) return;  // done
    CreatePic(pMem);        // create new pic... don't free pMem or something like that... just read from it
}

void CALLBACK softGPUsetfix(uint32_t dwFixBits) { dwEmuFixes = dwFixBits; }

void CALLBACK softGPUvBlank(int val) {
    vBlank = val;
    oddLines = oddLines ? FALSE : TRUE;  // bit changes per frame when not interlaced
                                         // printf("VB %x (%x)\n", oddLines, vBlank);
}

void CALLBACK softGPUhSync(int val) {
    // Interlaced mode - update bit every scanline
    if (PSXDisplay.Interlaced) {
        oddLines = (val % 2 ? FALSE : TRUE);
    }
    // printf("HS %x (%x)\n", oddLines, vBlank);
}

void CALLBACK softGPUvisualVibration(uint32_t iSmall, uint32_t iBig) {
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

    iRumbleTime = 15;  // let the rumble last 16 buffer swaps
}
