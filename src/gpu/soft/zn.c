/***************************************************************************
                          zn.c  -  description
                             -------------------
    begin                : Sat Jan 31 2004
    copyright            : (C) 2004 by Pete Bernert
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
// 2004/01/31 - Pete
// - added zn interface
//
//*************************************************************************//

#include "stdafx.h"

#define _IN_ZN

#include "externals.h"

// --------------------------------------------------- //
// - psx gpu plugin interface prototypes-------------- //
// --------------------------------------------------- //

#ifdef _WIN32
long GPUopen(HWND hwndGPU);
#else
long GPUopen(unsigned long* disp, const char* CapText, const char* CfgFile);
#endif
void GPUdisplayText(char* pText);
void GPUdisplayFlags(unsigned long dwFlags);
void GPUmakeSnapshot(void);
long GPUinit();
long GPUclose();
long GPUshutdown();
void GPUcursor(int iPlayer, int x, int y);
void GPUupdateLace(void);
unsigned long GPUreadStatus(void);
void GPUwriteStatus(unsigned long gdata);
void GPUreadDataMem(unsigned long* pMem, int iSize);
unsigned long GPUreadData(void);
void GPUwriteDataMem(unsigned long* pMem, int iSize);
void GPUwriteData(unsigned long gdata);
void GPUsetMode(unsigned long gdata);
long GPUgetMode(void);
long GPUdmaChain(unsigned long* baseAddrL, unsigned long addr);
long GPUconfigure(void);
void GPUabout(void);
long GPUtest(void);
long GPUfreeze(unsigned long ulGetFreezeData, void* pF);
void GPUgetScreenPic(unsigned char* pMem);
void GPUshowScreenPic(unsigned char* pMem);
#ifndef _WIN32
void GPUkeypressed(int keycode);
#endif

// --------------------------------------------------- //
// - zn gpu interface -------------------------------- //
// --------------------------------------------------- //

unsigned long dwGPUVersion = 0;
int iGPUHeight = 512;
int iGPUHeightMask = 511;
int GlobalTextIL = 0;
int iTileCheat = 0;

// --------------------------------------------------- //
// --------------------------------------------------- //
// --------------------------------------------------- //

typedef struct GPUOTAG {
    unsigned long Version;         // Version of structure - currently 1
    long hWnd;                     // Window handle
    unsigned long ScreenRotation;  // 0 = 0CW, 1 = 90CW, 2 = 180CW, 3 = 270CW = 90CCW
    unsigned long GPUVersion;      // 0 = a, 1 = b, 2 = c
    const char* GameName;          // NULL terminated string
    const char* CfgFile;           // NULL terminated string
} GPUConfiguration_t;

// --------------------------------------------------- //
// --------------------------------------------------- //
// --------------------------------------------------- //

#if 0

void ZN_GPUdisplayFlags(unsigned long dwFlags)
{
 GPUdisplayFlags(dwFlags);
}

// --------------------------------------------------- //

void ZN_GPUmakeSnapshot(void)
{
 GPUmakeSnapshot();
}

// --------------------------------------------------- //

long ZN_GPUinit()
{                                                      // we always set the vram size to 2MB, if the ZN interface is used
 iGPUHeight=1024;
 iGPUHeightMask=1023;

 return GPUinit();
}

// --------------------------------------------------- //

extern char * pConfigFile;

long ZN_GPUopen(void * vcfg)
{
 GPUConfiguration_t * cfg=(GPUConfiguration_t *)vcfg;
 long lret;

 if(!cfg)            return -1;
 if(cfg->Version!=1) return -1;

#ifdef _WIN32
 pConfigFile=(char *)cfg->CfgFile;                     // only used in this open, so we can store this temp pointer here without danger... don't access it later, though!
 lret=GPUopen((HWND)cfg->hWnd);
#else
 lret=GPUopen(&cfg->hWnd,cfg->GameName,cfg->CfgFile);
#endif

/*
 if(!lstrcmp(cfg->GameName,"kikaioh")     ||
    !lstrcmp(cfg->GameName,"sr2j")        ||
    !lstrcmp(cfg->GameName,"rvschool_a"))
  iTileCheat=1;
*/

 // some ZN games seem to erase the cluts with a 'white' TileS... strange..
 // I've added a cheat to avoid this issue. We can set it globally (for
 // all ZiNc games) without much risk

 iTileCheat=1;

 dwGPUVersion=cfg->GPUVersion;

 return lret;
}

// --------------------------------------------------- //

long ZN_GPUclose()
{
 return GPUclose();
}

// --------------------------------------------------- //

long ZN_GPUshutdown()
{
 return GPUshutdown();
}

// --------------------------------------------------- //

void ZN_GPUupdateLace(void)
{
 GPUupdateLace();
}

// --------------------------------------------------- //

unsigned long ZN_GPUreadStatus(void)
{
 return GPUreadStatus();
}

// --------------------------------------------------- //

void ZN_GPUwriteStatus(unsigned long gdata)
{
 GPUwriteStatus(gdata);
}

// --------------------------------------------------- //

long ZN_GPUdmaSliceOut(unsigned long *baseAddrL, unsigned long addr, unsigned long iSize)
{
 GPUreadDataMem(baseAddrL+addr,iSize);
 return 0;
}

// --------------------------------------------------- //

unsigned long ZN_GPUreadData(void)
{
 return GPUreadData();
}

// --------------------------------------------------- //

void ZN_GPUsetMode(unsigned long gdata)
{
 GPUsetMode(gdata);
}

// --------------------------------------------------- //

long ZN_GPUgetMode(void)
{
 return GPUgetMode();
}

// --------------------------------------------------- //

long ZN_GPUdmaSliceIn(unsigned long *baseAddrL, unsigned long addr, unsigned long iSize)
{
 GPUwriteDataMem(baseAddrL+addr,iSize);
 return 0;
}
// --------------------------------------------------- //

void ZN_GPUwriteData(unsigned long gdata)
{
 GPUwriteDataMem(&gdata,1);
}

// --------------------------------------------------- //

long ZN_GPUdmaChain(unsigned long * baseAddrL, unsigned long addr)
{
 return GPUdmaChain(baseAddrL,addr);
}

// --------------------------------------------------- //

long ZN_GPUtest(void)
{
 return GPUtest();
}

// --------------------------------------------------- //

long ZN_GPUfreeze(unsigned long ulGetFreezeData,void * pF)
{
 return GPUfreeze(ulGetFreezeData,pF);
}

// --------------------------------------------------- //

void ZN_GPUgetScreenPic(unsigned char * pMem)
{
 GPUgetScreenPic(pMem);
}

// --------------------------------------------------- //

void ZN_GPUshowScreenPic(unsigned char * pMem)
{
 GPUshowScreenPic(pMem);
}

// --------------------------------------------------- //

#ifndef _WIN32

void ZN_GPUkeypressed(int keycode)
{
 GPUkeypressed(keycode);
}

#endif
#endif
