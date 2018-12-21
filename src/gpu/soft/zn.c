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
long CALLBACK GPUopen(HWND hwndGPU);
#else
long GPUopen(unsigned long* disp, const char* CapText, const char* CfgFile);
#endif
void CALLBACK GPUdisplayText(char* pText);
void CALLBACK GPUdisplayFlags(unsigned long dwFlags);
void CALLBACK GPUmakeSnapshot(void);
long CALLBACK GPUinit();
long CALLBACK GPUclose();
long CALLBACK GPUshutdown();
void CALLBACK GPUcursor(int iPlayer, int x, int y);
void CALLBACK GPUupdateLace(void);
unsigned long CALLBACK GPUreadStatus(void);
void CALLBACK GPUwriteStatus(unsigned long gdata);
void CALLBACK GPUreadDataMem(unsigned long* pMem, int iSize);
unsigned long CALLBACK GPUreadData(void);
void CALLBACK GPUwriteDataMem(unsigned long* pMem, int iSize);
void CALLBACK GPUwriteData(unsigned long gdata);
void CALLBACK GPUsetMode(unsigned long gdata);
long CALLBACK GPUgetMode(void);
long CALLBACK GPUdmaChain(unsigned long* baseAddrL, unsigned long addr);
long CALLBACK GPUconfigure(void);
void CALLBACK GPUabout(void);
long CALLBACK GPUtest(void);
long CALLBACK GPUfreeze(unsigned long ulGetFreezeData, void* pF);
void CALLBACK GPUgetScreenPic(unsigned char* pMem);
void CALLBACK GPUshowScreenPic(unsigned char* pMem);
#ifndef _WIN32
void CALLBACK GPUkeypressed(int keycode);
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

void CALLBACK ZN_GPUdisplayFlags(unsigned long dwFlags)
{
 GPUdisplayFlags(dwFlags);
}

// --------------------------------------------------- //

void CALLBACK ZN_GPUmakeSnapshot(void)
{
 GPUmakeSnapshot();
}

// --------------------------------------------------- //

long CALLBACK ZN_GPUinit()
{                                                      // we always set the vram size to 2MB, if the ZN interface is used
 iGPUHeight=1024;
 iGPUHeightMask=1023;

 return GPUinit();
}

// --------------------------------------------------- //

extern char * pConfigFile;

long CALLBACK ZN_GPUopen(void * vcfg)
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

long CALLBACK ZN_GPUclose()
{
 return GPUclose();
}

// --------------------------------------------------- //

long CALLBACK ZN_GPUshutdown()
{
 return GPUshutdown();
}

// --------------------------------------------------- //

void CALLBACK ZN_GPUupdateLace(void)
{
 GPUupdateLace();
}

// --------------------------------------------------- //

unsigned long CALLBACK ZN_GPUreadStatus(void)
{
 return GPUreadStatus();
}

// --------------------------------------------------- //

void CALLBACK ZN_GPUwriteStatus(unsigned long gdata)
{
 GPUwriteStatus(gdata);
}

// --------------------------------------------------- //

long CALLBACK ZN_GPUdmaSliceOut(unsigned long *baseAddrL, unsigned long addr, unsigned long iSize)
{
 GPUreadDataMem(baseAddrL+addr,iSize);
 return 0;
}

// --------------------------------------------------- //

unsigned long CALLBACK ZN_GPUreadData(void)
{
 return GPUreadData();
}

// --------------------------------------------------- //

void CALLBACK ZN_GPUsetMode(unsigned long gdata)
{
 GPUsetMode(gdata);
}

// --------------------------------------------------- //

long CALLBACK ZN_GPUgetMode(void)
{
 return GPUgetMode();
}

// --------------------------------------------------- //

long CALLBACK ZN_GPUdmaSliceIn(unsigned long *baseAddrL, unsigned long addr, unsigned long iSize)
{
 GPUwriteDataMem(baseAddrL+addr,iSize);
 return 0;
}
// --------------------------------------------------- //

void CALLBACK ZN_GPUwriteData(unsigned long gdata)
{
 GPUwriteDataMem(&gdata,1);
}

// --------------------------------------------------- //

long CALLBACK ZN_GPUdmaChain(unsigned long * baseAddrL, unsigned long addr)
{
 return GPUdmaChain(baseAddrL,addr);
}

// --------------------------------------------------- //

long CALLBACK ZN_GPUtest(void)
{
 return GPUtest();
}

// --------------------------------------------------- //

long CALLBACK ZN_GPUfreeze(unsigned long ulGetFreezeData,void * pF)
{
 return GPUfreeze(ulGetFreezeData,pF);
}

// --------------------------------------------------- //

void CALLBACK ZN_GPUgetScreenPic(unsigned char * pMem)
{
 GPUgetScreenPic(pMem);
}

// --------------------------------------------------- //

void CALLBACK ZN_GPUshowScreenPic(unsigned char * pMem)
{
 GPUshowScreenPic(pMem);
}

// --------------------------------------------------- //

#ifndef _WIN32

void CALLBACK ZN_GPUkeypressed(int keycode)
{
 GPUkeypressed(keycode);
}

#endif
#endif
