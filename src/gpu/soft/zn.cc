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

#define _IN_ZN

#include "gpu/soft/externals.h"

// --------------------------------------------------- //
// - psx gpu plugin interface prototypes-------------- //
// --------------------------------------------------- //

// long GPUopen(HWND hwndGPU);
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
