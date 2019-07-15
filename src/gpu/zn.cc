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

#include <stdint.h>

#include "gpu/externals.h"

// --------------------------------------------------- //
// - psx gpu plugin interface prototypes-------------- //
// --------------------------------------------------- //

// int32_t GPUopen(HWND hwndGPU);
void GPUdisplayText(char* pText);
void GPUdisplayFlags(uint32_t dwFlags);
void GPUmakeSnapshot(void);
int32_t GPUinit();
int32_t GPUclose();
int32_t GPUshutdown();
void GPUcursor(int iPlayer, int x, int y);
void GPUupdateLace(void);
uint32_t GPUreadStatus(void);
void GPUwriteStatus(uint32_t gdata);
void GPUreadDataMem(uint32_t* pMem, int iSize);
uint32_t GPUreadData(void);
void GPUwriteDataMem(uint32_t* pMem, int iSize);
void GPUwriteData(uint32_t gdata);
void GPUsetMode(uint32_t gdata);
int32_t GPUgetMode(void);
int32_t GPUdmaChain(uint32_t* baseAddrL, uint32_t addr);
int32_t GPUconfigure(void);
void GPUabout(void);
int32_t GPUtest(void);
int32_t GPUfreeze(uint32_t ulGetFreezeData, void* pF);
void GPUgetScreenPic(unsigned char* pMem);
void GPUshowScreenPic(unsigned char* pMem);
#ifndef _WIN32
void GPUkeypressed(int keycode);
#endif

// --------------------------------------------------- //
// - zn gpu interface -------------------------------- //
// --------------------------------------------------- //

int iGPUHeightMask = 511;
int GlobalTextIL = 0;
int iTileCheat = 0;

// --------------------------------------------------- //
// --------------------------------------------------- //
// --------------------------------------------------- //

typedef struct GPUOTAG {
    uint32_t Version;         // Version of structure - currently 1
    int32_t hWnd;                     // Window handle
    uint32_t ScreenRotation;  // 0 = 0CW, 1 = 90CW, 2 = 180CW, 3 = 270CW = 90CCW
    const char* GameName;          // NULL terminated string
    const char* CfgFile;           // NULL terminated string
} GPUConfiguration_t;
