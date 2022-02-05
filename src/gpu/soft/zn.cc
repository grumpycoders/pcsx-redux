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

#include <cstdint>

#include "gpu/soft/externals.h"

uint32_t dwGPUVersion = 0;
int iGPUHeight = 512;
int iGPUHeightMask = 511;
int GlobalTextIL = 0;
int iTileCheat = 0;

typedef struct GPUOTAG {
    uint32_t Version;         // Version of structure - currently 1
    int32_t hWnd;             // Window handle
    uint32_t ScreenRotation;  // 0 = 0CW, 1 = 90CW, 2 = 180CW, 3 = 270CW = 90CCW
    uint32_t GPUVersion;      // 0 = a, 1 = b, 2 = c
    const char* GameName;     // NULL terminated string
    const char* CfgFile;      // NULL terminated string
} GPUConfiguration_t;
