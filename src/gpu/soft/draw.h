/***************************************************************************
                          draw.h  -  description
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
// 2001/10/28 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#ifndef _GPU_DRAW_H_
#define _GPU_DRAW_H_

void DoBufferSwap(void);
void DoClearScreenBuffer(void);
void DoClearFrontBuffer(void);
unsigned long ulInitDisplay(void);
void CloseDisplay(void);
void CreatePic(unsigned char* pMem);
void DestroyPic(void);
void DisplayPic(void);
void ShowGpuPic(void);
void ShowTextGpuPic(void);

#ifdef _WIN32
//void MoveScanLineArea(HWND hwnd);
#endif

///////////////////////////////////////////////////////////////////////

#endif  // _GPU_DRAW_H_
