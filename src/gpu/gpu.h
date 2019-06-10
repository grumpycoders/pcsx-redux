/***************************************************************************
                          gpu.h  -  description
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

#ifndef _GPU_INTERNALS_H
#define _GPU_INTERNALS_H

/////////////////////////////////////////////////////////////////////////////

#define OPAQUEON 10
#define OPAQUEOFF 11

#define KEY_RESETTEXSTORE 1
#define KEY_SHOWFPS 2
#define KEY_RESETOPAQUE 4
#define KEY_RESETDITHER 8
#define KEY_RESETFILTER 16
#define KEY_RESETADVBLEND 32
//#define KEY_BLACKWHITE    64
#define KEY_BADTEXTURES 128
#define KEY_CHECKTHISOUT 256

#ifndef _FPSE
#define RED(x) (x & 0xff)
#define BLUE(x) ((x >> 16) & 0xff)
#define GREEN(x) ((x >> 8) & 0xff)
#define COLOR(x) (x & 0xffffff)
#else
#define BLUE(x) (x & 0xff)
#define RED(x) ((x >> 16) & 0xff)
#define GREEN(x) ((x >> 8) & 0xff)
#define COLOR(x) (x & 0xffffff)
#endif

/////////////////////////////////////////////////////////////////////////////

void updateDisplay(void);
void SetAutoFrameCap(void);
void SetFixes(void);

/////////////////////////////////////////////////////////////////////////////

#endif  // _GPU_INTERNALS_H
