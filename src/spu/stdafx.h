/***************************************************************************
                           StdAfx.h  -  description
                             -------------------
    begin                : Wed May 15 2002
    copyright            : (C) 2002 by Pete Bernert
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
// 2002/05/15 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

//////////////////////////////////////////////////////////
// WINDOWS
//////////////////////////////////////////////////////////

#ifdef _WINDOWS

#define WIN32_LEAN_AND_MEAN
#define STRICT
#include <process.h>
#include <stdlib.h>
#include <windows.h>
#include <windowsx.h>
#include "mmsystem.h"

// enable that for auxprintf();
//#define SMALLDEBUG
//#include <dbgout.h>
// void auxprintf (LPCTSTR pFormat, ...);

#define INLINE __inline

//////////////////////////////////////////////////////////
// LINUX
//////////////////////////////////////////////////////////
#else

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/soundcard.h>
#include <unistd.h>
#ifndef NOTHREADLIB
#include <pthread.h>
#endif
#define RRand(range) (random() % range)
#include <math.h>
#include <string.h>
#include <sys/time.h>

#undef CALLBACK
#define CALLBACK
#define DWORD unsigned long
#define LOWORD(l) ((unsigned short)(l))
#define HIWORD(l) ((unsigned short)(((unsigned long)(l) >> 16) & 0xFFFF))

#define INLINE inline

#endif

#include "psemuxa.h"
