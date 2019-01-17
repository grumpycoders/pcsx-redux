/***************************************************************************
                        stdafx.h  -  description
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

#ifdef _WIN32

#ifndef STRICT
#define STRICT
#endif
#define D3D_OVERLOADS
#define DIRECT3D_VERSION 0x600
#define CINTERFACE

#include <TCHAR.H>
#include <WINDOWS.H>
#include <WINDOWSX.H>
#include "resource.h"

// stupid intel compiler warning on extern __inline funcs
#pragma warning(disable : 864)
// disable stupid MSVC2005 warnings as well...
#pragma warning(disable : 4996)
#pragma warning(disable : 4244)

// enable that for auxprintf();
//#define SMALLDEBUG
//#include <dbgout.h>
// void auxprintf (LPCTSTR pFormat, ...);

#else

#ifndef _SDL
#define __X11_C_
// X11 render
#define __inline inline
#define CALLBACK

#include <GL/gl.h>
#include <GL/glx.h>
#include <X11/cursorfont.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#else  // SDL render

#define __inline inline
#define CALLBACK

#include <SDL/SDL.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#endif

#endif
