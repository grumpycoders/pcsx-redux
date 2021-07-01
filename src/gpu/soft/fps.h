/***************************************************************************
                          fps.h -  description
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

#ifndef _FPS_INTERNALS_H
#define _FPS_INTERNALS_H

void FrameCap(void);
void FrameCapSSSPSX(void);
void FrameSkip(void);
void calcfps(void);
void PCFrameCap(void);
void PCcalcfps(void);
void SetAutoFrameCap(void);
void SetFPSHandler(void);
void InitFPS(void);
void CheckFrameRate(void);

static bool s_useFrameLimit = false;
static bool s_useFrameSkip = false;
static bool s_SSSPSXLimit = true;

#endif  // _FPS_INTERNALS_H
