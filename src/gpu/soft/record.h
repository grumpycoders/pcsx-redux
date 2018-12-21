/***************************************************************************
                       record.h  -  description
                             -------------------
    begin                : Fri Nov 09 2001
    copyright            : (C) 2001 by Darko Matesic
    email                : thedarkma@ptt.yu
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
// 2001/12/18 - Darko Matesic
// - two types of compression (16bit & 24bit)
// - FPSE 24bit MDEC support
//
// 2001/11/09 - Darko Matesic
// - first revision
//
//*************************************************************************//

#ifndef _RECORD_H_
#define _RECORD_H_

//#include <vfw.h>
#include "stdafx.h"

#if 0
                extern BOOL RECORD_RECORDING;
extern BITMAPINFOHEADER RECORD_BI;
extern unsigned char RECORD_BUFFER[1600 * 1200 * 3];
extern unsigned long RECORD_INDEX;
extern unsigned long RECORD_RECORDING_MODE;
extern unsigned long RECORD_VIDEO_SIZE;
extern unsigned long RECORD_RECORDING_WIDTH;
extern unsigned long RECORD_RECORDING_HEIGHT;
extern unsigned long RECORD_FRAME_RATE_SCALE;
extern unsigned long RECORD_COMPRESSION_MODE;
extern COMPVARS RECORD_COMPRESSION1;
extern unsigned char RECORD_COMPRESSION_STATE1[4096];
extern COMPVARS RECORD_COMPRESSION2;
extern unsigned char RECORD_COMPRESSION_STATE2[4096];

#endif  // 0

BOOL RECORD_Start();
void RECORD_Stop();
BOOL RECORD_WriteFrame();
BOOL RECORD_GetFrame();

#endif
