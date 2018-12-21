/***************************************************************************
                       record.c  -  description
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
// 2003/04/17 - Avery Lee
// - repaired AVISetStreamFormat call
//
// 2001/12/18 - Darko Matesic
// - two types of compression (16bit & 24bit)
// - FPSE 24bit MDEC support
//
// 2001/11/09 - Darko Matesic
// - first revision
//
//*************************************************************************//

#include "record.h"
#include <direct.h>
#include <math.h>
#include <stdio.h>
//#include <vfw.h>
#include "externals.h"
#include "gpu.h"
#include "stdafx.h"

#if 0
                extern BOOL RECORD_RECORDING = FALSE;
BITMAPINFOHEADER RECORD_BI = {40, 0, 0, 1, 16, 0, 0, 2048, 2048, 0, 0};
unsigned char RECORD_BUFFER[1600 * 1200 * 3];
unsigned long RECORD_INDEX;
unsigned long RECORD_RECORDING_MODE;
unsigned long RECORD_VIDEO_SIZE;
unsigned long RECORD_RECORDING_WIDTH;
unsigned long RECORD_RECORDING_HEIGHT;
unsigned long RECORD_FRAME_RATE_SCALE;
unsigned long RECORD_COMPRESSION_MODE;
COMPVARS RECORD_COMPRESSION1;
unsigned char RECORD_COMPRESSION_STATE1[4096];
COMPVARS RECORD_COMPRESSION2;
unsigned char RECORD_COMPRESSION_STATE2[4096];

PCOMPVARS pCompression = NULL;
AVISTREAMINFO strhdr;
PAVIFILE pfile = NULL;
PAVISTREAM ps = NULL;
PAVISTREAM psCompressed = NULL;
AVICOMPRESSOPTIONS opts;

#endif  // 0

unsigned long frame;
unsigned long skip;

//--------------------------------------------------------------------

BOOL RECORD_Start() { return FALSE; }

//--------------------------------------------------------------------

void RECORD_Stop() { return FALSE; }

//--------------------------------------------------------------------

BOOL RECORD_WriteFrame() { return FALSE; }

//--------------------------------------------------------------------

BOOL RECORD_GetFrame() { return FALSE; }
