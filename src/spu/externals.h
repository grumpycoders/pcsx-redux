/***************************************************************************
                         externals.h  -  description
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
// 2002/04/04 - Pete
// - increased channel struct for interpolation
//
// 2002/05/15 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#pragma once

#include "core/decode_xa.h"
#include "spu/interface.h"

/////////////////////////////////////////////////////////
// generic defines
/////////////////////////////////////////////////////////

#define PSE_LT_SPU 4
#define PSE_SPU_ERR_SUCCESS 0
#define PSE_SPU_ERR -60
#define PSE_SPU_ERR_NOTCONFIGURED PSE_SPU_ERR - 1
#define PSE_SPU_ERR_INIT PSE_SPU_ERR - 2
#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

////////////////////////////////////////////////////////////////////////
// spu defines
////////////////////////////////////////////////////////////////////////

// sound buffer sizes
// 400 ms complete sound buffer
#define SOUNDSIZE 70560
// 137 ms test buffer... if less than that is buffered, a new upload will happen
#define TESTSIZE 24192

// num of channels
#define MAXCHAN 24

// ~ 1 ms of data
#define NSSIZE 45

///////////////////////////////////////////////////////////
// struct defines
///////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////

// Tmp Flags

// used for debug channel muting
#define FLAG_MUTE 1

// used for simple interpolation
#define FLAG_IPOL0 2
#define FLAG_IPOL1 4

///////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////

typedef struct {
    int StartAddr;  // reverb area start addr in samples
    int CurrAddr;   // reverb area curr addr in samples

    int VolLeft;
    int VolRight;
    int iLastRVBLeft;
    int iLastRVBRight;
    int iRVBLeft;
    int iRVBRight;

    int FB_SRC_A;     // (offset)
    int FB_SRC_B;     // (offset)
    int IIR_ALPHA;    // (coef.)
    int ACC_COEF_A;   // (coef.)
    int ACC_COEF_B;   // (coef.)
    int ACC_COEF_C;   // (coef.)
    int ACC_COEF_D;   // (coef.)
    int IIR_COEF;     // (coef.)
    int FB_ALPHA;     // (coef.)
    int FB_X;         // (coef.)
    int IIR_DEST_A0;  // (offset)
    int IIR_DEST_A1;  // (offset)
    int ACC_SRC_A0;   // (offset)
    int ACC_SRC_A1;   // (offset)
    int ACC_SRC_B0;   // (offset)
    int ACC_SRC_B1;   // (offset)
    int IIR_SRC_A0;   // (offset)
    int IIR_SRC_A1;   // (offset)
    int IIR_DEST_B0;  // (offset)
    int IIR_DEST_B1;  // (offset)
    int ACC_SRC_C0;   // (offset)
    int ACC_SRC_C1;   // (offset)
    int ACC_SRC_D0;   // (offset)
    int ACC_SRC_D1;   // (offset)
    int IIR_SRC_B1;   // (offset)
    int IIR_SRC_B0;   // (offset)
    int MIX_DEST_A0;  // (offset)
    int MIX_DEST_A1;  // (offset)
    int MIX_DEST_B0;  // (offset)
    int MIX_DEST_B1;  // (offset)
    int IN_COEF_L;    // (coef.)
    int IN_COEF_R;    // (coef.)
} REVERBInfo;

#ifdef _WIN32
#define WM_MUTE (WM_USER + 543)
#endif

///////////////////////////////////////////////////////////
// SPU.C globals
///////////////////////////////////////////////////////////
// MISC

extern PCSX::SPU::SPUCHAN s_chan[];
extern REVERBInfo rvb;

extern unsigned long dwNoiseVal;
extern unsigned short spuCtrl;
extern unsigned short spuStat;
extern unsigned short spuIrq;
extern unsigned long spuAddr;
extern int bEndThread;
extern int bThreadEnded;
extern int bSpuInit;
extern unsigned long dwNewChannel;

extern int SSumR[];
extern int SSumL[];
extern int iCycle;
extern short *pS;

extern int iSpuAsyncWait;

extern void(*cddavCallback)(unsigned short, unsigned short);

///////////////////////////////////////////////////////////
// XA.C globals
///////////////////////////////////////////////////////////

extern xa_decode_t *xapGlobal;

extern unsigned long *XAFeed;
extern unsigned long *XAPlay;
extern unsigned long *XAStart;
extern unsigned long *XAEnd;

extern unsigned long XARepeat;
extern unsigned long XALastVal;

extern int iLeftXAVol;
extern int iRightXAVol;

///////////////////////////////////////////////////////////
// REVERB.C globals
///////////////////////////////////////////////////////////

extern int *sRVBPlay;
extern int *sRVBEnd;
extern int *sRVBStart;
extern int iReverbOff;
extern int iReverbRepeat;
extern int iReverbNum;
