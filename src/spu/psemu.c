/***************************************************************************
                          psemu.c  -  description
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

#include "stdafx.h"

#define _IN_PSEMU

#include "dma.h"
#include "externals.h"
#include "regs.h"

////////////////////////////////////////////////////////////////////////
// OLD, SOMEWHAT (BUT NOT MUCH) SUPPORTED PSEMUPRO FUNCS
////////////////////////////////////////////////////////////////////////

unsigned short SPUgetOne(unsigned long val) {
    if (spuAddr != 0xffffffff) {
        return SPUreadDMA();
    }
    if (val >= 512 * 1024) val = 512 * 1024 - 1;
    return spuMem[val >> 1];
}

void SPUputOne(unsigned long val, unsigned short data) {
    if (spuAddr != 0xffffffff) {
        SPUwriteDMA(data);
        return;
    }
    if (val >= 512 * 1024) val = 512 * 1024 - 1;
    spuMem[val >> 1] = data;
}

void SPUplaySample(unsigned char ch) {}

void SPUsetAddr(unsigned char ch, unsigned short waddr) {
    s_chan[ch].pStart = spuMemC + ((unsigned long)waddr << 3);
}

void SPUsetPitch(unsigned char ch, unsigned short pitch) { SetPitch(ch, pitch); }

void SPUsetVolumeL(unsigned char ch, short vol) { SetVolumeR(ch, vol); }

void SPUsetVolumeR(unsigned char ch, short vol) { SetVolumeL(ch, vol); }

void SPUstartChannels1(unsigned short channels) { SoundOn(0, 16, channels); }

void SPUstartChannels2(unsigned short channels) { SoundOn(16, 24, channels); }

void SPUstopChannels1(unsigned short channels) { SoundOff(0, 16, channels); }

void SPUstopChannels2(unsigned short channels) { SoundOff(16, 24, channels); }

void SPUplaySector(unsigned long mode, unsigned char* p) {
    if (!iUseXA) return;  // no XA? bye
}
