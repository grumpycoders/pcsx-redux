/***************************************************************************
                            zn.c  -  description
                            --------------------
    begin                : Wed April 23 2004
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
// 2004/04/23 - Pete
// - added ZINC zn interface
//
//*************************************************************************//

#include "stdafx.h"
#include "xa.h"

//*************************************************************************//
// global marker, if ZINC is running

int iZincEmu = 0;

//-------------------------------------------------------------------------//
// not used by ZINC

void SPUasync(unsigned long cycle);

void ZN_SPUupdate(void) { SPUasync(0); }

//-------------------------------------------------------------------------//

void SPUwriteRegister(unsigned long reg, unsigned short val);

void ZN_SPUwriteRegister(unsigned long reg, unsigned short val) { SPUwriteRegister(reg, val); }

//-------------------------------------------------------------------------//

unsigned short SPUreadRegister(unsigned long reg);

unsigned short ZN_SPUreadRegister(unsigned long reg) { return SPUreadRegister(reg); }

//-------------------------------------------------------------------------//
// not used by ZINC

unsigned short SPUreadDMA(void);

unsigned short ZN_SPUreadDMA(void) { return SPUreadDMA(); }

//-------------------------------------------------------------------------//
// not used by ZINC

void SPUwriteDMA(unsigned short val);

void ZN_SPUwriteDMA(unsigned short val) { SPUwriteDMA(val); }

//-------------------------------------------------------------------------//
// not used by ZINC

void SPUwriteDMAMem(unsigned short *pusPSXMem, int iSize);

void ZN_SPUwriteDMAMem(unsigned short *pusPSXMem, int iSize) { SPUwriteDMAMem(pusPSXMem, iSize); }

//-------------------------------------------------------------------------//
// not used by ZINC

void SPUreadDMAMem(unsigned short *pusPSXMem, int iSize);

void ZN_SPUreadDMAMem(unsigned short *pusPSXMem, int iSize) { SPUreadDMAMem(pusPSXMem, iSize); }

//-------------------------------------------------------------------------//
// not used by ZINC

void SPUplayADPCMchannel(xa_decode_t *xap);

void ZN_SPUplayADPCMchannel(xa_decode_t *xap) { SPUplayADPCMchannel(xap); }

//-------------------------------------------------------------------------//
// attention: no separate SPUInit/Shutdown funcs in ZN interface

long SPUinit(void);

#ifdef _WIN32

long SPUopen(HWND hW);

long ZN_SPUopen(HWND hW) {
    iZincEmu = 1;
    SPUinit();
    return SPUopen(hW);
}

#else

long SPUopen(void);

long ZN_SPUopen(void) {
    iZincEmu = 1;
    SPUinit();
    return SPUopen();
}

#endif

//-------------------------------------------------------------------------//

long SPUshutdown(void);
long SPUclose(void);

long ZN_SPUclose(void) {
    long lret = SPUclose();
    SPUshutdown();
    return lret;
}

//-------------------------------------------------------------------------//
// not used by ZINC

void SPUregisterCallback(void(*callback)(void));

void ZN_SPUregisterCallback(void(*callback)(void)) { SPUregisterCallback(callback); }

//-------------------------------------------------------------------------//
// not used by ZINC

long SPUfreeze(unsigned long ulFreezeMode, void *pF);

long ZN_SPUfreeze(unsigned long ulFreezeMode, void *pF) { return SPUfreeze(ulFreezeMode, pF); }

//-------------------------------------------------------------------------//

extern void(*irqQSound)(unsigned char *, long *, long);

void ZN_SPUqsound(void(*callback)(unsigned char *, long *, long)) { irqQSound = callback; }

//-------------------------------------------------------------------------//
