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

void CALLBACK SPUasync(unsigned long cycle);

void CALLBACK ZN_SPUupdate(void) { SPUasync(0); }

//-------------------------------------------------------------------------//

void CALLBACK SPUwriteRegister(unsigned long reg, unsigned short val);

void CALLBACK ZN_SPUwriteRegister(unsigned long reg, unsigned short val) { SPUwriteRegister(reg, val); }

//-------------------------------------------------------------------------//

unsigned short CALLBACK SPUreadRegister(unsigned long reg);

unsigned short CALLBACK ZN_SPUreadRegister(unsigned long reg) { return SPUreadRegister(reg); }

//-------------------------------------------------------------------------//
// not used by ZINC

unsigned short CALLBACK SPUreadDMA(void);

unsigned short CALLBACK ZN_SPUreadDMA(void) { return SPUreadDMA(); }

//-------------------------------------------------------------------------//
// not used by ZINC

void CALLBACK SPUwriteDMA(unsigned short val);

void CALLBACK ZN_SPUwriteDMA(unsigned short val) { SPUwriteDMA(val); }

//-------------------------------------------------------------------------//
// not used by ZINC

void CALLBACK SPUwriteDMAMem(unsigned short *pusPSXMem, int iSize);

void CALLBACK ZN_SPUwriteDMAMem(unsigned short *pusPSXMem, int iSize) { SPUwriteDMAMem(pusPSXMem, iSize); }

//-------------------------------------------------------------------------//
// not used by ZINC

void CALLBACK SPUreadDMAMem(unsigned short *pusPSXMem, int iSize);

void CALLBACK ZN_SPUreadDMAMem(unsigned short *pusPSXMem, int iSize) { SPUreadDMAMem(pusPSXMem, iSize); }

//-------------------------------------------------------------------------//
// not used by ZINC

void CALLBACK SPUplayADPCMchannel(xa_decode_t *xap);

void CALLBACK ZN_SPUplayADPCMchannel(xa_decode_t *xap) { SPUplayADPCMchannel(xap); }

//-------------------------------------------------------------------------//
// attention: no separate SPUInit/Shutdown funcs in ZN interface

long CALLBACK SPUinit(void);

#ifdef _WIN32

long CALLBACK SPUopen(HWND hW);

long CALLBACK ZN_SPUopen(HWND hW) {
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

long CALLBACK SPUshutdown(void);
long CALLBACK SPUclose(void);

long CALLBACK ZN_SPUclose(void) {
    long lret = SPUclose();
    SPUshutdown();
    return lret;
}

//-------------------------------------------------------------------------//
// not used by ZINC

void CALLBACK SPUregisterCallback(void(CALLBACK *callback)(void));

void CALLBACK ZN_SPUregisterCallback(void(CALLBACK *callback)(void)) { SPUregisterCallback(callback); }

//-------------------------------------------------------------------------//
// not used by ZINC

long CALLBACK SPUfreeze(unsigned long ulFreezeMode, void *pF);

long CALLBACK ZN_SPUfreeze(unsigned long ulFreezeMode, void *pF) { return SPUfreeze(ulFreezeMode, pF); }

//-------------------------------------------------------------------------//

extern void(CALLBACK *irqQSound)(unsigned char *, long *, long);

void CALLBACK ZN_SPUqsound(void(CALLBACK *callback)(unsigned char *, long *, long)) { irqQSound = callback; }

//-------------------------------------------------------------------------//
