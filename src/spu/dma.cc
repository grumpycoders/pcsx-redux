/***************************************************************************
                            dma.c  -  description
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

#include "spu/externals.h"
#include "spu/interface.h"

////////////////////////////////////////////////////////////////////////
// READ DMA (one value)
////////////////////////////////////////////////////////////////////////

unsigned short PCSX::SPU::impl::readDMA(void) {
    unsigned short s;

    s = spuMem[spuAddr >> 1];

    spuAddr += 2;
    if (spuAddr > 0x7ffff) spuAddr = 0;

    iSpuAsyncWait = 0;

    return s;
}

////////////////////////////////////////////////////////////////////////
// READ DMA (many values)
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::readDMAMem(unsigned short* pusPSXMem, int iSize) {
    int i;

    for (i = 0; i < iSize; i++) {
        *pusPSXMem++ = spuMem[spuAddr >> 1];  // spu addr got by writeregister
        spuAddr += 2;                         // inc spu addr
        if (spuAddr > 0x7ffff) spuAddr = 0;   // wrap
    }

    iSpuAsyncWait = 0;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

// to investigate: do sound data updates by writedma affect spu
// irqs? Will an irq be triggered, if new data is written to
// the memory irq address?

////////////////////////////////////////////////////////////////////////
// WRITE DMA (one value)
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::writeDMA(unsigned short val) {
    spuMem[spuAddr >> 1] = val;  // spu addr got by writeregister

    spuAddr += 2;                        // inc spu addr
    if (spuAddr > 0x7ffff) spuAddr = 0;  // wrap

    iSpuAsyncWait = 0;
}

////////////////////////////////////////////////////////////////////////
// WRITE DMA (many values)
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::writeDMAMem(unsigned short* pusPSXMem, int iSize) {
    int i;

    for (i = 0; i < iSize; i++) {
        spuMem[spuAddr >> 1] = *pusPSXMem++;  // spu addr got by writeregister
        spuAddr += 2;                         // inc spu addr
        if (spuAddr > 0x7ffff) spuAddr = 0;   // wrap
    }

    iSpuAsyncWait = 0;
}

////////////////////////////////////////////////////////////////////////
