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

// SPU RAM -> Main RAM DMA
void PCSX::SPU::impl::readDMAMem(uint16_t* mainMem, int size) {
    if (pMixIrq) cbMtx.lock();

    for (int i = 0; i < size; i++) {
        *mainMem++ = spuMem[spuAddr >> 1];  // Copy 2 bytes
        spuAddr = (spuAddr + 2) & 0x7ffff;  // Increment SPU address and wrap around
    }
    if (pMixIrq) cbMtx.unlock();
    iSpuAsyncWait = 0;
}

// to investigate: do sound data updates by writedma affect spu
// irqs? Will an irq be triggered, if new data is written to
// the memory irq address?

void PCSX::SPU::impl::lockSPURAM() { cbMtx.lock(); }
void PCSX::SPU::impl::unlockSPURAM() { cbMtx.unlock(); }

void PCSX::SPU::impl::resetCaptureBuffer() {
    if (settings.get<DBufIRQ>().value) pMixIrq = spuMemC;  // enable decoded buffer irqs by setting the address
    memset(captureBuffer.CDCapLeft, 0, CaptureBuffer::CB_SIZE);
    memset(captureBuffer.CDCapRight, 0, CaptureBuffer::CB_SIZE);
    captureBuffer.currIndex = 0;
    captureBuffer.endIndex = 0;
    captureBuffer.startIndex = 0;
    capBufVoiceIndex = 0;
}

// Main RAM -> SPU RAM DMA
void PCSX::SPU::impl::writeDMAMem(uint16_t* mainMem, int size) {
    if (pMixIrq) cbMtx.lock();

    for (int i = 0; i < size; i++) {
        spuMem[spuAddr >> 1] = *mainMem++;  // Copy 2 bytes
        spuAddr = (spuAddr + 2) & 0x7ffff;  // Increment SPU address and wrap around
    }

    if (pMixIrq) cbMtx.unlock();
    iSpuAsyncWait = 0;
}
