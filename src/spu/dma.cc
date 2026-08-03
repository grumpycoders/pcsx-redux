/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include "spu/externals.h"
#include "spu/interface.h"

// SPU RAM -> Main RAM DMA.
void PCSX::SPU::impl::readDMAMem(uint16_t* mainMem, int size) {
    if (pMixIrq) cbMtx.lock();

    for (int i = 0; i < size; i++) {
        // Copy 2 bytes.
        *mainMem++ = spuMem[spuAddr >> 1];
        // Increment the SPU address and wrap around.
        spuAddr = (spuAddr + 2) & 0x7ffff;
    }
    if (pMixIrq) cbMtx.unlock();
    iSpuAsyncWait = 0;
}

// To investigate: do sound data updates by DMA writes affect SPU IRQs? Will an IRQ be triggered if new
// data is written to the memory IRQ address?

void PCSX::SPU::impl::lockSPURAM() { cbMtx.lock(); }
void PCSX::SPU::impl::unlockSPURAM() { cbMtx.unlock(); }

void PCSX::SPU::impl::resetCaptureBuffer() {
    // Enable decoded buffer IRQs by setting the address.
    if (settings.get<DBufIRQ>().value) pMixIrq = spuRamBase;
    memset(captureBuffer.CDCapLeft, 0, CaptureBuffer::CB_SIZE);
    memset(captureBuffer.CDCapRight, 0, CaptureBuffer::CB_SIZE);
    captureBuffer.currIndex = 0;
    captureBuffer.endIndex = 0;
    captureBuffer.startIndex = 0;
    capBufVoiceIndex = 0;
}

// Main RAM -> SPU RAM DMA.
void PCSX::SPU::impl::writeDMAMem(uint16_t* mainMem, int size) {
    if (pMixIrq) cbMtx.lock();

    for (int i = 0; i < size; i++) {
        // Copy 2 bytes.
        spuMem[spuAddr >> 1] = *mainMem++;
        // Increment the SPU address and wrap around.
        spuAddr = (spuAddr + 2) & 0x7ffff;
    }

    if (pMixIrq) cbMtx.unlock();
    iSpuAsyncWait = 0;
}
