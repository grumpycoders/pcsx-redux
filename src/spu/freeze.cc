/***************************************************************************
                          freeze.c  -  description
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
// 2004/09/18 - Pete
// - corrected LDChen ADSRX values after save state loading
//
// 2003/03/20 - Pete
// - fix to prevent the new interpolations from crashing when loading a save state
//
// 2003/01/06 - Pete
// - small changes for version 1.3 adsr save state loading
//
// 2002/05/15 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#include "spu/externals.h"
#include "spu/interface.h"
#include "spu/registers.h"

////////////////////////////////////////////////////////////////////////
// freeze structs
////////////////////////////////////////////////////////////////////////

typedef struct {
    unsigned short spuIrq;
    unsigned long pSpuIrq;
    unsigned long dummy0;
    unsigned long dummy1;
    unsigned long dummy2;
    unsigned long dummy3;

    PCSX::SPU::SPUCHAN s_chan[PCSX::SPU::impl::MAXCHAN];

} SPUOSSFreeze_t;

////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// SPUFREEZE: called by main emu on savestate load/save
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::save(SaveStates::SPU &spu) {
    RemoveThread();

    spu.get<SaveStates::SPURam>().copyFrom(reinterpret_cast<uint8_t *>(spuMem));
    spu.get<SaveStates::SPUPorts>().copyFrom(reinterpret_cast<uint8_t *>(regArea));
    auto &xa = spu.get<SaveStates::XAField>();
    if (xapGlobal) {
        xa.get<SaveStates::XAFrequency>().value = xapGlobal->freq;
        xa.get<SaveStates::XANBits>().value = xapGlobal->nbits;
        xa.get<SaveStates::XANSamples>().value = xapGlobal->nsamples;
        xa.get<SaveStates::XAStereo>().value = xapGlobal->stereo;
        auto &left = xa.get<SaveStates::XAADPCMLeft>();
        left.get<SaveStates::ADPCMDecodeY0>().value = xapGlobal->left.y0;
        left.get<SaveStates::ADPCMDecodeY1>().value = xapGlobal->left.y1;
        auto &right = xa.get<SaveStates::XAADPCMLeft>();
        right.get<SaveStates::ADPCMDecodeY0>().value = xapGlobal->right.y0;
        right.get<SaveStates::ADPCMDecodeY1>().value = xapGlobal->right.y1;
        xa.get<SaveStates::XAPCM>().copyFrom(reinterpret_cast<uint8_t *>(xapGlobal->pcm));
    }
    spu.get<SaveStates::SPUIrq>().value = spuIrq;
    if (pSpuIrq) spu.get<SaveStates::SPUIrqPtr>().value = uintptr_t(pSpuIrq - spuMemC);

    for (unsigned i = 0; i < MAXCHAN; i++) {
        auto &channel = spu.get<SaveStates::Channels>().value[i];
        auto &data = channel.get<SaveStates::Data>();
        data = s_chan[i].data;
        channel.get<SaveStates::ADSRInfo>() = s_chan[i].ADSR;
        channel.get<SaveStates::ADSRInfoEx>() = s_chan[i].ADSRX;
        auto storePtr = [this](uint8_t *ptr, Protobuf::Int32 &val) { val.value = ptr ? ptr - spuMemC : -1; };
        storePtr(s_chan[i].pStart, data.get<Chan::StartPtr>());
        storePtr(s_chan[i].pCurr, data.get<Chan::CurrPtr>());
        storePtr(s_chan[i].pLoop, data.get<Chan::LoopPtr>());
    }

    spu.get<SaveStates::SPUAddr>().value = spuAddr;
    spu.get<SaveStates::SPUCtrl>().value = spuCtrl;
    spu.get<SaveStates::SPUStat>().value = spuStat;

    SetupThread();
}

void PCSX::SPU::impl::load(const SaveStates::SPU &spu) {
    RemoveThread();  // we stop processing while doing the save!

    spu.get<SaveStates::SPURam>().copyTo(reinterpret_cast<uint8_t *>(spuMem));
    spu.get<SaveStates::SPUPorts>().copyTo(reinterpret_cast<uint8_t *>(regArea));

#if 0
// ugh, the xa_decode pointer is grabbed... this seems a mess. We'll need to fix this up later.
    if (pF->xa.nsamples <= 4032)  // start xa again
        playADPCMchannel(&pF->xa);
#endif

    xapGlobal = 0;

    spuIrq = spu.get<SaveStates::SPUIrq>().value;
    const auto &pSpuIrqIn = spu.get<SaveStates::SPUIrqPtr>().value;
    pSpuIrq = pSpuIrqIn ? pSpuIrqIn + spuMemC : nullptr;

    for (unsigned i = 0; i < MAXCHAN; i++) {
        const auto &channel = spu.get<SaveStates::Channels>().value[i];
        const auto &data = channel.get<SaveStates::Data>();
        s_chan[i].data = data;
        s_chan[i].ADSR = channel.get<SaveStates::ADSRInfo>();
        s_chan[i].ADSRX = channel.get<SaveStates::ADSRInfoEx>();
        auto restorePtr = [this](uint8_t *&ptr, const Protobuf::Int32 &val) {
            ptr = val.value == -1 ? nullptr : val.value + spuMemC;
        };
        restorePtr(s_chan[i].pStart, data.get<Chan::StartPtr>());
        restorePtr(s_chan[i].pCurr, data.get<Chan::CurrPtr>());
        restorePtr(s_chan[i].pLoop, data.get<Chan::LoopPtr>());
        s_chan[i].data.get<Chan::Mute>().value = false;
        s_chan[i].data.get<Chan::IrqDone>().value = 0;
    }

    spuAddr = spu.get<SaveStates::SPUAddr>().value;
    spuCtrl = spu.get<SaveStates::SPUCtrl>().value;
    spuStat = spu.get<SaveStates::SPUStat>().value;

    // repair some globals
    for (unsigned i = 0; i <= 62; i += 2) writeRegister(H_Reverb + i, regArea[(H_Reverb + i - 0xc00) >> 1]);
    writeRegister(H_SPUReverbAddr, regArea[(H_SPUReverbAddr - 0xc00) >> 1]);
    writeRegister(H_SPUrvolL, regArea[(H_SPUrvolL - 0xc00) >> 1]);
    writeRegister(H_SPUrvolR, regArea[(H_SPUrvolR - 0xc00) >> 1]);

    writeRegister(H_SPUctrl, (uint16_t)(regArea[(H_SPUctrl - 0xc00) >> 1] | 0x4000));
    writeRegister(H_SPUstat, regArea[(H_SPUstat - 0xc00) >> 1]);
    writeRegister(H_CDLeft, regArea[(H_CDLeft - 0xc00) >> 1]);
    writeRegister(H_CDRight, regArea[(H_CDRight - 0xc00) >> 1]);

    // fix to prevent new interpolations from crashing
    for (unsigned i = 0; i < MAXCHAN; i++) s_chan[i].data.get<Chan::SB>().value[28].value = 0;

    // repair LDChen's ADSR changes
    if (spuAddr < 0x7ffff) {
        for (unsigned i = 0; i < 24; i++) {
            writeRegister(0x1f801c00 + (i << 4) + 0xc8, regArea[(i << 3) + 0x64]);
            writeRegister(0x1f801c00 + (i << 4) + 0xca, regArea[(i << 3) + 0x65]);
        }
    }

    SetupThread();  // start sound processing again
}
