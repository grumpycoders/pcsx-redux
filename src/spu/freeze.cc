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
#include "spu/registers.h"

void PCSX::SPU::impl::save(SaveStates::SPU &spu) {
    RemoveThread();

    // Capture buffer.
    spu.get<SaveStates::CBCDLeft>().copyFrom(reinterpret_cast<uint8_t *>(captureBuffer.CDCapLeft));
    spu.get<SaveStates::CBCDRight>().copyFrom(reinterpret_cast<uint8_t *>(captureBuffer.CDCapRight));
    spu.get<SaveStates::CBCurrIndex>().value = captureBuffer.currIndex;
    spu.get<SaveStates::CBEndIndex>().value = captureBuffer.endIndex;
    spu.get<SaveStates::CBStartIndex>().value = captureBuffer.startIndex;
    spu.get<SaveStates::CBVoiceIndex>().value = capBufVoiceIndex;

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
    if (irqAddress) spu.get<SaveStates::SPUIrqPtr>().value = uintptr_t(irqAddress - spuRamBase);

    for (unsigned i = 0; i < MAXCHAN; i++) {
        auto &channel = spu.get<SaveStates::Channels>().value[i];
        auto &data = channel.get<SaveStates::Data>();
        data = s_chan[i].data;
        channel.get<SaveStates::ADSRInfo>() = s_chan[i].adsr.legacy();
        channel.get<SaveStates::ADSRInfoEx>() = s_chan[i].adsr.ex();
        // Each per-voice helper owns the conversion between its runtime state and
        // its savestate-mirror fields; we just hand it the fields.
        s_chan[i].adpcm.saveTo(data.get<Chan::s_1>(), data.get<Chan::s_2>(), data.get<Chan::StartPtr>(),
                               data.get<Chan::CurrPtr>(), data.get<Chan::LoopPtr>(), spuRamBase,
                               data.get<Chan::SB>().value.data(), data.get<Chan::SBPos>());
        s_chan[i].volume.saveTo(data.get<Chan::LeftVolume>(), data.get<Chan::RightVolume>(),
                                data.get<Chan::LeftVolRaw>(), data.get<Chan::RightVolRaw>());
        s_chan[i].interp.saveTo(data.get<Chan::SB>().value.data(), data.get<Chan::spos>(), data.get<Chan::sinc>());
    }

    spu.get<SaveStates::SPUAddr>().value = spuAddr;
    spu.get<SaveStates::SPUCtrl>().value = spuCtrl;
    spu.get<SaveStates::SPUStat>().value = spuStat;

    m_noise.saveTo(spu.get<SaveStates::SPUNoiseClock>(), spu.get<SaveStates::SPUNoiseCount>(),
                   spu.get<SaveStates::SPUNoiseVal>());

    SetupThread();
}

void PCSX::SPU::impl::load(const SaveStates::SPU &spu) {
    // Processing is stopped while doing the save.
    RemoveThread();

    spu.get<SaveStates::CBCDLeft>().copyTo(reinterpret_cast<uint8_t *>(captureBuffer.CDCapLeft));
    spu.get<SaveStates::CBCDRight>().copyTo(reinterpret_cast<uint8_t *>(captureBuffer.CDCapRight));
    captureBuffer.currIndex = spu.get<SaveStates::CBCurrIndex>().value;
    captureBuffer.endIndex = spu.get<SaveStates::CBEndIndex>().value;
    captureBuffer.startIndex = spu.get<SaveStates::CBStartIndex>().value;
    capBufVoiceIndex = spu.get<SaveStates::CBVoiceIndex>().value;

    spu.get<SaveStates::SPURam>().copyTo(reinterpret_cast<uint8_t *>(spuMem));
    spu.get<SaveStates::SPUPorts>().copyTo(reinterpret_cast<uint8_t *>(regArea));

#if 0
// The xa_decode pointer is grabbed here, which is messy. This needs to be fixed up later.
    if (pF->xa.nsamples <= 4032)  // Start XA again.
        playADPCMchannel(&pF->xa);
#endif

    xapGlobal = 0;

    spuIrq = spu.get<SaveStates::SPUIrq>().value;
    const auto &pSpuIrqIn = spu.get<SaveStates::SPUIrqPtr>().value;
    irqAddress = pSpuIrqIn ? pSpuIrqIn + spuRamBase : nullptr;

    for (unsigned i = 0; i < MAXCHAN; i++) {
        const auto &channel = spu.get<SaveStates::Channels>().value[i];
        const auto &data = channel.get<SaveStates::Data>();
        s_chan[i].data = data;
        s_chan[i].adsr.legacy() = channel.get<SaveStates::ADSRInfo>();
        s_chan[i].adsr.ex() = channel.get<SaveStates::ADSRInfoEx>();
        s_chan[i].adpcm.loadFrom(data.get<Chan::s_1>(), data.get<Chan::s_2>(), data.get<Chan::StartPtr>(),
                                 data.get<Chan::CurrPtr>(), data.get<Chan::LoopPtr>(), spuRamBase,
                                 data.get<Chan::SB>().value.data(), data.get<Chan::SBPos>());
        s_chan[i].volume.loadFrom(data.get<Chan::LeftVolume>(), data.get<Chan::RightVolume>(),
                                  data.get<Chan::LeftVolRaw>(), data.get<Chan::RightVolRaw>());
        s_chan[i].interp.loadFrom(data.get<Chan::SB>().value.data(), data.get<Chan::spos>(), data.get<Chan::sinc>());
        s_chan[i].data.get<Chan::Mute>().value = false;
        s_chan[i].data.get<Chan::Solo>().value = false;
        s_chan[i].data.get<Chan::IrqDone>().value = 0;
    }

    spuAddr = spu.get<SaveStates::SPUAddr>().value;
    spuCtrl = spu.get<SaveStates::SPUCtrl>().value;
    spuStat = spu.get<SaveStates::SPUStat>().value;

    m_noise.loadFrom(spu.get<SaveStates::SPUNoiseClock>(), spu.get<SaveStates::SPUNoiseCount>(),
                     spu.get<SaveStates::SPUNoiseVal>());

    // Repair some globals.
    for (unsigned i = 0; i <= 62; i += 2) writeRegister(H_Reverb + i, regArea[(H_Reverb + i - 0xc00) >> 1]);
    writeRegister(H_SPUReverbAddr, regArea[(H_SPUReverbAddr - 0xc00) >> 1]);
    writeRegister(H_SPUrvolL, regArea[(H_SPUrvolL - 0xc00) >> 1]);
    writeRegister(H_SPUrvolR, regArea[(H_SPUrvolR - 0xc00) >> 1]);

    writeRegister(H_SPUctrl, (uint16_t)(regArea[(H_SPUctrl - 0xc00) >> 1] | 0x4000));
    writeRegister(H_SPUstat, regArea[(H_SPUstat - 0xc00) >> 1]);
    writeRegister(H_CDLeft, regArea[(H_CDLeft - 0xc00) >> 1]);
    writeRegister(H_CDRight, regArea[(H_CDRight - 0xc00) >> 1]);

    // Fix to prevent new interpolations from crashing.
    for (unsigned i = 0; i < MAXCHAN; i++) s_chan[i].interp.resetAfterLoad();

    // Repair LDChen's ADSR changes.
    if (spuAddr < 0x7ffff) {
        for (unsigned i = 0; i < 24; i++) {
            writeRegister(0x1f801c00 + (i << 4) + 0xc8, regArea[(i << 3) + 0x64]);
            writeRegister(0x1f801c00 + (i << 4) + 0xca, regArea[(i << 3) + 0x65]);
        }
    }

    // Start sound processing again.
    SetupThread();
}
