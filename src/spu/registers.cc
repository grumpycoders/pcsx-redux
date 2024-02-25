/***************************************************************************
                         registers.c  -  description
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
// 2004/09/18 - LDChen
// - pre-calculated ADSRX values
//
// 2003/02/09 - kode54
// - removed &0x3fff from reverb volume registers, fixes a few games,
//   hopefully won't be breaking anything
//
// 2003/01/19 - Pete
// - added Neill's reverb
//
// 2003/01/06 - Pete
// - added Neill's ADSR timings
//
// 2002/05/15 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#include "spu/registers.h"

#include <algorithm>

#include "core/logger.h"
#include "spu/externals.h"
#include "spu/interface.h"

/*
// adsr time values (in ms) by James Higgs ... see the end of
// the adsr.c source for details

#define ATTACK_MS     514L
#define DECAYHALF_MS  292L
#define DECAY_MS      584L
#define SUSTAIN_MS    450L
#define RELEASE_MS    446L
*/

// we have a timebase of 1.020408f ms, not 1 ms... so adjust adsr defines
#define ATTACK_MS 494L
#define DECAYHALF_MS 286L
#define DECAY_MS 572L
#define SUSTAIN_MS 441L
#define RELEASE_MS 437L

////////////////////////////////////////////////////////////////////////
// WRITE REGISTERS: called by main emu
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::writeRegister(uint32_t reg, uint16_t val) {
    const uint32_t r = reg & 0xfff;

    regArea[(r - 0xc00) >> 1] = val;

    // PCSX::PSXSPU_LOGGER::Log("SPU.write, writeRegister %08x: %04x\n", reg, val);

    // Check if this is one of the voice configuration registers
    if (r >= 0x0c00 && r < 0x0d80) {
        int ch = (r >> 4) - 0xc0;  // Figure out which voice it is
        switch (r & 0x0f) {
            case 0:  // Left volume
                SetVolumeL((uint8_t)ch, val);
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] Set Volume L = %04x\n", ch, val);
                break;
            case 2:  // Right volume
                SetVolumeR((uint8_t)ch, val);
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] Set Volume R = %04x\n", ch, val);
                break;
            case 4:  // Pitch
                SetPitch(ch, val);
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] ADPCM Sample Rate = %04x\n", ch, val);
                break;
            case 6:  // Sample start address
                // Brain Dead 13 - align to 16 boundary
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] ADPCM Start Address = %04x\n", ch, val);
                s_chan[ch].pStart = spuMemC + (uint32_t)((val << 3) & ~0xf);
                break;
            case 8: {  // Attack/Decay/Sustain/Release (ADSR)
                //---------------------------------------------//
                s_chan[ch].ADSRX.get<exAttackModeExp>().value = (val & ADSRFlags::AttackMode) ? 1 : 0;
                s_chan[ch].ADSRX.get<exAttackRate>().value =
                    (val & (ADSRFlags::AttackShiftMask | ADSRFlags::AttackStepMask)) >> 8;
                s_chan[ch].ADSRX.get<exDecayRate>().value = (val & ADSRFlags::DecayShiftMask) >> 4;
                s_chan[ch].ADSRX.get<exSustainLevel>().value = val & ADSRFlags::SustainLevelMask;
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] ADSR(lo) = %04x\n", ch, val);
                //---------------------------------------------// stuff below is only for debug mode

                s_chan[ch].ADSR.get<AttackModeExp>().value = (val & ADSRFlags::AttackMode) ? 1 : 0;

                uint32_t lx = (val & ADSRFlags::AttackShiftMask) >> 10;  // attack time to run from 0 to 100% volume
                lx = std::min(31U, lx);                                  // no overflow on shift!
                if (lx) {
                    lx = (1 << lx);
                    if (lx < 2147483) {
                        lx = (lx * ATTACK_MS) / 10000L;  // another overflow check
                    } else {
                        lx = (lx / 10000L) * ATTACK_MS;
                    }
                    if (!lx) {
                        lx = 1;
                    }
                }
                s_chan[ch].ADSR.get<AttackTime>().value = lx;

                // our adsr vol runs from 0 to 1024, so scale the sustain level
                s_chan[ch].ADSR.get<SustainLevel>().value = (1024 * (val & ADSRFlags::SustainLevelMask)) / 15;

                lx = (val & ADSRFlags::DecayShiftMask) >> 4;  // decay:
                if (lx)  // our const decay value is time it takes from 100% to 0% of volume
                {
                    lx = ((1 << (lx)) * DECAY_MS) / 10000L;
                    if (!lx) {
                        lx = 1;
                    }
                }
                s_chan[ch].ADSR.get<DecayTime>().value =  // so calc how long does it take to run from 100% to the
                                                          // wanted sus level
                    (lx * (1024 - s_chan[ch].ADSR.get<SustainLevel>().value)) / 1024;
            } break;
            //------------------------------------------------// adsr times with pre-calcs
            case 10: {
                //----------------------------------------------//
                s_chan[ch].ADSRX.get<exSustainModeExp>().value = (val & ADSRFlags::SustainMode) ? 1 : 0;
                s_chan[ch].ADSRX.get<exSustainIncrease>().value = (val & ADSRFlags::SustainDirection) ? 0 : 1;
                s_chan[ch].ADSRX.get<exSustainRate>().value =
                    (val & (ADSRFlags::SustainShiftMask | ADSRFlags::SustainStepMask)) >> 6;
                s_chan[ch].ADSRX.get<exReleaseModeExp>().value = (val & ADSRFlags::ReleaseMode) ? 1 : 0;
                s_chan[ch].ADSRX.get<exReleaseRate>().value = val & ADSRFlags::ReleaseShiftMask;
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] ADSR(hi) = %04x\n", ch, val);
                //----------------------------------------------// stuff below is only for debug mode

                s_chan[ch].ADSR.get<SustainModeExp>().value = (val & ADSRFlags::SustainMode) ? 1 : 0;
                s_chan[ch].ADSR.get<ReleaseModeExp>().value = (val & ADSRFlags::ReleaseMode) ? 1 : 0;

                uint32_t lx = (val & ADSRFlags::SustainShiftMask) >> 8;  // sustain time... often very high
                lx = std::min(31U, lx);                                  // values are used to hold the volume
                if (lx)                                                  // until a sound stop occurs
                {                                                        // the highest value we reach (due to
                    lx = (1 << lx);                                      // overflow checking) is:
                    if (lx < 2147483) {
                        lx = (lx * SUSTAIN_MS) / 10000L;  // 94704 seconds = 1578 minutes = 26 hours...
                    } else {
                        lx = (lx / 10000L) * SUSTAIN_MS;  // should be enuff... if the stop doesn't
                    }
                    if (!lx) {
                        lx = 1;  // come in this time span, I don't care :)
                    }
                }
                s_chan[ch].ADSR.get<SustainTime>().value = lx;

                lx = (val & ADSRFlags::ReleaseShiftMask);
                s_chan[ch].ADSR.get<ReleaseVal>().value = lx;
                if (lx)              // release time from 100% to 0%
                {                    // note: the release time will be
                    lx = (1 << lx);  // adjusted when a stop is coming,
                    if (lx < 2147483) {
                        lx = (lx * RELEASE_MS) / 10000L;  // so at this time the adsr vol will
                    } else {
                        lx = (lx / 10000L) * RELEASE_MS;  // run from (current volume) to 0%
                    }
                    if (!lx) {
                        lx = 1;
                    }
                }
                s_chan[ch].ADSR.get<ReleaseTime>().value = lx;

                if (val & 0x4000)  // add/dec flag
                {
                    s_chan[ch].ADSR.get<SustainModeDec>().value = -1;
                } else {
                    s_chan[ch].ADSR.get<SustainModeDec>().value = 1;
                }
            } break;
            case 12:  // TODO: Emulate ADSR Volume
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] ADSR Volume = %04x, unimplemented\n", ch, val);
                break;
            //------------------------------------------------//
            case 14:  // loop?
                // WaitForSingleObject(s_chan[ch].hMutex,2000);        // -> no multithread fuckups
                // align to 16-byte boundary
                s_chan[ch].pLoop = spuMemC + ((uint32_t)((val << 3) & ~0xf));
                s_chan[ch].data.get<Chan::IgnoreLoop>().value = true;
                //  ReleaseMutex(s_chan[ch].hMutex);                    // -> oki, on with the thread
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] ADPCM Repeat Address = %04x\n", ch, val);
                break;
                //------------------------------------------------//
        }

        iSpuAsyncWait = 0;
        return;
    }

    switch (r) {
        case H_SPUaddr:
            spuAddr = (uint32_t)val * 8;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, Data Transfer Address = %04x\n", val);
            break;

        case H_SPUdata:
            spuMem[spuAddr >> 1] = val;
            spuAddr += 2;
            if (spuAddr > 0x7ffff) {
                spuAddr = 0;
            }
            PCSX::PSXSPU_LOGGER::Log("SPU.write, Data Transfer Fifo = %04x\n", val);
            break;

        case H_SPUctrl:
            spuCtrl = val;
            m_noiseClock = (spuCtrl & (ControlFlags::NoiseShiftMask | ControlFlags::NoiseStepMask)) >> 8;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, CTRL = %04x\n", val);
            break;

        case H_SPUstat:
            spuStat = val & 0xf800;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, STAT = %04x, (read-only)\n", val);
            break;

        case H_SPUReverbAddr:
            if (val == 0xFFFF || val <= 0x200) {
                rvb.StartAddr = rvb.CurrAddr = 0;
            } else {
                const long iv = (uint32_t)val << 2;
                if (rvb.StartAddr != iv) {
                    rvb.StartAddr = (uint32_t)val << 2;
                    rvb.CurrAddr = rvb.StartAddr;
                }
            }
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mBASE = %04x\n", val);
            break;

        case H_SPUirqAddr:
            spuIrq = val;
            pSpuIrq = spuMemC + ((uint32_t)val << 3);
            PCSX::PSXSPU_LOGGER::Log("SPU.write, IRQ Address = %04x\n", val);
            break;

        case H_SPUrvolL:
            rvb.VolLeft = val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vLOUT = %04x\n", val);
            break;

        case H_SPUrvolR:
            rvb.VolRight = val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vROUT = %04x\n", val);
            break;
        //-------------------------------------------------//
        case H_ExtLeft:
            // auxprintf("EL %d\n",val);
            PCSX::PSXSPU_LOGGER::Log("SPU.write, External Audio Input Volume Left = %04x, unimplemented\n", val);
            break;
        //-------------------------------------------------//
        case H_ExtRight:
            // auxprintf("ER %d\n",val);
            PCSX::PSXSPU_LOGGER::Log("SPU.write, External Audio Input Volume Right = %04x, unimplemented\n", val);
            break;
        //-------------------------------------------------//
        case H_SPUmvolL:
            // auxprintf("ML %d\n",val);
            PCSX::PSXSPU_LOGGER::Log("SPU.write, Main Volume Left = %04x, unimplemented\n", val);
            break;
        //-------------------------------------------------//
        case H_SPUmvolR:
            // auxprintf("MR %d\n",val);
            PCSX::PSXSPU_LOGGER::Log("SPU.write, Main Volume Right = %04x, unimplemented\n", val);
            break;
        //-------------------------------------------------//
        case H_SPUMute1:
            // auxprintf("M0 %04x\n",val);
            // PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice 0..23 ON/OFF (status) (ENDX) = %04x, (read-only)\n", val);
            break;
        //-------------------------------------------------//
        case H_SPUMute2:
            // auxprintf("M1 %04x\n",val);
            // PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice 0..23 ON/OFF2 (status) (ENDX) = %04x, (read-only)\n", val);
            break;

        case H_SPUon1:
            SoundOn(0, 16, val);
            break;

        case H_SPUon2:
            SoundOn(16, 24, val);
            break;

        case H_SPUoff1:
            SoundOff(0, 16, val);
            break;

        case H_SPUoff2:
            SoundOff(16, 24, val);
            break;

        case H_CDLeft:
            iLeftXAVol = val & 0x7fff;
            if (cddavCallback) {
                cddavCallback(0, val);
            }
            PCSX::PSXSPU_LOGGER::Log("SPU.write, CD Audio Input Volume Left = %04x, unimplemented\n", val);
            break;

        case H_CDRight:
            iRightXAVol = val & 0x7fff;
            if (cddavCallback) {
                cddavCallback(1, val);
            }
            PCSX::PSXSPU_LOGGER::Log("SPU.write, CD Audio Input Volume Right = %04x, unimplemented\n", val);
            break;

        case H_FMod1:
            FModOn(0, 16, val);
            break;

        case H_FMod2:
            FModOn(16, 24, val);
            break;

        case H_Noise1:
            NoiseOn(0, 16, val);
            break;

        case H_Noise2:
            NoiseOn(16, 24, val);
            break;

        case H_RVBon1:
            ReverbOn(0, 16, val);
            break;

        case H_RVBon2:
            ReverbOn(16, 24, val);
            break;

        case H_Reverb + 0:
            rvb.FB_SRC_A = val;

            // OK, here's the fake REVERB stuff...
            // depending on effect we do more or less delay and repeats... bah
            // still... better than nothing :)

            SetREVERB(val);
            PCSX::PSXSPU_LOGGER::Log("SPU.write, dAPF1 = %04x\n", val);
            break;

        case H_Reverb + 2:
            rvb.FB_SRC_B = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, dAPF2 = %04x\n", val);
            break;
        case H_Reverb + 4:
            rvb.IIR_ALPHA = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vIIR = %04x\n", val);
            break;
        case H_Reverb + 6:
            rvb.ACC_COEF_A = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vCOMB1 = %04x\n", val);
            break;
        case H_Reverb + 8:
            rvb.ACC_COEF_B = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vCOMB2 = %04x\n", val);
            break;
        case H_Reverb + 10:
            rvb.ACC_COEF_C = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vCOMB3 = %04x\n", val);
            break;
        case H_Reverb + 12:
            rvb.ACC_COEF_D = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vCOMB4 = %04x\n", val);
            break;
        case H_Reverb + 14:
            rvb.IIR_COEF = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vWALL = %04x\n", val);
            break;
        case H_Reverb + 16:
            rvb.FB_ALPHA = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vAPF1 = %04x\n", val);
            break;
        case H_Reverb + 18:
            rvb.FB_X = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vAPF2 = %04x\n", val);
            break;
        case H_Reverb + 20:
            rvb.IIR_DEST_A0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLSAME = %04x\n", val);
            break;
        case H_Reverb + 22:
            rvb.IIR_DEST_A1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRSAME = %04x\n", val);
            break;
        case H_Reverb + 24:
            rvb.ACC_SRC_A0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLCOMB1 = %04x\n", val);
            break;
        case H_Reverb + 26:
            rvb.ACC_SRC_A1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRCOMB1 = %04x\n", val);
            break;
        case H_Reverb + 28:
            rvb.ACC_SRC_B0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLCOMB2 = %04x\n", val);
            break;
        case H_Reverb + 30:
            rvb.ACC_SRC_B1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRCOMB2 = %04x\n", val);
            break;
        case H_Reverb + 32:
            rvb.IIR_SRC_A0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, dLSAME = %04x\n", val);
            break;
        case H_Reverb + 34:
            rvb.IIR_SRC_A1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, dRSAME = %04x\n", val);
            break;
        case H_Reverb + 36:
            rvb.IIR_DEST_B0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLDIFF = %04x\n", val);
            break;
        case H_Reverb + 38:
            rvb.IIR_DEST_B1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRDIFF = %04x\n", val);
            break;
        case H_Reverb + 40:
            rvb.ACC_SRC_C0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLCOMB3 = %04x\n", val);
            break;
        case H_Reverb + 42:
            rvb.ACC_SRC_C1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRCOMB3 = %04x\n", val);
            break;
        case H_Reverb + 44:
            rvb.ACC_SRC_D0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLCOMB4 = %04x\n", val);
            break;
        case H_Reverb + 46:
            rvb.ACC_SRC_D1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRCOMB4 = %04x\n", val);
            break;
        case H_Reverb + 48:
            rvb.IIR_SRC_B1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, dLDIFF = %04x\n", val);
            break;
        case H_Reverb + 50:
            rvb.IIR_SRC_B0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, dRDIFF = %04x\n", val);
            break;
        case H_Reverb + 52:
            rvb.MIX_DEST_A0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLAPF1 = %04x\n", val);
            break;
        case H_Reverb + 54:
            rvb.MIX_DEST_A1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRAPF1 = %04x\n", val);
            break;
        case H_Reverb + 56:
            rvb.MIX_DEST_B0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLAPF2 = %04x\n", val);
            break;
        case H_Reverb + 58:
            rvb.MIX_DEST_B1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRAPF2 = %04x\n", val);
            break;
        case H_Reverb + 60:
            rvb.IN_COEF_L = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vLIN = %04x\n", val);
            break;
        case H_Reverb + 62:
            rvb.IN_COEF_R = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vRIN = %04x\n", val);
            break;
    }

    iSpuAsyncWait = 0;
}

////////////////////////////////////////////////////////////////////////
// READ REGISTER: called by main emu
////////////////////////////////////////////////////////////////////////

uint16_t PCSX::SPU::impl::readRegister(uint32_t reg) {
    const uint32_t r = reg & 0xfff;

    iSpuAsyncWait = 0;

    if (r >= 0x0c00 && r < 0x0d80) {
        switch (r & 0x0f) {
            case 12:  // get adsr vol
            {
                const int ch = (r >> 4) - 0xc0;

                if (s_chan[ch].data.get<Chan::New>().value) return 1;  // we are started, but not processed? return 1
                if (s_chan[ch].ADSRX.get<exVolume>().value &&  // same here... we haven't decoded one sample yet, so no
                                                               // envelope yet.
                                                               // return 1 as well
                    !s_chan[ch].ADSRX.get<exEnvelopeVol>().value)
                    return 1;
                return (uint16_t)s_chan[ch].ADSRX.get<exEnvelopeVol>().value;
            }

            case 14:  // get loop address
            {
                const int ch = (r >> 4) - 0xc0;
                if (s_chan[ch].pLoop == nullptr) return 0;
                return (uint16_t)((s_chan[ch].pLoop - spuMemC) >> 3);
            }
        }
    }

    switch (r) {
        case H_SPUctrl:
            return spuCtrl;

        case H_SPUstat:
            return (spuStat & ~StatusFlags::SPUModeMask) | (spuCtrl & StatusFlags::SPUModeMask);

        case H_SPUaddr:
            return (uint16_t)(spuAddr >> 3);

        case H_SPUdata: {
            uint16_t s = spuMem[spuAddr >> 1];
            spuAddr += 2;

            if (spuAddr > 0x7ffff) {
                spuAddr = 0;
            }
            return s;
        }

        case H_SPUirqAddr:
            return spuIrq;
    }

    return regArea[(r - 0xc00) >> 1];
}

// Start ADSR for voices [start, end] depending on val
void PCSX::SPU::impl::SoundOn(int start, int end, uint16_t val) {
    for (int ch = start; ch < end; ch++, val >>= 1) {
        if ((val & 1) && s_chan[ch].pStart) {  // mmm... start has to be set before key on !?!
            s_chan[ch].data.get<Chan::IgnoreLoop>().value = false;
            s_chan[ch].data.get<Chan::New>().value = true;
            dwNewChannel |= (1 << ch);  // bitfield for faster testing
            PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i ON\n", ch);
        }
    }
}

// Stop sound for voices [start, end] if the corresponding bit in val is set to 1
void PCSX::SPU::impl::SoundOff(int start, int end, uint16_t val) {
    for (int ch = start; ch < end; ch++, val >>= 1) {
        if (val & 1) {
            if(s_chan[ch].data.get<Chan::Stop>().value != true) {
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i OFF\n", ch);
            }
            s_chan[ch].data.get<Chan::Stop>().value = true;
        }
    }
}

// Set pitch modulation for voices [start, end] depending on val
void PCSX::SPU::impl::FModOn(int start, int end, uint16_t val) {
    for (int ch = start; ch < end; ch++, val >>= 1) {
        if (val & 1) {                                        // Check if modulation should be enabled for this voice
            if (ch > 0) {                                     // Pitch modulation doesn't work for voice 0
                if (s_chan[ch].data.get<Chan::FMod>().value != 1) {
                    PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i Pitch Modulation ON\n", ch);
                }
                s_chan[ch].data.get<Chan::FMod>().value = 1;  // sound channel
                s_chan[ch - 1].data.get<Chan::FMod>().value = 2;  // freq channel
            }
        } else {
            if (s_chan[ch].data.get<Chan::FMod>().value != 0) {
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i Pitch Modulation OFF\n", ch);
            }
            s_chan[ch].data.get<Chan::FMod>().value = 0;  // --> turn off fmod
        }
    }
}

// Set voices [start, end] to output ADPCM or noise, depending on if the corresponding bit in val is set to 0 or 1
// respectively
void PCSX::SPU::impl::NoiseOn(int start, int end, uint16_t val) {
    for (int ch = start; ch < end; ch++, val >>= 1) {
        if (val & 1) {
            if (s_chan[ch].data.get<Chan::Noise>().value != true) {
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i Noise ON\n", ch);
            }
            s_chan[ch].data.get<Chan::Noise>().value = true;
        } else {
            if(s_chan[ch].data.get<Chan::Noise>().value != false) {
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i Noise OFF\n", ch);
            }
            s_chan[ch].data.get<Chan::Noise>().value = false;
        }
    }
}

////////////////////////////////////////////////////////////////////////
// LEFT VOLUME register write
////////////////////////////////////////////////////////////////////////

// please note: sweep and phase invert are wrong... but I've never seen
// them used

void PCSX::SPU::impl::SetVolumeL(uint8_t ch, int16_t vol)  // LEFT VOLUME
{
    s_chan[ch].data.get<Chan::LeftVolRaw>().value = vol;

    if (vol & VolumeFlags::VolumeMode)  // sweep?
    {
        int16_t sInc;
        if (vol & VolumeFlags::SweepDirection) {
            sInc = -1;  // Decrease
        } else {
            sInc = 1;  // Increase
        }
        if (vol & VolumeFlags::SweepPhase) {
            // Negative Phase
            vol ^= 0xffff;  // -> mmm... phase inverted? have to investigate this
        }
        vol = ((vol & 0x7f) + 1) / 2;  // -> sweep: 0..127 -> 0..64
        vol += vol / (2 * sInc);  // -> HACK: we don't sweep right now, so we just raise/lower the volume by the half!
        vol *= 128;
    } else  // no sweep:
    {
        if (vol & 0x4000)  // -> mmm... phase inverted? have to investigate this
        {
            vol = (vol & 0x3fff) - 0x4000;
        }
    }

    vol &= 0x3fff;
    s_chan[ch].data.get<Chan::LeftVolume>().value = vol;  // store volume
}

////////////////////////////////////////////////////////////////////////
// RIGHT VOLUME register write
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::SetVolumeR(uint8_t ch, int16_t vol)  // RIGHT VOLUME
{
    s_chan[ch].data.get<Chan::RightVolRaw>().value = vol;

    if (vol & VolumeFlags::VolumeMode)  // sweep? - Arc the Lad III
    {
        int16_t sInc;
        if (vol & VolumeFlags::SweepDirection) {
            sInc = -1;  // Decrease
        } else {
            sInc = 1;  // Increase
        }
        if (vol & VolumeFlags::SweepPhase) {  // Negative Phase
            vol ^= 0xffff;                    // -> mmm... phase inverted? have to investigate this
        }
        vol = ((vol & 0x7f) + 1) / 2;  // -> sweep: 0..127 -> 0..64
        vol += vol / (2 * sInc);  // -> HACK: we don't sweep right now, so we just raise/lower the volume by the half!
        vol *= 128;
    } else  // no sweep:
    {
        if (vol & 0x4000)  // -> mmm... phase inverted? have to investigate this
        {
            vol = (vol & 0x3fff) - 0x4000;
        }
    }

    vol &= 0x3fff;

    s_chan[ch].data.get<Chan::RightVolume>().value = vol;
}

////////////////////////////////////////////////////////////////////////
// PITCH register write
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::SetPitch(int ch, uint16_t val)  // SET PITCH
{
    int NP;
    if (val > 0x3fff) {
        NP = 0x3fff;  // get pitch val
    } else {
        NP = val;
    }

    s_chan[ch].data.get<Chan::RawPitch>().value = NP;

    NP = (44100L * NP) / 4096L;  // calc frequency
    if (NP < 1) {
        NP = 1;  // some security
    }
    s_chan[ch].data.get<Chan::ActFreq>().value = NP;  // store frequency
}

// Enable/disable reverb for voices [start, end] depending on val
void PCSX::SPU::impl::ReverbOn(int start, int end, uint16_t val) {
    for (int ch = start; ch < end; ch++, val >>= 1) {
        if (val & 1) {
            if (s_chan[ch].data.get<Chan::Reverb>().value != true) {
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i Reverb ON\n", ch);
            }
            s_chan[ch].data.get<Chan::Reverb>().value = true;
            
        }
        else
        {
            if (s_chan[ch].data.get<Chan::Reverb>().value != false) {
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i Reverb OFF\n", ch);
            }
            s_chan[ch].data.get<Chan::Reverb>().value = false;
        }
        
    }
}
