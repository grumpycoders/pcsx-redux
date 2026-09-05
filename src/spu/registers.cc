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

#include "spu/registers.h"

#include <algorithm>

#include "core/logger.h"
#include "spu/externals.h"
#include "spu/interface.h"

// ADSR time values in milliseconds, by James Higgs; see the end of the adsr.c source for details. The original values
// were ATTACK_MS 514, DECAYHALF_MS 292, DECAY_MS 584, SUSTAIN_MS 450 and RELEASE_MS 446. The timebase here is
// 1.020408 ms rather than 1 ms, so the values below are adjusted.
#define ATTACK_MS 494L
#define DECAYHALF_MS 286L
#define DECAY_MS 572L
#define SUSTAIN_MS 441L
#define RELEASE_MS 437L

////////////////////////////////////////////////////////////////////////
// Write registers: called by the main emulator.
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::writeRegister(uint32_t reg, uint16_t val) {
    const uint32_t r = reg & 0xfff;

    regArea[(r - 0xc00) >> 1] = val;

    // Check if this is one of the voice configuration registers.
    if (r >= 0x0c00 && r < 0x0d80) {
        // Figure out which voice it is.
        int ch = (r >> 4) - 0xc0;
        switch (r & 0x0f) {
            // Left volume.
            case 0:
                s_chan[ch].volume.setLeft(val);
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] Set Volume L = %04x\n", ch, val);
                break;
            // Right volume.
            case 2:
                s_chan[ch].volume.setRight(val);
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] Set Volume R = %04x\n", ch, val);
                break;
            // Pitch.
            case 4:
                SetPitch(ch, val);
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] ADPCM Sample Rate = %04x\n", ch, val);
                break;
            // Sample start address.
            case 6:
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] ADPCM Start Address = %04x\n", ch, val);
                // Brain Dead 13: align to a 16-byte boundary.
                s_chan[ch].adpcm.setStart(spuRamBase + (uint32_t)((val << 3) & ~0xf));
                break;
            // Attack/Decay/Sustain/Release (ADSR).
            case 8: {
                s_chan[ch].adsr.ex().get<exAttackModeExp>().value = (val & ADSRFlags::AttackMode) ? 1 : 0;
                s_chan[ch].adsr.ex().get<exAttackRate>().value =
                    (val & (ADSRFlags::AttackShiftMask | ADSRFlags::AttackStepMask)) >> 8;
                s_chan[ch].adsr.ex().get<exDecayRate>().value = (val & ADSRFlags::DecayShiftMask) >> 4;
                s_chan[ch].adsr.ex().get<exSustainLevel>().value = val & ADSRFlags::SustainLevelMask;
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] ADSR(lo) = %04x\n", ch, val);

                // The code below is only for debug mode.

                s_chan[ch].adsr.legacy().get<AttackModeExp>().value = (val & ADSRFlags::AttackMode) ? 1 : 0;

                // Attack time to run from 0 to 100% volume.
                uint32_t lx = (val & ADSRFlags::AttackShiftMask) >> 10;
                // No overflow on shift.
                lx = std::min(31U, lx);
                if (lx) {
                    lx = (1 << lx);
                    if (lx < 2147483) {
                        // Another overflow check.
                        lx = (lx * ATTACK_MS) / 10000L;
                    } else {
                        lx = (lx / 10000L) * ATTACK_MS;
                    }
                    if (!lx) {
                        lx = 1;
                    }
                }
                s_chan[ch].adsr.legacy().get<AttackTime>().value = lx;

                // The ADSR volume runs from 0 to 1024, so scale the sustain level.
                s_chan[ch].adsr.legacy().get<SustainLevel>().value = (1024 * (val & ADSRFlags::SustainLevelMask)) / 15;

                // Decay.
                lx = (val & ADSRFlags::DecayShiftMask) >> 4;
                // The constant decay value is the time it takes to run from 100% to 0% of volume.
                if (lx) {
                    lx = ((1 << (lx)) * DECAY_MS) / 10000L;
                    if (!lx) {
                        lx = 1;
                    }
                }
                // Calculate how long it takes to run from 100% to the wanted sustain level.
                s_chan[ch].adsr.legacy().get<DecayTime>().value =
                    (lx * (1024 - s_chan[ch].adsr.legacy().get<SustainLevel>().value)) / 1024;
            } break;
            // ADSR times with pre-calculations.
            case 10: {
                s_chan[ch].adsr.ex().get<exSustainModeExp>().value = (val & ADSRFlags::SustainMode) ? 1 : 0;
                s_chan[ch].adsr.ex().get<exSustainIncrease>().value = (val & ADSRFlags::SustainDirection) ? 0 : 1;
                s_chan[ch].adsr.ex().get<exSustainRate>().value =
                    (val & (ADSRFlags::SustainShiftMask | ADSRFlags::SustainStepMask)) >> 6;
                s_chan[ch].adsr.ex().get<exReleaseModeExp>().value = (val & ADSRFlags::ReleaseMode) ? 1 : 0;
                s_chan[ch].adsr.ex().get<exReleaseRate>().value = val & ADSRFlags::ReleaseShiftMask;
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] ADSR(hi) = %04x\n", ch, val);

                // The code below is only for debug mode.

                s_chan[ch].adsr.legacy().get<SustainModeExp>().value = (val & ADSRFlags::SustainMode) ? 1 : 0;
                s_chan[ch].adsr.legacy().get<ReleaseModeExp>().value = (val & ADSRFlags::ReleaseMode) ? 1 : 0;

                // Sustain time. Very high values are often used to hold the volume until a sound stop occurs. Due to
                // the overflow checking below, the highest value reached is 94704 seconds, which is 1578 minutes, or
                // 26 hours. That is assumed to be enough; a stop that does not come within that time span is not
                // accounted for.
                uint32_t lx = (val & ADSRFlags::SustainShiftMask) >> 8;
                lx = std::min(31U, lx);
                if (lx) {
                    lx = (1 << lx);
                    if (lx < 2147483) {
                        lx = (lx * SUSTAIN_MS) / 10000L;
                    } else {
                        lx = (lx / 10000L) * SUSTAIN_MS;
                    }
                    if (!lx) {
                        lx = 1;
                    }
                }
                s_chan[ch].adsr.legacy().get<SustainTime>().value = lx;

                lx = (val & ADSRFlags::ReleaseShiftMask);
                s_chan[ch].adsr.legacy().get<ReleaseVal>().value = lx;
                // Release time from 100% to 0%. Note that the release time is adjusted when a stop is coming, so at
                // that point the ADSR volume runs from the current volume to 0%.
                if (lx) {
                    lx = (1 << lx);
                    if (lx < 2147483) {
                        lx = (lx * RELEASE_MS) / 10000L;
                    } else {
                        lx = (lx / 10000L) * RELEASE_MS;
                    }
                    if (!lx) {
                        lx = 1;
                    }
                }
                s_chan[ch].adsr.legacy().get<ReleaseTime>().value = lx;

                // Add/decrement flag.
                if (val & 0x4000) {
                    s_chan[ch].adsr.legacy().get<SustainModeDec>().value = -1;
                } else {
                    s_chan[ch].adsr.legacy().get<SustainModeDec>().value = 1;
                }
            } break;
            // TODO: emulate the ADSR volume.
            case 12:
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] ADSR Volume = %04x, unimplemented\n", ch, val);
                break;
            // Loop address.
            case 14:
                // Align to a 16-byte boundary.
                s_chan[ch].adpcm.setLoop(spuRamBase + ((uint32_t)((val << 3) & ~0xf)));
                s_chan[ch].data.get<Chan::IgnoreLoop>().value = true;
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice[%02i] ADPCM Repeat Address = %04x\n", ch, val);
                break;
        }

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
            // Writing IRQ9 Enable = 0 is the acknowledge: it is the only thing that clears
            // the SPUSTAT flag, and writing it back to 1 is what re-arms the interrupt.
            if (!(val & ControlFlags::IRQEnable)) spuStat &= ~StatusFlags::IRQFlag;
            spuCtrl = val;
            m_noise.setClock((spuCtrl & (ControlFlags::NoiseShiftMask | ControlFlags::NoiseStepMask)) >> 8);
            PCSX::PSXSPU_LOGGER::Log("SPU.write, CTRL = %04x\n", val);
            break;

        case H_SPUstat:
            spuStat = val & 0xf800;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, STAT = %04x, (read-only)\n", val);
            break;

        case H_SPUReverbAddr:
            if (val == 0xFFFF || val <= 0x200) {
                m_reverb.rvb.StartAddr = m_reverb.rvb.CurrAddr = 0;
            } else {
                const long iv = (uint32_t)val << 2;
                if (m_reverb.rvb.StartAddr != iv) {
                    m_reverb.rvb.StartAddr = (uint32_t)val << 2;
                    m_reverb.rvb.CurrAddr = m_reverb.rvb.StartAddr;
                }
            }
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mBASE = %04x\n", val);
            break;

        case H_SPUirqAddr:
            spuIrq = val;
            irqAddress = spuRamBase + ((uint32_t)val << 3);
            PCSX::PSXSPU_LOGGER::Log("SPU.write, IRQ Address = %04x\n", val);
            break;

        case H_SPUrvolL:
            m_reverb.rvb.VolLeft = val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vLOUT = %04x\n", val);
            break;

        case H_SPUrvolR:
            m_reverb.rvb.VolRight = val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vROUT = %04x\n", val);
            break;

        case H_ExtLeft:
            PCSX::PSXSPU_LOGGER::Log("SPU.write, External Audio Input Volume Left = %04x, unimplemented\n", val);
            break;

        case H_ExtRight:
            PCSX::PSXSPU_LOGGER::Log("SPU.write, External Audio Input Volume Right = %04x, unimplemented\n", val);
            break;

        case H_SPUmvolL:
            PCSX::PSXSPU_LOGGER::Log("SPU.write, Main Volume Left = %04x, unimplemented\n", val);
            break;

        case H_SPUmvolR:
            PCSX::PSXSPU_LOGGER::Log("SPU.write, Main Volume Right = %04x, unimplemented\n", val);
            break;

        // Voice 0..23 ON/OFF (status) (ENDX), read-only.
        case H_SPUMute1:
            break;

        // Voice 0..23 ON/OFF2 (status) (ENDX), read-only.
        case H_SPUMute2:
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
            m_reverb.rvb.FB_SRC_A = val;

            // Fake reverb: depending on the effect, more or less delay and repeats are applied.
            PCSX::PSXSPU_LOGGER::Log("SPU.write, dAPF1 = %04x\n", val);
            break;

        case H_Reverb + 2:
            m_reverb.rvb.FB_SRC_B = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, dAPF2 = %04x\n", val);
            break;
        case H_Reverb + 4:
            m_reverb.rvb.IIR_ALPHA = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vIIR = %04x\n", val);
            break;
        case H_Reverb + 6:
            m_reverb.rvb.ACC_COEF_A = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vCOMB1 = %04x\n", val);
            break;
        case H_Reverb + 8:
            m_reverb.rvb.ACC_COEF_B = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vCOMB2 = %04x\n", val);
            break;
        case H_Reverb + 10:
            m_reverb.rvb.ACC_COEF_C = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vCOMB3 = %04x\n", val);
            break;
        case H_Reverb + 12:
            m_reverb.rvb.ACC_COEF_D = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vCOMB4 = %04x\n", val);
            break;
        case H_Reverb + 14:
            m_reverb.rvb.IIR_COEF = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vWALL = %04x\n", val);
            break;
        case H_Reverb + 16:
            m_reverb.rvb.FB_ALPHA = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vAPF1 = %04x\n", val);
            break;
        case H_Reverb + 18:
            m_reverb.rvb.FB_X = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vAPF2 = %04x\n", val);
            break;
        case H_Reverb + 20:
            m_reverb.rvb.IIR_DEST_A0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLSAME = %04x\n", val);
            break;
        case H_Reverb + 22:
            m_reverb.rvb.IIR_DEST_A1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRSAME = %04x\n", val);
            break;
        case H_Reverb + 24:
            m_reverb.rvb.ACC_SRC_A0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLCOMB1 = %04x\n", val);
            break;
        case H_Reverb + 26:
            m_reverb.rvb.ACC_SRC_A1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRCOMB1 = %04x\n", val);
            break;
        case H_Reverb + 28:
            m_reverb.rvb.ACC_SRC_B0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLCOMB2 = %04x\n", val);
            break;
        case H_Reverb + 30:
            m_reverb.rvb.ACC_SRC_B1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRCOMB2 = %04x\n", val);
            break;
        case H_Reverb + 32:
            m_reverb.rvb.IIR_SRC_A0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, dLSAME = %04x\n", val);
            break;
        case H_Reverb + 34:
            m_reverb.rvb.IIR_SRC_A1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, dRSAME = %04x\n", val);
            break;
        case H_Reverb + 36:
            m_reverb.rvb.IIR_DEST_B0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLDIFF = %04x\n", val);
            break;
        case H_Reverb + 38:
            m_reverb.rvb.IIR_DEST_B1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRDIFF = %04x\n", val);
            break;
        case H_Reverb + 40:
            m_reverb.rvb.ACC_SRC_C0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLCOMB3 = %04x\n", val);
            break;
        case H_Reverb + 42:
            m_reverb.rvb.ACC_SRC_C1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRCOMB3 = %04x\n", val);
            break;
        case H_Reverb + 44:
            m_reverb.rvb.ACC_SRC_D0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLCOMB4 = %04x\n", val);
            break;
        case H_Reverb + 46:
            m_reverb.rvb.ACC_SRC_D1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRCOMB4 = %04x\n", val);
            break;
        case H_Reverb + 48:
            m_reverb.rvb.IIR_SRC_B1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, dLDIFF = %04x\n", val);
            break;
        case H_Reverb + 50:
            m_reverb.rvb.IIR_SRC_B0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, dRDIFF = %04x\n", val);
            break;
        case H_Reverb + 52:
            m_reverb.rvb.MIX_DEST_A0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLAPF1 = %04x\n", val);
            break;
        case H_Reverb + 54:
            m_reverb.rvb.MIX_DEST_A1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRAPF1 = %04x\n", val);
            break;
        case H_Reverb + 56:
            m_reverb.rvb.MIX_DEST_B0 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mLAPF2 = %04x\n", val);
            break;
        case H_Reverb + 58:
            m_reverb.rvb.MIX_DEST_B1 = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, mRAPF2 = %04x\n", val);
            break;
        case H_Reverb + 60:
            m_reverb.rvb.IN_COEF_L = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vLIN = %04x\n", val);
            break;
        case H_Reverb + 62:
            m_reverb.rvb.IN_COEF_R = (int16_t)val;
            PCSX::PSXSPU_LOGGER::Log("SPU.write, vRIN = %04x\n", val);
            break;
    }

}

////////////////////////////////////////////////////////////////////////
// Read register: called by the main emulator.
////////////////////////////////////////////////////////////////////////

uint16_t PCSX::SPU::impl::readRegister(uint32_t reg) {
    const uint32_t r = reg & 0xfff;

    if (r >= 0x0c00 && r < 0x0d80) {
        switch (r & 0x0f) {
            // Get the ADSR volume.
            case 12: {
                const int ch = (r >> 4) - 0xc0;

                // ENVX is the live envelope level and nothing else (0..7FFFh). A voice that
                // has been keyed on but has not stepped its envelope yet reads 0, exactly
                // like an idle one - software keys on and then spins on ENVX until it goes
                // nonzero to synchronise with the SPU's own sample clock. The old "started
                // but not processed, return 1" fudge broke that: the spin exited at key-on
                // instead of at the first envelope step, so every subsequent read landed one
                // envelope period early.
                PCSX::PSXSPU_LOGGER::Log("SPU.read, Voice[%02i] Current ADSR Volume = %04x\n", ch,
                                         (uint16_t)s_chan[ch].adsr.ex().get<exEnvelopeVol>().value);
                return (uint16_t)s_chan[ch].adsr.ex().get<exEnvelopeVol>().value;
            }

            // Get the loop address.
            case 14: {
                const int ch = (r >> 4) - 0xc0;
                if (s_chan[ch].adpcm.loop() == nullptr) {
                    PCSX::PSXSPU_LOGGER::Log("SPU.read, Voice[%02i] ADPCM Repeat Address = 00000\n", ch);
                    return 0;
                }
                PCSX::PSXSPU_LOGGER::Log("SPU.read, Voice[%02i] ADPCM Repeat Address = %04x\n", ch,
                                         (uint16_t)((s_chan[ch].adpcm.loop() - spuRamBase) >> 3));
                return (uint16_t)((s_chan[ch].adpcm.loop() - spuRamBase) >> 3);
            }
        }
    }

    switch (r) {
        // ENDX low 16 voices (read-only).
        case H_SPUMute1:
            return (uint16_t)(spuEndx & 0xffff);

        // ENDX high 8 voices (read-only).
        case H_SPUMute2:
            return (uint16_t)((spuEndx >> 16) & 0xff);

        case H_SPUctrl:
            PCSX::PSXSPU_LOGGER::Log("SPU.read, CTRL = %04x\n", spuCtrl);
            return spuCtrl;

        case H_SPUstat:
            PCSX::PSXSPU_LOGGER::Log("SPU.read, STAT = %04x\n",
                                     (spuStat & ~StatusFlags::SPUModeMask) | (spuCtrl & StatusFlags::SPUModeMask));
            return (spuStat & ~StatusFlags::SPUModeMask) | (spuCtrl & StatusFlags::SPUModeMask);

        case H_SPUaddr:
            PCSX::PSXSPU_LOGGER::Log("SPU.read, Data Transfer Address = %04x\n", (uint16_t)(spuAddr >> 3));
            return (uint16_t)(spuAddr >> 3);

        case H_SPUdata: {
            uint16_t s = spuMem[spuAddr >> 1];
            spuAddr += 2;

            if (spuAddr > 0x7ffff) {
                spuAddr = 0;
            }
            PCSX::PSXSPU_LOGGER::Log("SPU.read, Data Transfer Fifo = %04x\n", s);
            return s;
        }

        case H_SPUirqAddr:
            PCSX::PSXSPU_LOGGER::Log("SPU.read, Data Transfer Fifo = %04x\n", spuIrq);
            return spuIrq;
    }

    PCSX::PSXSPU_LOGGER::Log("SPU.read, regArea[%03x] = %04x\n", r, regArea[(r - 0xc00) >> 1]);
    return regArea[(r - 0xc00) >> 1];
}

// Start ADSR for voices [start, end] depending on val.
void PCSX::SPU::impl::SoundOn(int start, int end, uint16_t val) {
    for (int ch = start; ch < end; ch++, val >>= 1) {
        // The start address has to be set before key on.
        if ((val & 1) && s_chan[ch].adpcm.start()) {
            s_chan[ch].data.get<Chan::IgnoreLoop>().value = false;
            s_chan[ch].data.get<Chan::New>().value = true;
            // Key-on clears this voice's ENDX bit.
            spuEndx &= ~(1u << ch);
            // Bitfield for faster testing.
            newChannelMask |= (1 << ch);
            PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i ON\n", ch);
        }
    }
}

// Stop sound for voices [start, end] if the corresponding bit in val is set to 1.
void PCSX::SPU::impl::SoundOff(int start, int end, uint16_t val) {
    for (int ch = start; ch < end; ch++, val >>= 1) {
        if (val & 1) {
            if (s_chan[ch].data.get<Chan::Stop>().value != true) {
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i OFF\n", ch);
            }
            s_chan[ch].data.get<Chan::Stop>().value = true;
        }
    }
}

// Set pitch modulation for voices [start, end] depending on val.
void PCSX::SPU::impl::FModOn(int start, int end, uint16_t val) {
    for (int ch = start; ch < end; ch++, val >>= 1) {
        // Check if modulation should be enabled for this voice.
        if (val & 1) {
            // Pitch modulation does not work for voice 0.
            if (ch > 0) {
                if (s_chan[ch].data.get<Chan::FMod>().value != 1) {
                    PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i Pitch Modulation ON\n", ch);
                }
                // Sound channel.
                s_chan[ch].data.get<Chan::FMod>().value = 1;
                // Frequency channel.
                s_chan[ch - 1].data.get<Chan::FMod>().value = 2;
            }
        } else {
            if (s_chan[ch].data.get<Chan::FMod>().value != 0) {
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i Pitch Modulation OFF\n", ch);
            }
            // Turn off frequency modulation.
            s_chan[ch].data.get<Chan::FMod>().value = 0;
        }
    }
}

// Set voices [start, end] to output ADPCM or noise, depending on whether the corresponding bit in val is set to 0 or
// 1 respectively.
void PCSX::SPU::impl::NoiseOn(int start, int end, uint16_t val) {
    for (int ch = start; ch < end; ch++, val >>= 1) {
        if (val & 1) {
            if (s_chan[ch].data.get<Chan::Noise>().value != true) {
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i Noise ON\n", ch);
            }
            s_chan[ch].data.get<Chan::Noise>().value = true;
        } else {
            if (s_chan[ch].data.get<Chan::Noise>().value != false) {
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i Noise OFF\n", ch);
            }
            s_chan[ch].data.get<Chan::Noise>().value = false;
        }
    }
}

// Set the pitch for voice ch.
void PCSX::SPU::impl::SetPitch(int ch, uint16_t val) {
    int NP;
    // Get the pitch value.
    if (val > 0x3fff) {
        NP = 0x3fff;
    } else {
        NP = val;
    }

    s_chan[ch].data.get<Chan::RawPitch>().value = NP;

    // Calculate the frequency.
    NP = (44100L * NP) / 4096L;
    // Some security.
    if (NP < 1) {
        NP = 1;
    }
    // Store the frequency.
    s_chan[ch].data.get<Chan::ActFreq>().value = NP;
}

// Enable/disable reverb for voices [start, end] depending on val.
void PCSX::SPU::impl::ReverbOn(int start, int end, uint16_t val) {
    for (int ch = start; ch < end; ch++, val >>= 1) {
        if (val & 1) {
            if (s_chan[ch].data.get<Chan::Reverb>().value != true) {
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i Reverb ON\n", ch);
            }
            s_chan[ch].data.get<Chan::Reverb>().value = true;

        } else {
            if (s_chan[ch].data.get<Chan::Reverb>().value != false) {
                PCSX::PSXSPU_LOGGER::Log("SPU.write, Voice %02i Reverb OFF\n", ch);
            }
            s_chan[ch].data.get<Chan::Reverb>().value = false;
        }
    }
}
