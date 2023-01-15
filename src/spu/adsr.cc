/***************************************************************************
                          adsr.c  -  description
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
// - Speed optimized ADSR mixing
//
// 2003/05/14 - xodnizel
// - removed stopping of reverb on sample end
//
// 2003/01/06 - Pete
// - added Neill's ADSR timings
//
// 2002/05/15 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#include "spu/adsr.h"

#include "spu/externals.h"
#include "spu/interface.h"

enum ADSRState : int32_t {
    Attack = 0,
    Decay = 1,
    Sustain = 2,
    Release = 3,
    Stopped = 4,
};

inline int PCSX::SPU::ADSR::Attack(SPUCHAN *ch) {
    int rate = ch->ADSRX.get<exAttackRate>().value;
    int32_t EnvelopeVol = ch->ADSRX.get<exEnvelopeVol>().value;
    int32_t EnvelopeVolFrak = ch->ADSRX.get<exEnvelopeVolFrak>().value;
    const int32_t attack_mode_exp = ch->ADSRX.get<exAttackModeExp>().value;

    // Exponential increase
    if (attack_mode_exp && EnvelopeVol >= 0x6000) {
        rate += 8;
    }

    EnvelopeVolFrak++;
    if (EnvelopeVolFrak >= denominator[rate]) {
        EnvelopeVolFrak = 0;
        EnvelopeVol += numerator_increase[rate];
    }

    if (EnvelopeVol >= 32767L) {
        EnvelopeVol = 32767L;
        EnvelopeVolFrak = 0;
        ch->ADSRX.get<exState>().value = ADSRState::Decay;
    }

    ch->ADSRX.get<exEnvelopeVol>().value = EnvelopeVol;
    ch->ADSRX.get<exEnvelopeVolFrak>().value = EnvelopeVolFrak;
    ch->ADSRX.get<exVolume>().value = (EnvelopeVol >>= 5);

    return EnvelopeVol;
}

inline int PCSX::SPU::ADSR::Decay(SPUCHAN *ch) {
    const int rate = ch->ADSRX.get<exDecayRate>().value * 4;
    int32_t EnvelopeVol = ch->ADSRX.get<exEnvelopeVol>().value;
    int32_t EnvelopeVolFrak = ch->ADSRX.get<exEnvelopeVolFrak>().value;
    const int32_t release_mode_exp = ch->ADSRX.get<exReleaseModeExp>().value;

    EnvelopeVolFrak++;
    if (EnvelopeVolFrak >= denominator[rate]) {
        EnvelopeVolFrak = 0;

        if (release_mode_exp) {
            // Exponential decrease
            EnvelopeVol += (numerator_decrease[rate] * EnvelopeVol) >> 15;
        } else {
            EnvelopeVol += numerator_decrease[rate];
        }
        // EnvelopeVol += (numerator_decrease[rate] * EnvelopeVol) >> 15;
    }

    if (EnvelopeVol < 0) {
        EnvelopeVol = 0;
        EnvelopeVolFrak = 0;
    }

    if (((EnvelopeVol >> 11) & 0xf) < ch->ADSRX.get<exSustainLevel>().value) {
        ch->ADSRX.get<exState>().value = ADSRState::Sustain;
    }

    ch->ADSRX.get<exEnvelopeVol>().value = EnvelopeVol;
    ch->ADSRX.get<exEnvelopeVolFrak>().value = EnvelopeVolFrak;
    ch->ADSRX.get<exVolume>().value = (EnvelopeVol >>= 5);

    return EnvelopeVol;
}

inline int PCSX::SPU::ADSR::Sustain(SPUCHAN *ch) {
    int rate = ch->ADSRX.get<exSustainRate>().value;
    int32_t EnvelopeVol = ch->ADSRX.get<exEnvelopeVol>().value;
    int32_t EnvelopeVolFrak = ch->ADSRX.get<exEnvelopeVolFrak>().value;
    const int32_t sustain_mode_exp = ch->ADSRX.get<exSustainModeExp>().value;
    const int32_t sustain_increase = ch->ADSRX.get<exSustainIncrease>().value;

    if (sustain_increase) {
        // Exponential increase
        if (sustain_mode_exp && (EnvelopeVol >= 0x6000)) {
            rate += 8;
        }

        EnvelopeVolFrak++;
        if (EnvelopeVolFrak >= denominator[rate]) {
            EnvelopeVolFrak = 0;
            EnvelopeVol += numerator_increase[rate];
        }

    } else {
        EnvelopeVolFrak++;
        if (EnvelopeVolFrak >= denominator[rate]) {
            EnvelopeVolFrak = 0;

            // Exponential decrease
            if (sustain_mode_exp) {
                EnvelopeVol += (numerator_decrease[rate] * EnvelopeVol) >> 15;
            } else {
                EnvelopeVol += numerator_decrease[rate];
            }
        }
    }

    if (EnvelopeVol > 32767L) {
        EnvelopeVol = 32767L;
    }

    if (EnvelopeVol < 0) {
        EnvelopeVol = 0;
        EnvelopeVolFrak = 0;
    }

    ch->ADSRX.get<exEnvelopeVol>().value = EnvelopeVol;
    ch->ADSRX.get<exEnvelopeVolFrak>().value = EnvelopeVolFrak;
    ch->ADSRX.get<exVolume>().value = (EnvelopeVol >>= 5);

    return EnvelopeVol;
}

inline int PCSX::SPU::ADSR::Release(SPUCHAN *ch) {
    int rate = ch->ADSRX.get<exReleaseRate>().value * 4;
    int32_t EnvelopeVol = ch->ADSRX.get<exEnvelopeVol>().value;
    int32_t EnvelopeVolFrak = ch->ADSRX.get<exEnvelopeVolFrak>().value;
    const int32_t release_mode_exp = ch->ADSRX.get<exReleaseModeExp>().value;

    EnvelopeVolFrak++;
    if (EnvelopeVolFrak >= denominator[rate]) {
        EnvelopeVolFrak = 0;

        // Exponential decrease
        if (release_mode_exp) {
            EnvelopeVol += (numerator_decrease[rate] * EnvelopeVol) >> 15;
        } else {
            EnvelopeVol += numerator_decrease[rate];
        }
    }

    if (EnvelopeVol < 0) {
        // ch->ADSRX.get<exState>().value = ADSRState::Stopped;
        EnvelopeVol = 0;
        EnvelopeVolFrak = 0;
        ch->data.get<Chan::On>().value = false;
    }

    ch->ADSRX.get<exEnvelopeVol>().value = EnvelopeVol;
    ch->ADSRX.get<exEnvelopeVolFrak>().value = EnvelopeVolFrak;
    ch->ADSRX.get<exVolume>().value = (EnvelopeVol >>= 5);

    return EnvelopeVol;
}

void PCSX::SPU::ADSR::start(SPUCHAN *pChannel)  // MIX ADSR
{
    pChannel->ADSRX.get<exVolume>().value = 1;  // and init some adsr vars
    pChannel->ADSRX.get<exState>().value = ADSRState::Attack;
    pChannel->ADSRX.get<exEnvelopeVol>().value = 0;
    pChannel->ADSRX.get<exEnvelopeVolFrak>().value = 0;
}

int PCSX::SPU::ADSR::mix(SPUCHAN *ch) {
    if (ch->data.get<Chan::Stop>().value) {
        ch->ADSRX.get<exState>().value = ADSRState::Release;
    }

    switch (ch->ADSRX.get<exState>().value) {
        case ADSRState::Attack:
            return Attack(ch);
        case ADSRState::Decay:
            return Decay(ch);
        case ADSRState::Sustain:
            return Sustain(ch);
        case ADSRState::Release:
            return Release(ch);
    }

    return 0;
}
