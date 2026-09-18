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

#include "spu/adsr.h"

#include <stdint.h>

#include <algorithm>

#include "support/table-generator.h"

// The ADSR rate/level model derives from Neill Corlett's PlayStation SPU
// envelope-timing notes; psx-spx (soundprocessingunitspu.md) is the
// authoritative hardware reference. The live envelope level is a 15-bit value
// (0..0x7fff). The volume factor handed to the mixer, and reported by voice
// register 0xC, is that level shifted down to 10 bits (0..0x400).

namespace EnvelopeTables {
// The rate tables are built at compile time (consteval; table math by Nic).
// They encode the classic SPU rate curve whose period doubles every four rate
// steps: a phase counts samples in the fraction accumulator up to
// denominator[rate], then steps the level by numerator_increase[rate] (rising)
// or numerator_decrease[rate] (falling, negative).
struct DenominatorGenerator {
    static consteval int32_t calculateValue(std::size_t rate) { return (rate < 48) ? 1 : (1 << ((rate >> 2) - 11)); }
};

struct NumeratorIncreaseGenerator {
    static consteval int32_t calculateValue(std::size_t rate) {
        return (rate < 48) ? (7 - (rate & 3)) << (11 - (rate >> 2)) : (7 - (rate & 3));
    }
};

struct NumeratorDecreaseGenerator {
    static consteval int32_t calculateValue(std::size_t rate) {
        return (rate < 48) ? (-8 + (rate & 3)) << (11 - (rate >> 2)) : (-8 + (rate & 3));
    }
};

constexpr auto denominator = PCSX::generateTable<128, DenominatorGenerator>();
constexpr auto numerator_increase = PCSX::generateTable<128, NumeratorIncreaseGenerator>();
constexpr auto numerator_decrease = PCSX::generateTable<128, NumeratorDecreaseGenerator>();
}  // namespace EnvelopeTables

namespace {
constexpr int32_t kEnvelopeMax = 0x7fff;       // 15-bit envelope ceiling (32767)
constexpr int kEnvelopeToLevelShift = 5;       // 15-bit level -> 10-bit volume factor
constexpr int32_t kExponentialKnee = 0x6000;   // above here the exponential rise flattens...
constexpr int kExponentialKneeRateStep = 8;    // ...by stepping to a slower rate-table entry
constexpr int kExponentialDecreaseShift = 15;  // Q15 scale for an exponential decrease
constexpr int kCoarseRateScale = 4;            // decay/release rate -> fine rate-table index
constexpr int kSustainLevelShift = 11;         // top four bits of the level...
constexpr int32_t kSustainLevelMask = 0xf;     // ...compared against the 0..15 sustain level
// The attack and sustain rates arrive from the register decode as a full 0..127 (attack is
// (val & 0x7f00) >> 8, sustain is (val & 0x1fc0) >> 6), so the knee's rate-step lands past the
// end of the 128-entry tables on the slowest rates. Saturate instead of reading off the end.
constexpr int kMaxRateIndex = 127;
}  // namespace

// Write the freshly computed envelope state back and return the full 15-bit
// (0..0x7fff) envelope volume. The mixer applies it as `sample * envelope >> 15`,
// matching the hardware SPU. The 0..0x400 `exVolume` mirror (envelope >> 5) is
// still maintained for the voice register / debugger, but it is no longer the
// value handed to the mixer (that lossy 10-bit gain + /1023 divide ran enveloped
// samples ~0.1% high and discarded the envelope's low 5 bits).
int PCSX::SPU::AdsrEnvelope::commit(int32_t envelopeVol, int32_t envelopeVolFraction) {
    const int level = envelopeVol >> kEnvelopeToLevelShift;
    m_adsrx.get<exEnvelopeVol>().value = envelopeVol;
    m_adsrx.get<exEnvelopeVolF>().value = envelopeVolFraction;
    m_adsrx.get<exVolume>().value = level;
    return envelopeVol;
}

int PCSX::SPU::AdsrEnvelope::Attack() {
    int rateIndex = m_adsrx.get<exAttackRate>().value;
    int32_t envelopeVol = m_adsrx.get<exEnvelopeVol>().value;
    int32_t envelopeVolFraction = m_adsrx.get<exEnvelopeVolF>().value;
    const bool exponential = m_adsrx.get<exAttackModeExp>().value != 0;

    // Past the knee the exponential attack curve flattens to a slower rate.
    if (exponential && envelopeVol >= kExponentialKnee) {
        rateIndex = std::min(rateIndex + kExponentialKneeRateStep, kMaxRateIndex);
    }

    if (++envelopeVolFraction >= EnvelopeTables::denominator.data[rateIndex]) {
        envelopeVolFraction = 0;
        envelopeVol += EnvelopeTables::numerator_increase.data[rateIndex];
    }

    if (envelopeVol >= kEnvelopeMax) {
        envelopeVol = kEnvelopeMax;
        m_adsrx.get<exState>().value = ADSRState::Decay;
    }

    return commit(envelopeVol, envelopeVolFraction);
}

int PCSX::SPU::AdsrEnvelope::Decay() {
    const int rateIndex = m_adsrx.get<exDecayRate>().value * kCoarseRateScale;
    int32_t envelopeVol = m_adsrx.get<exEnvelopeVol>().value;
    int32_t envelopeVolFraction = m_adsrx.get<exEnvelopeVolF>().value;
    const bool exponential = m_adsrx.get<exReleaseModeExp>().value != 0;

    if (++envelopeVolFraction >= EnvelopeTables::denominator.data[rateIndex]) {
        envelopeVolFraction = 0;
        envelopeVol += exponential ? (EnvelopeTables::numerator_decrease.data[rateIndex] * envelopeVol) >>
                                         kExponentialDecreaseShift
                                   : EnvelopeTables::numerator_decrease.data[rateIndex];
    }

    envelopeVol = std::max(envelopeVol, 0);

    if (((envelopeVol >> kSustainLevelShift) & kSustainLevelMask) <= m_adsrx.get<exSustainLevel>().value) {
        m_adsrx.get<exState>().value = ADSRState::Sustain;
    }

    return commit(envelopeVol, envelopeVolFraction);
}

int PCSX::SPU::AdsrEnvelope::Sustain() {
    int rateIndex = m_adsrx.get<exSustainRate>().value;
    int32_t envelopeVol = m_adsrx.get<exEnvelopeVol>().value;
    int32_t envelopeVolFraction = m_adsrx.get<exEnvelopeVolF>().value;
    const bool exponential = m_adsrx.get<exSustainModeExp>().value != 0;
    const bool increase = m_adsrx.get<exSustainIncrease>().value != 0;

    if (increase) {
        // Past the knee the exponential rise flattens to a slower rate.
        if (exponential && envelopeVol >= kExponentialKnee) {
            rateIndex = std::min(rateIndex + kExponentialKneeRateStep, kMaxRateIndex);
        }

        if (++envelopeVolFraction >= EnvelopeTables::denominator.data[rateIndex]) {
            envelopeVolFraction = 0;
            envelopeVol += EnvelopeTables::numerator_increase.data[rateIndex];
        }

        envelopeVol = std::min(envelopeVol, kEnvelopeMax);
    } else {
        if (++envelopeVolFraction >= EnvelopeTables::denominator.data[rateIndex]) {
            envelopeVolFraction = 0;
            envelopeVol += exponential ? (EnvelopeTables::numerator_decrease.data[rateIndex] * envelopeVol) >>
                                             kExponentialDecreaseShift
                                       : EnvelopeTables::numerator_decrease.data[rateIndex];
        }

        envelopeVol = std::max(envelopeVol, 0);
    }

    return commit(envelopeVol, envelopeVolFraction);
}

int PCSX::SPU::AdsrEnvelope::Release(bool &channelOn) {
    const int rateIndex = m_adsrx.get<exReleaseRate>().value * kCoarseRateScale;
    int32_t envelopeVol = m_adsrx.get<exEnvelopeVol>().value;
    int32_t envelopeVolFraction = m_adsrx.get<exEnvelopeVolF>().value;
    const bool exponential = m_adsrx.get<exReleaseModeExp>().value != 0;

    if (++envelopeVolFraction >= EnvelopeTables::denominator.data[rateIndex]) {
        envelopeVolFraction = 0;
        envelopeVol += exponential ? (EnvelopeTables::numerator_decrease.data[rateIndex] * envelopeVol) >>
                                         kExponentialDecreaseShift
                                   : EnvelopeTables::numerator_decrease.data[rateIndex];
    }

    if (envelopeVol < 0) {
        m_adsrx.get<exState>().value = ADSRState::Stopped;
        envelopeVol = 0;
        channelOn = false;
    }

    return commit(envelopeVol, envelopeVolFraction);
}

void PCSX::SPU::AdsrEnvelope::keyOn() {
    // Reset the live envelope to the very start of the Attack phase. The level is
    // genuinely zero until the first Attack step lands; ENVX reads it as such.
    m_adsrx.get<exVolume>().value = 0;
    m_adsrx.get<exState>().value = ADSRState::Attack;
    m_adsrx.get<exEnvelopeVol>().value = 0;
    m_adsrx.get<exEnvelopeVolF>().value = 0;
}

int PCSX::SPU::AdsrEnvelope::step(bool stopRequested, bool &channelOn) {
    if (stopRequested) {
        m_adsrx.get<exState>().value = ADSRState::Release;
    }

    switch (m_adsrx.get<exState>().value) {
        case ADSRState::Attack:
            return Attack();
        case ADSRState::Decay:
            return Decay();
        case ADSRState::Sustain:
            return Sustain();
        case ADSRState::Release:
            return Release(channelOn);
    }

    return 0;
}
