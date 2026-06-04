/***************************************************************************
                           adsr.h  -  description
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

#pragma once

#include <stdint.h>

#include "support/protobuf.h"
#include "support/typestring-wrapper.h"  // for the TYPESTRING() macro used below

namespace PCSX {

namespace SPU {

// ADSR INFOS PER CHANNEL
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("attack_mode_exp"), 1> AttackModeExp;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("attack_time"), 2> AttackTime;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("decay_time"), 3> DecayTime;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("sustain_level"), 4> SustainLevel;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("sustain_mode_exp"), 5> SustainModeExp;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("sustain_mode_dec"), 6> SustainModeDec;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("sustain_time"), 7> SustainTime;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("release_mode_exp"), 8> ReleaseModeExp;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("release_val"), 9> ReleaseVal;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("release_time"), 10> ReleaseTime;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("release_start_time"), 11> ReleaseStartTime;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("release_vol"), 12> ReleaseVol;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("time"), 13> lTime;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("volume"), 14> lVolume;
typedef Protobuf::Message<TYPESTRING("ADSRInfo"), AttackModeExp, AttackTime, DecayTime, SustainLevel, SustainModeExp,
                          SustainModeDec, SustainTime, ReleaseModeExp, ReleaseVal, ReleaseTime, ReleaseStartTime,
                          ReleaseVol, lTime, lVolume>
    ADSRInfo;

typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("state"), 1> exState;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("attack_mode_exp"), 2> exAttackModeExp;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("attack_rate"), 3> exAttackRate;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("decay_rate"), 4> exDecayRate;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("sustain_level"), 5> exSustainLevel;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("sustain_mode_exp"), 6> exSustainModeExp;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("sustain_increase"), 7> exSustainIncrease;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("sustain_rate"), 8> exSustainRate;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("release_mode_exp"), 9> exReleaseModeExp;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("release_rate"), 10> exReleaseRate;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("envelope_vol"), 11> exEnvelopeVol;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("volume"), 12> exVolume;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("envelope_vol_fraction"), 13> exEnvelopeVolF;

typedef Protobuf::Message<TYPESTRING("ADSRInfoEx"), exState, exAttackModeExp, exAttackRate, exDecayRate, exSustainLevel,
                          exSustainModeExp, exSustainIncrease, exSustainRate, exReleaseModeExp, exReleaseRate,
                          exEnvelopeVol, exVolume, exEnvelopeVolF>
    ADSRInfoEx;

// Self-contained per-voice ADSR envelope. Owns the envelope state (the active
// ADSRInfo plus the live ADSRInfoEx) and the four-phase attack/decay/sustain/
// release state machine. Extracted out of the SPUCHAN per-voice struct and the
// MainThread synthesis loop; the math and timing are unchanged.
class AdsrEnvelope {
  public:
    // Key-on: reset the live envelope to the start of the Attack phase.
    void keyOn();

    // Advance the envelope by one sample and return the full 15-bit (0..0x7fff)
    // envelope volume, which the mixer applies as `sample * envelope >> 15`
    // (hardware-accurate). stopRequested mirrors the voice's key-off/Stop flag and
    // forces the Release phase; channelOn is cleared once Release runs the envelope
    // down to zero (i.e. the voice has finished playing).
    int step(bool stopRequested, bool& channelOn);

    // Current 0..0x400 volume factor (envelope_vol >> 5) mirror, as last produced
    // by step(). Reported by the voice register / debugger, not used by the mixer.
    int currentLevel() const { return m_adsrx.get<exVolume>().value; }

    // Clear all envelope state (voice wipe).
    void reset() {
        m_adsr.reset();
        m_adsrx.reset();
    }

    // Access to the protobuf-backed envelope state for register decode, the
    // debugger UI, and savestate serialization.
    ADSRInfo &legacy() { return m_adsr; }
    const ADSRInfo &legacy() const { return m_adsr; }
    ADSRInfoEx &ex() { return m_adsrx; }
    const ADSRInfoEx &ex() const { return m_adsrx; }

  private:
    struct ADSRState {
        enum : int32_t {
            Attack = 0,
            Decay = 1,
            Sustain = 2,
            Release = 3,
            Stopped = 4,
        };
    };

    int Attack();
    int Decay();
    int Sustain();
    int Release(bool &channelOn);

    // Store the freshly computed envelope state and return the 0..0x400 factor.
    int commit(int32_t envelopeVol, int32_t envelopeVolFraction);

    ADSRInfo m_adsr;     // active ADSR settings (legacy/debug; still serialized)
    ADSRInfoEx m_adsrx;  // next/live ADSR envelope state
};

}  // namespace SPU

}  // namespace PCSX
