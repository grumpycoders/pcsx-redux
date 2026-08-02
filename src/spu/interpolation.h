/***************************************************************************
                       interpolation.h  -  description
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

namespace PCSX {

namespace SPU {

// Self-contained per-voice resampler. Takes the freshly decoded ADPCM samples
// plus the fractional pitch position and produces one output sample at the
// emulator's 44.1kHz mixing rate, in one of four modes (none / "Pete's common
// sense" linear / hardware-accurate gaussian / cubic). Extracted out of the
// MainThread synthesis loop and the SPU impl; the math is unchanged.
//
// The working set is five int32 slots that the two mode families alias
// differently: gauss/cubic pack a four-tap int16 window into m_state[1] and
// m_state[2] and use m_state[0] as the ring index, while the linear modes use
// m_state[0] as the step, m_state[1..3] as delay slots and m_state[4] as a
// recompute flag. That overlap is deliberate, which is why they stay one block
// rather than becoming five named members.
//
// The slots used to live in the tail of the per-voice sample buffer, SB[28..32],
// so that the whole thing serialized as one savestate field. They are members
// now and saveTo()/loadFrom() mirror them back into those same SB indices, so
// the savestate format is unchanged; storeVal()/getVal() still take the decoded
// sample window as a raw `Protobuf::Int32 *sb` to avoid a types.h include cycle,
// exactly as the ADPCM decoder does.
class Interpolator {
  public:
    // Key-on: clear the interpolation window and seed the fractional pitch
    // position `spos` (which lives in the channel) for the active mode, exactly
    // as StartSound used to do inline. Gauss/cubic start further ahead so the
    // four-tap window is primed before the first output sample.
    void keyOn(int32_t *spos, int interpolationType) {
        m_state[1] = 0;  // init our interpolation helpers
        m_state[2] = 0;

        if (interpolationType >= 2)  // gauss/cubic interpolation?
        {
            *spos = 0x30000L;
            m_state[0] = 0;
        }  // -> start with more decoding
        else {
            *spos = 0x10000L;
            m_state[3] = 0;
        }  // -> no/simple interpolation starts with one 44100 decoding
    }

    // A psx-pitch change happened: in simple-interpolation mode, flag that the
    // step must be recomputed on the next pass.
    void onFrequencyChanged(int interpolationType) {
        if (interpolationType == 1) m_state[4] = 1;
    }

    // Store one freshly decoded sample `fa` into the interpolation window so a
    // later getVal() can weight it. `fmod` is the channel's freq-mod mode (2 =
    // frequency-modulator source channel), `unmuted` is the SPU-wide unmute
    // control bit.
    void storeVal(Protobuf::Int32 *sb, int fa, int interpolationType, int fmod, bool unmuted);

    // Produce one resampled output sample for the current fractional pitch
    // position `spos` (gauss/cubic) / pitch increment `sinc` (linear).
    int getVal(Protobuf::Int32 *sb, int32_t spos, int32_t sinc, int interpolationType, int fmod);

    // Savestate mirrors: the slots ride in SB[28..32] on the wire, where they
    // used to live, so old states keep loading.
    void saveTo(Protobuf::Int32 *sb) const {
        for (int i = 0; i < kStateSlots; i++) sb[28 + i].value = m_state[i];
    }
    void loadFrom(const Protobuf::Int32 *sb) {
        for (int i = 0; i < kStateSlots; i++) m_state[i] = sb[28 + i].value;
    }

    // Post-load fixup: clear the slot the two mode families disagree about, so a
    // state saved under one interpolation mode cannot feed a garbage ring index
    // or step to another. Was "fix to prevent new interpolations from crashing".
    void resetAfterLoad() { m_state[0] = 0; }

  private:
    static constexpr int kStateSlots = 5;

    int16_t &gaussWindow(int index);
    void interpolateUp(int32_t sinc);
    void interpolateDown(int32_t sinc);

    int32_t m_state[kStateSlots] = {};
};

}  // namespace SPU

}  // namespace PCSX
