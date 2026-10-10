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

#pragma once

#include <stdint.h>

#include "support/protobuf.h"

namespace PCSX {

namespace SPU {

// Per-voice left/right output volume: the raw register value last written,
// and the current level (VOLXL/VOLXR, -8000h..+7FFFh). In fixed mode the level
// is the decoded register value. In sweep mode it is an envelope stepped once
// per output sample.
//
// The level is kept twice. The mix track is stepped by the SPU thread, one
// sample at a time, and is what the mixer and reverb multiply by. The reader
// track belongs to the CPU thread: it is advanced lazily to the sample clock
// of the access on every register read or write, so a VOLX read answers at
// the reader's cycle rather than wherever the SPU thread's batch loop is.
// Both tracks run the same step function from the same writes.
//
// Note: the PS1's global main L/R volume is not emulated (those register writes
// are logged only, no state is kept), so this type is purely per-voice.
class VoiceVolume {
  public:
    // A left/right volume register write, at SPU sample `nowSample`.
    void setLeft(int16_t raw, uint64_t nowSample) { write(m_left, raw, nowSample); }
    void setRight(int16_t raw, uint64_t nowSample) { write(m_right, raw, nowSample); }

    // SPU thread: advance both sides by one output sample.
    void step() {
        stepTrack(m_left.mix, m_left.raw);
        stepTrack(m_right.mix, m_right.raw);
    }

    // Effective -0x4000..0x3fff volume the mixer and reverb stages apply.
    // Negative means the voice is phase inverted on that side.
    int left() const { return m_left.mix.level >> 1; }
    int right() const { return m_right.mix.level >> 1; }

    // CPU thread: VOLXL/VOLXR at SPU sample `nowSample`.
    uint16_t currentLeft(uint64_t nowSample) { return readAt(m_left, nowSample); }
    uint16_t currentRight(uint64_t nowSample) { return readAt(m_right, nowSample); }

    void reset() {
        m_left = Side{};
        m_right = Side{};
    }

    // Savestate bridge (freeze.cc only). The saved level is the effective one,
    // as before; the sweep sub-sample counter and the reader's sample clock are
    // not saved, so a sweep resumes from the next step boundary after a load.
    void saveTo(Protobuf::Int32 &left, Protobuf::Int32 &right, Protobuf::Int32 &leftRaw,
                Protobuf::Int32 &rightRaw) const {
        left.value = this->left();
        right.value = this->right();
        leftRaw.value = m_left.raw;
        rightRaw.value = m_right.raw;
    }
    void loadFrom(const Protobuf::Int32 &left, const Protobuf::Int32 &right, const Protobuf::Int32 &leftRaw,
                  const Protobuf::Int32 &rightRaw) {
        m_left = Side{};
        m_right = Side{};
        m_left.raw = leftRaw.value;
        m_right.raw = rightRaw.value;
        m_left.mix.level = m_left.reader.level = left.value * 2;
        m_right.mix.level = m_right.reader.level = right.value * 2;
    }

  private:
    struct Track {
        int32_t level = 0;     // current volume, -0x8000..0x7fff
        int32_t fraction = 0;  // samples since the last sweep step
    };
    struct Side {
        uint16_t raw = 0;
        Track mix;
        Track reader;
        uint64_t readerSample = 0;
        bool readerValid = false;
    };

    // Fixed-mode register value to level.
    static int32_t decodeFixed(uint16_t raw);
    // One output sample of the sweep envelope. No-op in fixed mode.
    static void stepTrack(Track &track, uint16_t raw);
    static void advanceReader(Side &side, uint64_t nowSample);
    static void write(Side &side, int16_t raw, uint64_t nowSample);
    static uint16_t readAt(Side &side, uint64_t nowSample);

    Side m_left;
    Side m_right;
};

}  // namespace SPU

}  // namespace PCSX
