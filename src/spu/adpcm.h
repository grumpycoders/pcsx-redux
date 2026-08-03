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

// Self-contained per-voice ADPCM decoder. Owns the decode cursor into sound RAM
// (start/current/loop pointers) and the two-sample IIR decode history, and
// turns a 16-byte ADPCM block into 28 PCM samples. Extracted out of the SPUCHAN
// per-voice struct and the MainThread synthesis loop; the math and the cursor
// bookkeeping are unchanged. The loop/stop flag resolution and the SPU IRQ check
// stay in MainThread, which owns the SPU-wide state they need; this class just
// exposes the cursor so that code can keep driving it.
class AdpcmDecoder {
  public:
    // Key-on: rewind the decode cursor to the sample start and clear the IIR
    // history, exactly as StartSound used to do inline.
    void keyOn() {
        m_curr = m_start;
        m_s1 = 0;
        m_s2 = 0;
    }

    // EXPERIMENTAL: hardware emits a few samples of silence after KEY_ON before
    // the first decoded sample appears. Seed a per-voice countdown at key-on;
    // while it is active the synthesis loop emits silence and freezes decode.
    void setStartupDelay(int samples) { m_startupDelay = samples; }
    bool startupDelayActive() const { return m_startupDelay > 0; }
    void tickStartupDelay() {
        if (m_startupDelay > 0) m_startupDelay--;
    }

    // Clear all decode state (voice wipe).
    void reset() {
        m_start = nullptr;
        m_curr = nullptr;
        m_loop = nullptr;
        m_s1 = 0;
        m_s2 = 0;
    }

    // Cursor sentinel for a voice that decoded a stop/loop-end block with no loop
    // target: the next synthesis pass sees it in the cursor and turns the voice
    // off. It is a deliberately invalid, non-null pointer, distinct from the
    // nullptr "wiped" state. Its exact all-ones bit pattern is what the savestate
    // pointer-offset bridge stores and restores by plain arithmetic, so it must
    // stay all-ones. (Was an inline (uint8_t *)-1 cast smuggled into the cursor.)
    inline static uint8_t *const kStopped = reinterpret_cast<uint8_t *>(~uintptr_t(0));
    bool stopped() const { return m_curr == kStopped; }

    // Decode cursor accessors (raw pointers into sound RAM).
    uint8_t *start() const { return m_start; }
    uint8_t *curr() const { return m_curr; }
    uint8_t *loop() const { return m_loop; }
    void setStart(uint8_t *p) { m_start = p; }
    void setCurr(uint8_t *p) { m_curr = p; }
    void setLoop(uint8_t *p) { m_loop = p; }

    // Savestate bridge (freeze.cc only). Encode/decode this decoder's runtime
    // state - the two-sample IIR history and the three sound-RAM cursors - into
    // the per-channel savestate fields. The fields are passed in rather than the
    // whole channel message because adpcm.h cannot include types.h (it is
    // included by it). `ramBase` is spuRamBase; each cursor is stored as a byte
    // offset, with -1 standing in for a null pointer. The kStopped sentinel is
    // an all-ones (non-null) pointer, so it round-trips as raw offset arithmetic.
    void saveTo(Protobuf::Int32 &history1, Protobuf::Int32 &history2, Protobuf::Int32 &startOffset,
                Protobuf::Int32 &currOffset, Protobuf::Int32 &loopOffset, uint8_t *ramBase,
                Protobuf::Int32 *sb, Protobuf::Int32 &sbPos) const;
    void loadFrom(const Protobuf::Int32 &history1, const Protobuf::Int32 &history2,
                  const Protobuf::Int32 &startOffset, const Protobuf::Int32 &currOffset,
                  const Protobuf::Int32 &loopOffset, uint8_t *ramBase, const Protobuf::Int32 *sb,
                  const Protobuf::Int32 &sbPos);

    struct DecodeResult {
        uint8_t *blockEnd;  // one past the 16-byte block just decoded
        int flags;          // the block's flag byte (loop/repeat/end bits)
    };

    // Decode the 16-byte ADPCM block beginning at `block` into our own 28-sample
    // buffer, advancing the IIR history, and rewind the read cursor to the top of
    // that buffer. The buffer is ours because we are the only thing that fills it;
    // the voice pulls samples back out one at a time. Returns the address just past
    // the block and the block's flag byte, which the caller needs for its IRQ check
    // and loop handling.
    DecodeResult decodeBlock(uint8_t *block);

    static constexpr int kSamplesPerBlock = 28;
    bool bufferExhausted() const { return m_pos >= kSamplesPerBlock; }
    int32_t takeSample() { return m_samples[m_pos++]; }
    // Key-on leaves the buffer empty so the first sample forces a decode.
    void emptyBuffer() { m_pos = kSamplesPerBlock; }

  private:
    // ADPCM IIR filter coefficient pairs, indexed by the block's predictor. The
    // coefficients are Q6 fixed point, so the feedback term is shifted right by 6.
    static constexpr int kFilterCoeff[5][2] = {{0, 0}, {60, 0}, {115, -52}, {98, -55}, {122, -60}};
    static constexpr int kCoeffShift = 6;

    uint8_t *m_start = nullptr;  // start pointer into sound RAM
    uint8_t *m_curr = nullptr;   // current position in sound RAM
    uint8_t *m_loop = nullptr;   // loop pointer into sound RAM
    int32_t m_s1 = 0;            // last decoded sample (IIR history)
    int32_t m_s2 = 0;            // next-to-last decoded sample (IIR history)
    int m_startupDelay = 0;      // EXPERIMENTAL: post-key-on silence countdown (samples)
    int32_t m_samples[kSamplesPerBlock] = {};  // the decoded block
    int m_pos = kSamplesPerBlock;              // read cursor into it
};

}  // namespace SPU

}  // namespace PCSX
