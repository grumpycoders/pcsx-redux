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

#include "spu/volume.h"

#include <algorithm>

namespace {
constexpr uint16_t kSweepMode = 1 << 15;         // 15 1=Sweep Mode
constexpr uint16_t kSweepExponential = 1 << 14;  // 14 0=Linear, 1=Exponential
constexpr uint16_t kSweepDecrease = 1 << 13;     // 13 0=Increase, 1=Decrease
constexpr uint16_t kSweepNegative = 1 << 12;     // 12 0=Positive, 1=Negative phase
constexpr int32_t kLevelMin = -0x8000;
constexpr int32_t kLevelMax = 0x7fff;
constexpr int32_t kExponentialKnee = 0x6000;
// A read long after the last access walks the gap one sample at a time. Past
// this many samples (about 95s) every sweep has long since settled.
constexpr uint64_t kMaxReaderWalk = 1u << 22;
}  // namespace

// Fixed mode: bits 0-14 are the level/2, bit 14 the sign.
int32_t PCSX::SPU::VoiceVolume::decodeFixed(uint16_t raw) {
    int32_t v = raw & 0x7fff;
    if (v & 0x4000) v -= 0x8000;
    return v * 2;
}

// The sweep steps at the ADSR envelope's rate for the same shift: on silicon,
// shift 12 adds +7 every other sample, shift 16 every 32nd sample, and shift
// 13 step 3 adds +4 every 4th sample. The exponential increase slows by 4
// above 6000h like an ADSR exponential attack. Exponential decrease ignores the phase bit: the step is
// -(8-step)*level>>15, which parks a negative level at -0FFFh where the scaled
// step rounds to zero. Below shift 12 only shift 4 was checked on silicon
// (it saturates within 512 samples); the rest follow the ADSR rule.
void PCSX::SPU::VoiceVolume::stepTrack(Track &track, uint16_t raw) {
    if (!(raw & kSweepMode)) return;
    const bool exponential = raw & kSweepExponential;
    const bool decrease = raw & kSweepDecrease;
    const bool negative = raw & kSweepNegative;
    int shift = (raw >> 2) & 31;
    const int step = raw & 3;
    // An all-ones rate never steps.
    if (shift == 31 && step == 3) return;

    int32_t level = track.level;
    if (exponential && !decrease && level >= kExponentialKnee) shift += 2;
    const int32_t interval = shift > 11 ? 1 << (shift - 11) : 1;
    int32_t delta = (decrease != negative) ? -8 + step : 7 - step;
    if (exponential && decrease) delta = -8 + step;
    if (shift < 11) delta *= 1 << (11 - shift);

    if (++track.fraction < interval) return;
    track.fraction = 0;

    if (exponential && decrease) delta = (delta * level) >> 15;
    level += delta;
    if (!decrease) {
        level = std::clamp(level, kLevelMin, kLevelMax);
    } else if (negative) {
        level = std::clamp(level, kLevelMin, 0);
    } else {
        level = std::clamp(level, 0, kLevelMax);
    }
    track.level = level;
}

void PCSX::SPU::VoiceVolume::advanceReader(Side &side, uint64_t nowSample) {
    if (!side.readerValid || nowSample < side.readerSample) {
        side.reader = side.mix;
        side.readerSample = nowSample;
        side.readerValid = true;
        return;
    }
    const uint64_t gap = std::min(nowSample - side.readerSample, kMaxReaderWalk);
    if (side.raw & kSweepMode) {
        for (uint64_t i = 0; i < gap; i++) stepTrack(side.reader, side.raw);
    }
    side.readerSample = nowSample;
}

void PCSX::SPU::VoiceVolume::write(Side &side, int16_t raw, uint64_t nowSample) {
    advanceReader(side, nowSample);
    side.raw = static_cast<uint16_t>(raw);
    if (side.raw & kSweepMode) {
        // A sweep starts from the current level.
        side.mix.fraction = 0;
        side.reader.fraction = 0;
    } else {
        side.mix = side.reader = Track{decodeFixed(side.raw), 0};
    }
}

uint16_t PCSX::SPU::VoiceVolume::readAt(Side &side, uint64_t nowSample) {
    advanceReader(side, nowSample);
    return static_cast<uint16_t>(side.reader.level);
}
