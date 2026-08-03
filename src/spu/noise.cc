/***************************************************************************
                          noise.c  -  description
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

#include "spu/noise.h"

namespace {
// The LFSR runs on a 16.16 fixed-point phase accumulator: one output sample
// advances it by one whole unit, plus the fractional step selected by the
// SPUCTRL step bits.
constexpr uint32_t kSampleTick = 0x10000;
constexpr uint32_t kFractionMask = 0xffff;
}  // namespace

int PCSX::SPU::NoiseGenerator::getVal() const {
    return static_cast<int16_t>(m_val);  // noise level = low 16 bits of the LFSR, signed
}

void PCSX::SPU::NoiseGenerator::step() {
    // Dr. Hell's (Xebra) noise model. kWaveform is the precomputed Galois LFSR
    // parity bit fed back in; kFreqStep paces the accumulator from the SPUCTRL
    // step bits (entry 4 is the wrap threshold for the fractional part).
    static constexpr uint8_t kWaveform[64] = {1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1,
                                              1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0,
                                              1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1};
    static constexpr uint16_t kFreqStep[5] = {0, 84, 140, 180, 210};

    const uint32_t shift = m_clock >> 2;       // SPUCTRL noise-shift bits select the LFSR rate
    const uint32_t step = m_clock & 3;         // SPUCTRL noise-step bits select the fractional step
    const uint32_t threshold = (0x8000u >> shift) << 16;

    m_count += kSampleTick + kFreqStep[step];
    if ((m_count & kFractionMask) >= kFreqStep[4]) m_count += kSampleTick - kFreqStep[step];

    if (m_count >= threshold) {
        while (m_count >= threshold) m_count -= threshold;
        m_val = (m_val << 1) | kWaveform[(m_val >> 10) & 63];  // clock the LFSR
    }
}
