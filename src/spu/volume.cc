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

namespace {
constexpr int16_t kVolumeMax = 0x3fff;     // effective level is 14 bits
constexpr int16_t kFixedSignBit = 0x4000;  // bit 14: fixed-mode negative phase
}  // namespace

// All arithmetic stays in int16_t on purpose: the sweep approximation below
// relies on the 16-bit wraparound the original peops code produced.
int PCSX::SPU::VoiceVolume::decode(int16_t vol) {
    // Sweep mode.
    if (vol & VolumeFlags::VolumeMode) {
        // Redux does not run the hardware volume sweep envelope. A sweep-mode
        // write is folded into a single raised or lowered fixed level - an
        // approximation faithful to the original model and rarely hit by games.
        const int16_t direction = (vol & VolumeFlags::SweepDirection) ? -1 : 1;
        // Approximated negative phase.
        if (vol & VolumeFlags::SweepPhase) vol ^= 0xffff;
        // Sweep step 0..127 -> 0..64.
        vol = ((vol & 0x7f) + 1) / 2;
        // Shift the level by half.
        vol += vol / (2 * direction);
        vol *= 128;
    } else if (vol & kFixedSignBit) {
        // Fixed mode, negative phase.
        vol = (vol & kVolumeMax) - kFixedSignBit;
    }

    // No mask here. Masking with kVolumeMax would throw away the sign the
    // branch above just reconstructed, turning a quiet phase-inverted voice
    // into a near-full-scale in-phase one. Every other path already lands in
    // range: fixed positive has bits 14 and 15 clear, and the sweep
    // approximation yields 0x3000 or 0x1000.
    return vol;
}
