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

#include "spu/interpolation.h"

#include "spu/gauss.h"
#include "spu/rounding-probe.h"

namespace PCSX::SPU {
// The four-tap gaussian/cubic window is four int16 samples packed into m_state[1]
// and m_state[2], addressed as a ring by the index in m_state[0].
int16_t &PCSX::SPU::Interpolator::gaussWindow(int index) { return reinterpret_cast<int16_t *>(&m_state[1])[index & 3]; }
}  // namespace PCSX::SPU

////////////////////////////////////////////////////////////////////////
// Helpers for simple interpolation.

//
// Easy interpolation on upsampling, with no special filter: the "Pete's common sense" approach.
//
// Instead of having n equal sample values in a row, like:
//       ____
//           |____
//
// we compare the current delta change with the next delta change.
//
// If curr_delta is positive,
//
//  - and the next delta is smaller (or changes direction):
//         \.
//          -__
//
//  - and the next delta is significantly (at least twice) bigger:
//         --_
//            \.
//
//  - and the next delta is nearly the same:
//          \.
//           \.
//
//
// If curr_delta is negative,
//
//  - and the next delta is smaller (or changes direction):
//          _--
//         /
//
//  - and the next delta is significantly (at least twice) bigger:
//            /
//         __-
//
//  - and the next delta is nearly the same:
//           /
//          /
//

void PCSX::SPU::Interpolator::interpolateUp() {
    if (m_state[4] == 1) {
        // Flag 1: calculate the step and set the flag, without changing the value in this pass.
        // Current delta, to the next value.
        const int id1 = m_state[2] - m_state[1];
        // Next delta, to the value after that.
        const int id2 = m_state[3] - m_state[2];

        m_state[4] = 0;

        // Current delta positive.
        if (id1 > 0) {
            if (id2 < id1) {
                m_state[0] = id1;
                m_state[4] = 2;
            } else if (id2 < (id1 << 1))
                m_state[0] = (id1 * m_sinc) / 0x10000L;
            else
                m_state[0] = (id1 * m_sinc) / 0x20000L;
        } else {
            // Current delta negative.
            if (id2 > id1) {
                m_state[0] = id1;
                m_state[4] = 2;
            } else if (id2 > (id1 << 1))
                m_state[0] = (id1 * m_sinc) / 0x10000L;
            else
                m_state[0] = (id1 * m_sinc) / 0x20000L;
        }
    } else if (m_state[4] == 2) {
        // Flag 2: apply the step that the previous pass computed.
        m_state[4] = 0;

        m_state[0] = (m_state[0] * m_sinc) / 0x20000L;
        if (m_sinc <= 0x8000)
            m_state[1] = m_state[2] - (m_state[0] * ((0x10000 / m_sinc) - 1));
        else
            m_state[1] += m_state[0];
    } else
        // No flags: add the bigger value if possible, calculate the smaller step and set flag 1.
        m_state[1] += m_state[0];
}

//
// Even easier interpolation on downsampling, also with no special filter: again the "Pete's common sense" approach.
//

void PCSX::SPU::Interpolator::interpolateDown() {
    // Would we skip at least one value?
    if (m_sinc >= 0x20000L) {
        // Add the easy weight.
        m_state[1] += (m_state[2] - m_state[1]) / 2;
        // Would we skip even more values? Then add the next weight as well.
        if (m_sinc >= 0x30000L) m_state[1] += (m_state[3] - m_state[2]) / 2;
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SPU::Interpolator::storeVal(int fa, int interpolationType, bool isFModSource, bool unmuted) {
    // Frequency modulator source channel.
    if (isFModSource)
        m_state[1] = fa;
    else {
        // A muted voice stores silence; otherwise the sample is clamped.
        if (!unmuted)
            fa = 0;
        else {
            if (fa > 32767L) fa = 32767L;
            if (fa < -32767L) fa = -32767L;
        }

        if (interpolationType >= 2) {
            // Gauss/cubic interpolation.
            int gpos = m_state[0];
            gaussWindow(gpos) = fa;
            gpos = (gpos + 1) & 3;
            m_state[0] = gpos;
        } else if (interpolationType == 1) {
            // Simple interpolation. Helpers for simple linear interpolation: delay the real value for two slots and
            // calculate the two deltas, for a look at the future behavior.
            m_state[0] = 0;
            m_state[1] = m_state[2];
            m_state[2] = m_state[3];
            m_state[3] = fa;
            // Flag a new interpolation calculation.
            m_state[4] = 1;
        } else
            // No interpolation.
            m_state[1] = fa;
    }
}

////////////////////////////////////////////////////////////////////////

int PCSX::SPU::Interpolator::getVal(int interpolationType, bool isFModSource) {
    int fa;

    if (isFModSource) return m_state[1];

    switch (interpolationType) {
        //--------------------------------------------------//
        case 3:  // cubic interpolation
        {
            const int gpos = m_state[0];
            const int64_t xd = (m_spos >> 1) + 1;

            fa = gaussWindow(gpos + 3) - 3 * gaussWindow(gpos + 2) + 3 * gaussWindow(gpos + 1) - gaussWindow(gpos);
            fa *= (xd - (2 << 15)) / 6;
            fa >>= 15;
            fa += gaussWindow(gpos + 2) - gaussWindow(gpos + 1) - gaussWindow(gpos + 1) + gaussWindow(gpos);
            fa *= (xd - (1 << 15)) >> 1;
            fa >>= 15;
            fa += gaussWindow(gpos + 1) - gaussWindow(gpos);
            fa *= xd;
            fa >>= 15;
            fa = fa + gaussWindow(gpos);
        } break;
        //--------------------------------------------------//
        case 2:  // gauss interpolation
        {
            // Hardware-canonical PSX SPU gaussian (no$psx): four taps from the
            // 512-entry gauss512 table indexed by the 8-bit fractional position
            // i = bits 8..15 of the 16.16 pitch counter, each product summed after
            // an individual SAR 15. The window holds oldest..newest at gpos..gpos+3.
            // This replaces Pete Bernert's approximation (per-tap `& ~2047` quantize
            // then `>> 11` over the over-unity SNES-logged table), which ran ~0.4%
            // hot; gauss512's four coefficients sum to ~0x7F80, matching hardware's
            // slight attenuation.
            const int gpos = m_state[0];
            const int i = (m_spos >> 8) & 0xFF;
            const int probe = PCSX::SPU::roundingProbe();
            if (probe & 128) {
                auto &gp = PCSX::SPU::gaussProbe();
                gp.idx = i;
                gp.w0 = gaussWindow(gpos);
                gp.w1 = gaussWindow(gpos + 1);
                gp.w2 = gaussWindow(gpos + 2);
                gp.w3 = gaussWindow(gpos + 3);
                gp.type = 2;
                gp.seq++;
            }
            auto tap = [probe](int c, int smp) -> int {
                const int p = c * smp;
                if (probe & 4) return (p + (1 << 14)) >> 15;  // DIAGNOSTIC round-to-nearest
                if (probe & 8) return p / 32768;              // DIAGNOSTIC truncate toward zero
                return p >> 15;
            };
            if (probe & (16 | 32)) {
                // DIAGNOSTIC: full-precision accumulate, one shift at the end.
                const int64_t acc = int64_t(Gauss::gauss512[0x0FF - i]) * gaussWindow(gpos) +
                                    int64_t(Gauss::gauss512[0x1FF - i]) * gaussWindow(gpos + 1) +
                                    int64_t(Gauss::gauss512[0x100 + i]) * gaussWindow(gpos + 2) +
                                    int64_t(Gauss::gauss512[0x000 + i]) * gaussWindow(gpos + 3);
                fa = int((probe & 32) ? ((acc + (1 << 14)) >> 15) : (acc >> 15));
            } else {
                int vr = tap(Gauss::gauss512[0x0FF - i], gaussWindow(gpos));
                vr += tap(Gauss::gauss512[0x1FF - i], gaussWindow(gpos + 1));
                vr += tap(Gauss::gauss512[0x100 + i], gaussWindow(gpos + 2));
                vr += tap(Gauss::gauss512[0x000 + i], gaussWindow(gpos + 3));
                fa = vr;
            }
        } break;
        //--------------------------------------------------//
        case 1:  // simple interpolation
        {
            // Upsampling, or else downsampling.
            if (m_sinc < 0x10000L)
                interpolateUp();
            else
                interpolateDown();
            fa = m_state[1];
        } break;
        //--------------------------------------------------//
        default:  // no interpolation
        {
            fa = m_state[1];
        } break;
            //--------------------------------------------------//
    }

    return fa;
}
