/***************************************************************************
                       interpolation.c  -  description
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

#include "spu/interpolation.h"

#include "spu/gauss.h"

namespace PCSX::SPU {
// The four-tap gaussian/cubic window is four int16 samples packed into m_state[1]
// and m_state[2], addressed as a ring by the index in m_state[0].
int16_t &PCSX::SPU::Interpolator::gaussWindow(int index) {
    return reinterpret_cast<int16_t *>(&m_state[1])[index & 3];
}
}  // namespace PCSX::SPU

////////////////////////////////////////////////////////////////////////
// helpers for simple interpolation

//
// easy interpolation on upsampling, no special filter, just "Pete's common sense" tm
//
// instead of having n equal sample values in a row like:
//       ____
//           |____
//
// we compare the current delta change with the next delta change.
//
// if curr_delta is positive,
//
//  - and next delta is smaller (or changing direction):
//         \.
//          -__
//
//  - and next delta significant (at least twice) bigger:
//         --_
//            \.
//
//  - and next delta is nearly same:
//          \.
//           \.
//
//
// if curr_delta is negative,
//
//  - and next delta is smaller (or changing direction):
//          _--
//         /
//
//  - and next delta significant (at least twice) bigger:
//            /
//         __-
//
//  - and next delta is nearly same:
//           /
//          /
//

void PCSX::SPU::Interpolator::interpolateUp() {
    if (m_state[4] == 1)  // flag == 1? calc step and set flag... and don't change the value in this pass
    {
        const int id1 = m_state[2] - m_state[1];  // curr delta to next val
        const int id2 = m_state[3] - m_state[2];  // and next delta to next-next val :)

        m_state[4] = 0;

        if (id1 > 0)  // curr delta positive
        {
            if (id2 < id1) {
                m_state[0] = id1;
                m_state[4] = 2;
            } else if (id2 < (id1 << 1))
                m_state[0] = (id1 * m_sinc) / 0x10000L;
            else
                m_state[0] = (id1 * m_sinc) / 0x20000L;
        } else  // curr delta negative
        {
            if (id2 > id1) {
                m_state[0] = id1;
                m_state[4] = 2;
            } else if (id2 > (id1 << 1))
                m_state[0] = (id1 * m_sinc) / 0x10000L;
            else
                m_state[0] = (id1 * m_sinc) / 0x20000L;
        }
    } else if (m_state[4] == 2)  // flag 1: calc step and set flag... and don't change the value in this pass
    {
        m_state[4] = 0;

        m_state[0] = (m_state[0] * m_sinc) / 0x20000L;
        if (m_sinc <= 0x8000)
            m_state[1] = m_state[2] - (m_state[0] * ((0x10000 / m_sinc) - 1));
        else
            m_state[1] += m_state[0];
    } else  // no flags? add bigger val (if possible), calc smaller step, set flag1
        m_state[1] += m_state[0];
}

//
// even easier interpolation on downsampling, also no special filter, again just "Pete's common sense" tm
//

void PCSX::SPU::Interpolator::interpolateDown() {
    if (m_sinc >= 0x20000L)  // we would skip at least one val?
    {
        m_state[1] += (m_state[2] - m_state[1]) / 2;      // add easy weight
        if (m_sinc >= 0x30000L)                                   // we would skip even more vals?
            m_state[1] += (m_state[3] - m_state[2]) / 2;  // add additional next weight
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SPU::Interpolator::storeVal(Protobuf::Int32 *sb, int fa, int interpolationType, int fmod, bool unmuted) {
    if (fmod == 2)  // fmod freq channel
        m_state[1] = fa;
    else {
        if (!unmuted)
            fa = 0;  // muted?
        else         // else adjust
        {
            if (fa > 32767L) fa = 32767L;
            if (fa < -32767L) fa = -32767L;
        }

        if (interpolationType >= 2)  // gauss/cubic interpolation
        {
            int gpos = m_state[0];
            gaussWindow(gpos) = fa;
            gpos = (gpos + 1) & 3;
            m_state[0] = gpos;
        } else if (interpolationType == 1)  // simple interpolation
        {
            m_state[0] = 0;
            m_state[1] = m_state[2];  // -> helpers for simple linear interpolation: delay real val for two slots,
                                          // and calc the two deltas, for a 'look at the future behaviour'
            m_state[2] = m_state[3];
            m_state[3] = fa;
            m_state[4] = 1;  // -> flag: calc new interolation
        } else
            m_state[1] = fa;  // no interpolation
    }
}

////////////////////////////////////////////////////////////////////////

int PCSX::SPU::Interpolator::getVal(Protobuf::Int32 *sb, int interpolationType, int fmod) {
    int fa;

    if (fmod == 2) return m_state[1];

    switch (interpolationType) {
        //--------------------------------------------------//
        case 3:  // cubic interpolation
        {
            const int gpos = m_state[0];
            const int64_t xd = (m_spos >> 1) + 1;

            fa = gaussWindow(gpos + 3) - 3 * gaussWindow(gpos + 2) + 3 * gaussWindow(gpos + 1) -
                 gaussWindow(gpos);
            fa *= (xd - (2 << 15)) / 6;
            fa >>= 15;
            fa += gaussWindow(gpos + 2) - gaussWindow(gpos + 1) - gaussWindow(gpos + 1) +
                  gaussWindow(gpos);
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
            int vr = (Gauss::gauss512[0x0FF - i] * gaussWindow(gpos)) >> 15;
            vr += (Gauss::gauss512[0x1FF - i] * gaussWindow(gpos + 1)) >> 15;
            vr += (Gauss::gauss512[0x100 + i] * gaussWindow(gpos + 2)) >> 15;
            vr += (Gauss::gauss512[0x000 + i] * gaussWindow(gpos + 3)) >> 15;
            fa = vr;
        } break;
        //--------------------------------------------------//
        case 1:  // simple interpolation
        {
            if (m_sinc < 0x10000L)            // -> upsampling?
                interpolateUp();    // --> interpolate up
            else
                interpolateDown();  // --> else down
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
