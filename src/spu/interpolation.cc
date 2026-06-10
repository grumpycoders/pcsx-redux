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
namespace {
// The four-tap gaussian/cubic window is four int16 samples packed into the two
// int32 slots sb[29] and sb[30], addressed as a ring by the index in sb[28].
int16_t &gaussWindow(Protobuf::Int32 *sb, int index) {
    return reinterpret_cast<int16_t *>(&sb[29].value)[index & 3];
}
}  // namespace
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

void PCSX::SPU::Interpolator::interpolateUp(Protobuf::Int32 *sb, int32_t sinc) {
    if (sb[32].value == 1)  // flag == 1? calc step and set flag... and don't change the value in this pass
    {
        const int id1 = sb[30].value - sb[29].value;  // curr delta to next val
        const int id2 = sb[31].value - sb[30].value;  // and next delta to next-next val :)

        sb[32].value = 0;

        if (id1 > 0)  // curr delta positive
        {
            if (id2 < id1) {
                sb[28].value = id1;
                sb[32].value = 2;
            } else if (id2 < (id1 << 1))
                sb[28].value = (id1 * sinc) / 0x10000L;
            else
                sb[28].value = (id1 * sinc) / 0x20000L;
        } else  // curr delta negative
        {
            if (id2 > id1) {
                sb[28].value = id1;
                sb[32].value = 2;
            } else if (id2 > (id1 << 1))
                sb[28].value = (id1 * sinc) / 0x10000L;
            else
                sb[28].value = (id1 * sinc) / 0x20000L;
        }
    } else if (sb[32].value == 2)  // flag 1: calc step and set flag... and don't change the value in this pass
    {
        sb[32].value = 0;

        sb[28].value = (sb[28].value * sinc) / 0x20000L;
        if (sinc <= 0x8000)
            sb[29].value = sb[30].value - (sb[28].value * ((0x10000 / sinc) - 1));
        else
            sb[29].value += sb[28].value;
    } else  // no flags? add bigger val (if possible), calc smaller step, set flag1
        sb[29].value += sb[28].value;
}

//
// even easier interpolation on downsampling, also no special filter, again just "Pete's common sense" tm
//

void PCSX::SPU::Interpolator::interpolateDown(Protobuf::Int32 *sb, int32_t sinc) {
    if (sinc >= 0x20000L)  // we would skip at least one val?
    {
        sb[29].value += (sb[30].value - sb[29].value) / 2;      // add easy weight
        if (sinc >= 0x30000L)                                   // we would skip even more vals?
            sb[29].value += (sb[31].value - sb[30].value) / 2;  // add additional next weight
    }
}

////////////////////////////////////////////////////////////////////////

void PCSX::SPU::Interpolator::storeVal(Protobuf::Int32 *sb, int fa, int interpolationType, int fmod, bool unmuted) {
    if (fmod == 2)  // fmod freq channel
        sb[29].value = fa;
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
            int gpos = sb[28].value;
            gaussWindow(sb, gpos) = fa;
            gpos = (gpos + 1) & 3;
            sb[28].value = gpos;
        } else if (interpolationType == 1)  // simple interpolation
        {
            sb[28].value = 0;
            sb[29].value = sb[30].value;  // -> helpers for simple linear interpolation: delay real val for two slots,
                                          // and calc the two deltas, for a 'look at the future behaviour'
            sb[30].value = sb[31].value;
            sb[31].value = fa;
            sb[32].value = 1;  // -> flag: calc new interolation
        } else
            sb[29].value = fa;  // no interpolation
    }
}

////////////////////////////////////////////////////////////////////////

int PCSX::SPU::Interpolator::getVal(Protobuf::Int32 *sb, int32_t spos, int32_t sinc, int interpolationType, int fmod) {
    int fa;

    if (fmod == 2) return sb[29].value;

    switch (interpolationType) {
        //--------------------------------------------------//
        case 3:  // cubic interpolation
        {
            const int gpos = sb[28].value;
            const int64_t xd = (spos >> 1) + 1;

            fa = gaussWindow(sb, gpos + 3) - 3 * gaussWindow(sb, gpos + 2) + 3 * gaussWindow(sb, gpos + 1) -
                 gaussWindow(sb, gpos);
            fa *= (xd - (2 << 15)) / 6;
            fa >>= 15;
            fa += gaussWindow(sb, gpos + 2) - gaussWindow(sb, gpos + 1) - gaussWindow(sb, gpos + 1) +
                  gaussWindow(sb, gpos);
            fa *= (xd - (1 << 15)) >> 1;
            fa >>= 15;
            fa += gaussWindow(sb, gpos + 1) - gaussWindow(sb, gpos);
            fa *= xd;
            fa >>= 15;
            fa = fa + gaussWindow(sb, gpos);
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
            const int gpos = sb[28].value;
            const int i = (spos >> 8) & 0xFF;
            int vr = (Gauss::gauss512[0x0FF - i] * gaussWindow(sb, gpos)) >> 15;
            vr += (Gauss::gauss512[0x1FF - i] * gaussWindow(sb, gpos + 1)) >> 15;
            vr += (Gauss::gauss512[0x100 + i] * gaussWindow(sb, gpos + 2)) >> 15;
            vr += (Gauss::gauss512[0x000 + i] * gaussWindow(sb, gpos + 3)) >> 15;
            fa = vr;
        } break;
        //--------------------------------------------------//
        case 1:  // simple interpolation
        {
            if (sinc < 0x10000L)            // -> upsampling?
                interpolateUp(sb, sinc);    // --> interpolate up
            else
                interpolateDown(sb, sinc);  // --> else down
            fa = sb[29].value;
        } break;
        //--------------------------------------------------//
        default:  // no interpolation
        {
            fa = sb[29].value;
        } break;
            //--------------------------------------------------//
    }

    return fa;
}
