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

//*************************************************************************//
// History of changes:
//
// 2002/05/15 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#pragma once

#include "spu/externals.h"
#include "spu/types.h"

namespace PCSX {

namespace SPU {

class ADSR {
  public:
    void start(SPUCHAN* pChannel);
    int mix(SPUCHAN* pChannel);
    ADSR() {
        // Pre-calculate ADSR effective rates

        for (int rate = 0; rate <= 47; rate++) {
            denominator[rate] = 1;
            numerator_increase[rate] = (7 - (rate & 3)) << (11 - (rate >> 2));
            numerator_decrease[rate] = (-8 + (rate & 3)) << (11 - (rate >> 2));
        }

        for (int rate = 48; rate <= 127; rate++) {
            denominator[rate] = 1 << ((rate >> 2) - 11);
            numerator_increase[rate] = 7 - (rate & 3);
            numerator_decrease[rate] = -8 + (rate & 3);
        }
    };

  private:
    int32_t denominator[128];
    int32_t numerator_increase[128];
    int32_t numerator_decrease[128];

    int Attack(SPUCHAN* ch);
    int Decay(SPUCHAN* ch);
    int Sustain(SPUCHAN* ch);
    int Release(SPUCHAN* ch);
};

}  // namespace SPU

}  // namespace PCSX
