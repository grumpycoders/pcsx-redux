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

  private:
    struct ADSRState {
        enum : int32_t {
            Attack = 0,
            Decay = 1,
            Sustain = 2,
            Release = 3,
            Stopped = 4,
        };
    };

    int Attack(SPUCHAN* ch);
    int Decay(SPUCHAN* ch);
    int Sustain(SPUCHAN* ch);
    int Release(SPUCHAN* ch);
};

}  // namespace SPU

}  // namespace PCSX
