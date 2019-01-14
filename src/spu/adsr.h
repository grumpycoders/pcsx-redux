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
    static inline const uint32_t m_tableDisp[] = {
        -0x18 + 0 + 32, -0x18 + 4 + 32,  -0x18 + 6 + 32,  -0x18 + 8 + 32,  // release/decay
        -0x18 + 9 + 32, -0x18 + 10 + 32, -0x18 + 11 + 32, -0x18 + 12 + 32,

        -0x1B + 0 + 32, -0x1B + 4 + 32,  -0x1B + 6 + 32,  -0x1B + 8 + 32,  // sustain
        -0x1B + 9 + 32, -0x1B + 10 + 32, -0x1B + 11 + 32, -0x1B + 12 + 32,
    };

    class Table {
      public:
        Table();
        const uint32_t& operator[](size_t index) const { return m_table[index]; }

      private:
        uint32_t m_table[160];
    };

    const Table m_table;
};

}  // namespace SPU

}  // namespace PCSX
