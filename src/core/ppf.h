/*  PPF Patch Support for PCSX-Reloaded
 *  Copyright (c) 2009, Wei Mingzhi <whistler_wmz@users.sf.net>.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include <stdint.h>

namespace PCSX {

class PPF {
  public:
    void BuildPPFCache();
    void FreePPFCache();
    void CheckPPFCache(uint8_t *pB, uint8_t m, uint8_t s, uint8_t f);

  private:
    struct PPF_DATA {
        int32_t addr;
        int32_t pos;
        int32_t anz;
        struct PPF_DATA *pNext;
    };

    struct PPF_CACHE {
        int32_t addr;
        struct PPF_DATA *pNext;
    };

    PPF_CACHE *s_ppfCache = NULL;
    PPF_DATA *s_ppfHead = NULL, *s_ppfLast = NULL;
    int s_iPPFNum = 0;

    void FillPPFCache();
    void AddToPPF(int32_t ladr, int32_t pos, int32_t anz, uint8_t *ppfmem);
};

}  // namespace PCSX
