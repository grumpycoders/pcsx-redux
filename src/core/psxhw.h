/***************************************************************************
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
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

#pragma once

#include "core/psxcounters.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/sio.h"
#include "core/sio1.h"

#define HW_DMA0_MADR (psxHu32ref(0x1080))  // MDEC in DMA
#define HW_DMA0_BCR (psxHu32ref(0x1084))
#define HW_DMA0_CHCR (psxHu32ref(0x1088))

#define HW_DMA1_MADR (psxHu32ref(0x1090))  // MDEC out DMA
#define HW_DMA1_BCR (psxHu32ref(0x1094))
#define HW_DMA1_CHCR (psxHu32ref(0x1098))

#define HW_DMA2_MADR (psxHu32ref(0x10a0))  // GPU DMA
#define HW_DMA2_BCR (psxHu32ref(0x10a4))
#define HW_DMA2_CHCR (psxHu32ref(0x10a8))

#define HW_DMA3_MADR (psxHu32ref(0x10b0))  // CDROM DMA
#define HW_DMA3_BCR (psxHu32ref(0x10b4))
#define HW_DMA3_CHCR (psxHu32ref(0x10b8))

#define HW_DMA4_MADR (psxHu32ref(0x10c0))  // SPU DMA
#define HW_DMA4_BCR (psxHu32ref(0x10c4))
#define HW_DMA4_CHCR (psxHu32ref(0x10c8))

#define HW_DMA6_MADR (psxHu32ref(0x10e0))  // GPU DMA (OT)
#define HW_DMA6_BCR (psxHu32ref(0x10e4))
#define HW_DMA6_CHCR (psxHu32ref(0x10e8))

#define HW_DMA_PCR (psxHu32ref(0x10f0))
#define HW_DMA_ICR (psxHu32ref(0x10f4))

#define DMA_INTERRUPT(n)                            \
    if (SWAP_LEu32(HW_DMA_ICR) & (1 << (16 + n))) { \
        HW_DMA_ICR |= SWAP_LE32(1 << (24 + n));     \
        psxHu32ref(0x1070) |= SWAP_LE32(8);         \
    }

namespace PCSX {

class HW {
  public:
    void reset();
    uint8_t read8(uint32_t add);
    uint16_t read16(uint32_t add);
    uint32_t read32(uint32_t add);
    void write8(uint32_t add, uint32_t rawvalue);
    void write16(uint32_t add, uint32_t rawvalue);
    void write32(uint32_t add, uint32_t value);
    int psxHwFreeze(gzFile f, int Mode);

  private:
    bool s_dmaGpuListHackEn = false;

    void dma0(uint32_t madr, uint32_t bcr, uint32_t chcr);
    void dma1(uint32_t madr, uint32_t bcr, uint32_t chcr);
    void dma2(uint32_t madr, uint32_t bcr, uint32_t chcr);
    void dma3(uint32_t madr, uint32_t bcr, uint32_t chcr);
};

}  // namespace PCSX
