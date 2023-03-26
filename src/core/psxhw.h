/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
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
#include "core/psxdma.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"

namespace PCSX {

class HW {
  public:
    void reset();
    uint8_t read8(uint32_t add);
    uint16_t read16(uint32_t add);
    uint32_t read32(uint32_t add);
    void write8(uint32_t add, uint32_t value);
    void write16(uint32_t add, uint32_t value);
    void write32(uint32_t add, uint32_t value);

  private:
    bool m_dmaGpuListHackEn = false;

    void dma0(uint32_t madr, uint32_t bcr, uint32_t chcr);
    void dma1(uint32_t madr, uint32_t bcr, uint32_t chcr);
    void dma2(uint32_t madr, uint32_t bcr, uint32_t chcr);
    void dma3(uint32_t madr, uint32_t bcr, uint32_t chcr);

    template <unsigned n>
    void dmaExec(uint32_t chcr) {
        auto &mem = g_emulator->m_mem;
        mem->setCHCR<n>(chcr);
        uint32_t pcr = mem->readHardwareRegister<0x10f0>();
        if ((chcr & 0x01000000) && (pcr & (8 << (n * 4)))) {
            uint32_t madr = mem->readHardwareRegister<0x1080 + n * 0x10>();
            uint32_t bcr = mem->readHardwareRegister<0x1084 + n * 0x10>();
            if constexpr (n == 0) {
                dma0(madr, bcr, chcr);
            } else if constexpr (n == 1) {
                dma1(madr, bcr, chcr);
            } else if constexpr (n == 2) {
                dma2(madr, bcr, chcr);
            } else if constexpr (n == 3) {
                dma3(madr, bcr, chcr);
            } else if constexpr (n == 4) {
                dma4(madr, bcr, chcr);
            } else if constexpr (n == 6) {
                dma6(madr, bcr, chcr);
            }
        }
    }
};

}  // namespace PCSX
