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

#include <string_view>
#include <vector>

#include "core/elfloader.h"
#include "core/psxemulator.h"

#if defined(__BIGENDIAN__)

#define SWAP_LE16(v) ((((v)&0xff00) >> 8) | (((v)&0xff) << 8))
#define SWAP_LE32(v) \
    ((((v)&0xff000000ul) >> 24) | (((v)&0xff0000ul) >> 8) | (((v)&0xff00ul) << 8) | (((v)&0xfful) << 24))
#define SWAP_LEu16(v) SWAP_LE16((uint16_t)(v))
#define SWAP_LEu32(v) SWAP_LE32((uint32_t)(v))

#else

#define SWAP_LE16(b) (b)
#define SWAP_LE32(b) (b)
#define SWAP_LEu16(b) (b)
#define SWAP_LEu32(b) (b)

#endif

namespace PCSX {

class Memory {
  public:
    uint8_t *m_psxM = NULL;  // Kernel & User Memory (8 Meg)
    uint8_t *m_psxP = NULL;  // Parallel Port (64K)
    uint8_t *m_psxR = NULL;  // BIOS ROM (512K)
    uint8_t *m_psxH = NULL;  // Scratch Pad (1K) & Hardware Registers (8K)

    uint8_t **m_writeLUT = NULL;
    uint8_t **m_readLUT = NULL;

    // Memory map:
    // https://psx-spx.consoledev.net/memorymap/

  public:
#define psxMs8(mem) PCSX::g_emulator->m_mem->m_psxM[(mem)&0x7fffff]
#define psxMs16(mem) (SWAP_LE16(*(int16_t *)&PCSX::g_emulator->m_mem->m_psxM[(mem)&0x7fffff]))
#define psxMs32(mem) (SWAP_LE32(*(int32_t *)&PCSX::g_emulator->m_mem->m_psxM[(mem)&0x7fffff]))
#define psxMu8(mem) (*(uint8_t *)&PCSX::g_emulator->m_mem->m_psxM[(mem)&0x7fffff])
#define psxMu16(mem) (SWAP_LE16(*(uint16_t *)&PCSX::g_emulator->m_mem->m_psxM[(mem)&0x7fffff]))
#define psxMu32(mem) (SWAP_LE32(*(uint32_t *)&PCSX::g_emulator->m_mem->m_psxM[(mem)&0x7fffff]))
#define psxMs8ref(mem) PCSX::g_emulator->m_mem->m_psxM[(mem)&0x7fffff]
#define psxMs16ref(mem) (*(int16_t *)&PCSX::g_emulator->m_mem->m_psxM[(mem)&0x7fffff])
#define psxMs32ref(mem) (*(int32_t *)&PCSX::g_emulator->m_mem->m_psxM[(mem)&0x7fffff])
#define psxMu8ref(mem) (*(uint8_t *)&PCSX::g_emulator->m_mem->m_psxM[(mem)&0x7fffff])
#define psxMu16ref(mem) (*(uint16_t *)&PCSX::g_emulator->m_mem->m_psxM[(mem)&0x7fffff])
#define psxMu32ref(mem) (*(uint32_t *)&PCSX::g_emulator->m_mem->m_psxM[(mem)&0x7fffff])
#define psxPs8(mem) PCSX::g_emulator->m_mem->m_psxP[(mem)&0xffff]
#define psxPs16(mem) (SWAP_LE16(*(int16_t *)&PCSX::g_emulator->m_mem->m_psxP[(mem)&0xffff]))
#define psxPs32(mem) (SWAP_LE32(*(int32_t *)&PCSX::g_emulator->m_mem->m_psxP[(mem)&0xffff]))
#define psxPu8(mem) (*(uint8_t *)&PCSX::g_emulator->m_mem->m_psxP[(mem)&0xffff])
#define psxPu16(mem) (SWAP_LE16(*(uint16_t *)&PCSX::g_emulator->m_mem->m_psxP[(mem)&0xffff]))
#define psxPu32(mem) (SWAP_LE32(*(uint32_t *)&PCSX::g_emulator->m_mem->m_psxP[(mem)&0xffff]))
#define psxPs8ref(mem) PCSX::g_emulator->m_mem->m_psxP[(mem)&0xffff]
#define psxPs16ref(mem) (*(int16_t *)&PCSX::g_emulator->m_mem->m_psxP[(mem)&0xffff])
#define psxPs32ref(mem) (*(int32_t *)&PCSX::g_emulator->m_mem->m_psxP[(mem)&0xffff])
#define psxPu8ref(mem) (*(uint8_t *)&PCSX::g_emulator->m_mem->m_psxP[(mem)&0xffff])
#define psxPu16ref(mem) (*(uint16_t *)&PCSX::g_emulator->m_mem->m_psxP[(mem)&0xffff])
#define psxPu32ref(mem) (*(uint32_t *)&PCSX::g_emulator->m_mem->m_psxP[(mem)&0xffff])
#define psxRs8(mem) PCSX::g_emulator->m_mem->m_psxR[(mem)&0x7ffff]
#define psxRs16(mem) (SWAP_LE16(*(int16_t *)&PCSX::g_emulator->m_mem->m_psxR[(mem)&0x7ffff]))
#define psxRs32(mem) (SWAP_LE32(*(int32_t *)&PCSX::g_emulator->m_mem->m_psxR[(mem)&0x7ffff]))
#define psxRu8(mem) (*(uint8_t *)&PCSX::g_emulator->m_mem->m_psxR[(mem)&0x7ffff])
#define psxRu16(mem) (SWAP_LE16(*(uint16_t *)&PCSX::g_emulator->m_mem->m_psxR[(mem)&0x7ffff]))
#define psxRu32(mem) (SWAP_LE32(*(uint32_t *)&PCSX::g_emulator->m_mem->m_psxR[(mem)&0x7ffff]))
#define psxRs8ref(mem) PCSX::g_emulator->m_mem->m_psxR[(mem)&0x7ffff]
#define psxRs16ref(mem) (*(int16_t *)&PCSX::g_emulator->m_mem->m_psxR[(mem)&0x7ffff])
#define psxRs32ref(mem) (*(int32_t *)&PCSX::g_emulator->m_mem->m_psxR[(mem)&0x7ffff])
#define psxRu8ref(mem) (*(uint8_t *)&PCSX::g_emulator->m_mem->m_psxR[(mem)&0x7ffff])
#define psxRu16ref(mem) (*(uint16_t *)&PCSX::g_emulator->m_mem->m_psxR[(mem)&0x7ffff])
#define psxRu32ref(mem) (*(uint32_t *)&PCSX::g_emulator->m_mem->m_psxR[(mem)&0x7ffff])
#define psxHs8(mem) PCSX::g_emulator->m_mem->m_psxH[(mem)&0xffff]
#define psxHs16(mem) (SWAP_LE16(*(int16_t *)&PCSX::g_emulator->m_mem->m_psxH[(mem)&0xffff]))
#define psxHs32(mem) (SWAP_LE32(*(int32_t *)&PCSX::g_emulator->m_mem->m_psxH[(mem)&0xffff]))
#define psxHu8(mem) (*(uint8_t *)&PCSX::g_emulator->m_mem->m_psxH[(mem)&0xffff])
#define psxHu16(mem) (SWAP_LE16(*(uint16_t *)&PCSX::g_emulator->m_mem->m_psxH[(mem)&0xffff]))
#define psxHu32(mem) (SWAP_LE32(*(uint32_t *)&PCSX::g_emulator->m_mem->m_psxH[(mem)&0xffff]))
#define psxHs8ref(mem) PCSX::g_emulator->m_mem->m_psxH[(mem)&0xffff]
#define psxHs16ref(mem) (*(int16_t *)&PCSX::g_emulator->m_mem->m_psxH[(mem)&0xffff])
#define psxHs32ref(mem) (*(int32_t *)&PCSX::g_emulator->m_mem->m_psxH[(mem)&0xffff])
#define psxHu8ref(mem) (*(uint8_t *)&PCSX::g_emulator->m_mem->m_psxH[(mem)&0xffff])
#define psxHu16ref(mem) (*(uint16_t *)&PCSX::g_emulator->m_mem->m_psxH[(mem)&0xffff])
#define psxHu32ref(mem) (*(uint32_t *)&PCSX::g_emulator->m_mem->m_psxH[(mem)&0xffff])
#define PSXM(mem)                                         \
    (PCSX::g_emulator->m_mem->m_readLUT[(mem) >> 16] == 0 \
         ? NULL                                           \
         : (uint8_t *)(PCSX::g_emulator->m_mem->m_readLUT[(mem) >> 16] + ((mem)&0xffff)))
#define PSXS(mem) (mem ? (const char *)PSXM(mem) : "<NULL>")
#define PSXMs8(mem) (*(int8_t *)PSXM(mem))
#define PSXMs16(mem) (SWAP_LE16(*(int16_t *)PSXM(mem)))
#define PSXMs32(mem) (SWAP_LE32(*(int32_t *)PSXM(mem)))
#define PSXMu8(mem) (*(uint8_t *)PSXM(mem))
#define PSXMu16(mem) (SWAP_LE16(*(uint16_t *)PSXM(mem)))
#define PSXMu32(mem) (SWAP_LE32(*(uint32_t *)PSXM(mem)))
#define PSXMu32ref(mem) (*(uint32_t *)PSXM(mem))

    int init();
    void reset();
    void shutdown();

    uint8_t read8(uint32_t address);
    uint16_t read16(uint32_t address);
    uint32_t read32(uint32_t address);
    void write8(uint32_t address, uint32_t value);
    void write16(uint32_t address, uint32_t value);
    void write32(uint32_t address, uint32_t value);
    const void *pointerRead(uint32_t address);
    const void *pointerWrite(uint32_t address, int size);

    void setLuts();

    const std::vector<Elf> getElves() const { return m_elfs; }
    uint32_t getBiosAdler32() { return m_biosAdler32; }
    std::string_view getBiosVersionString();

  private:
    std::vector<Elf> m_elfs;
    int m_writeok = 1;
    uint32_t m_biosAdler32 = 0;
};

}  // namespace PCSX
