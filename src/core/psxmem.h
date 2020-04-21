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

#include <vector>

#include "core/psxemulator.h"

#include "core/elfloader.h"

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
    uint8_t *g_psxM = NULL;  // Kernel & User Memory (2 Meg)
    uint8_t *g_psxP = NULL;  // Parallel Port (64K)
    uint8_t *g_psxR = NULL;  // BIOS ROM (512K)
    uint8_t *g_psxH = NULL;  // Scratch Pad (1K) & Hardware Registers (8K)

    uint8_t **g_psxMemWLUT = NULL;
    uint8_t **g_psxMemRLUT = NULL;

    /*  Playstation Memory Map (from Playstation doc by Joshua Walker)
    0x0000_0000-0x0000_ffff     Kernel (64K)
    0x0001_0000-0x001f_ffff     User Memory (1.9 Meg)

    0x1f00_0000-0x1f00_ffff     Parallel Port (64K)

    0x1f80_0000-0x1f80_03ff     Scratch Pad (1024 bytes)

    0x1f80_1000-0x1f80_2fff     Hardware Registers (8K)

    0x1fc0_0000-0x1fc7_ffff     BIOS (512K)

    0x8000_0000-0x801f_ffff     Kernel and User Memory Mirror (2 Meg) Cached
    0x9fc0_0000-0x9fc7_ffff     BIOS Mirror (512K) Cached

    0xa000_0000-0xa01f_ffff     Kernel and User Memory Mirror (2 Meg) Uncached
    0xbfc0_0000-0xbfc7_ffff     BIOS Mirror (512K) Uncached
    */

  public:
#define psxMs8(mem) PCSX::g_emulator.m_psxMem->g_psxM[(mem)&0x1fffff]
#define psxMs16(mem) (SWAP_LE16(*(int16_t *)&PCSX::g_emulator.m_psxMem->g_psxM[(mem)&0x1fffff]))
#define psxMs32(mem) (SWAP_LE32(*(int32_t *)&PCSX::g_emulator.m_psxMem->g_psxM[(mem)&0x1fffff]))
#define psxMu8(mem) (*(uint8_t *)&PCSX::g_emulator.m_psxMem->g_psxM[(mem)&0x1fffff])
#define psxMu16(mem) (SWAP_LE16(*(uint16_t *)&PCSX::g_emulator.m_psxMem->g_psxM[(mem)&0x1fffff]))
#define psxMu32(mem) (SWAP_LE32(*(uint32_t *)&PCSX::g_emulator.m_psxMem->g_psxM[(mem)&0x1fffff]))
#define psxMs8ref(mem) PCSX::g_emulator.m_psxMem->g_psxM[(mem)&0x1fffff]
#define psxMs16ref(mem) (*(int16_t *)&PCSX::g_emulator.m_psxMem->g_psxM[(mem)&0x1fffff])
#define psxMs32ref(mem) (*(int32_t *)&PCSX::g_emulator.m_psxMem->g_psxM[(mem)&0x1fffff])
#define psxMu8ref(mem) (*(uint8_t *)&PCSX::g_emulator.m_psxMem->g_psxM[(mem)&0x1fffff])
#define psxMu16ref(mem) (*(uint16_t *)&PCSX::g_emulator.m_psxMem->g_psxM[(mem)&0x1fffff])
#define psxMu32ref(mem) (*(uint32_t *)&PCSX::g_emulator.m_psxMem->g_psxM[(mem)&0x1fffff])
#define psxPs8(mem) PCSX::g_emulator.m_psxMem->g_psxP[(mem)&0xffff]
#define psxPs16(mem) (SWAP_LE16(*(int16_t *)&PCSX::g_emulator.m_psxMem->g_psxP[(mem)&0xffff]))
#define psxPs32(mem) (SWAP_LE32(*(int32_t *)&PCSX::g_emulator.m_psxMem->g_psxP[(mem)&0xffff]))
#define psxPu8(mem) (*(uint8_t *)&PCSX::g_emulator.m_psxMem->g_psxP[(mem)&0xffff])
#define psxPu16(mem) (SWAP_LE16(*(uint16_t *)&PCSX::g_emulator.m_psxMem->g_psxP[(mem)&0xffff]))
#define psxPu32(mem) (SWAP_LE32(*(uint32_t *)&PCSX::g_emulator.m_psxMem->g_psxP[(mem)&0xffff]))
#define psxPs8ref(mem) PCSX::g_emulator.m_psxMem->g_psxP[(mem)&0xffff]
#define psxPs16ref(mem) (*(int16_t *)&PCSX::g_emulator.m_psxMem->g_psxP[(mem)&0xffff])
#define psxPs32ref(mem) (*(int32_t *)&PCSX::g_emulator.m_psxMem->g_psxP[(mem)&0xffff])
#define psxPu8ref(mem) (*(uint8_t *)&PCSX::g_emulator.m_psxMem->g_psxP[(mem)&0xffff])
#define psxPu16ref(mem) (*(uint16_t *)&PCSX::g_emulator.m_psxMem->g_psxP[(mem)&0xffff])
#define psxPu32ref(mem) (*(uint32_t *)&PCSX::g_emulator.m_psxMem->g_psxP[(mem)&0xffff])
#define psxRs8(mem) PCSX::g_emulator.m_psxMem->g_psxR[(mem)&0x7ffff]
#define psxRs16(mem) (SWAP_LE16(*(int16_t *)&PCSX::g_emulator.m_psxMem->g_psxR[(mem)&0x7ffff]))
#define psxRs32(mem) (SWAP_LE32(*(int32_t *)&PCSX::g_emulator.m_psxMem->g_psxR[(mem)&0x7ffff]))
#define psxRu8(mem) (*(uint8_t *)&PCSX::g_emulator.m_psxMem->g_psxR[(mem)&0x7ffff])
#define psxRu16(mem) (SWAP_LE16(*(uint16_t *)&PCSX::g_emulator.m_psxMem->g_psxR[(mem)&0x7ffff]))
#define psxRu32(mem) (SWAP_LE32(*(uint32_t *)&PCSX::g_emulator.m_psxMem->g_psxR[(mem)&0x7ffff]))
#define psxRs8ref(mem) PCSX::g_emulator.m_psxMem->g_psxR[(mem)&0x7ffff]
#define psxRs16ref(mem) (*(int16_t *)&PCSX::g_emulator.m_psxMem->g_psxR[(mem)&0x7ffff])
#define psxRs32ref(mem) (*(int32_t *)&PCSX::g_emulator.m_psxMem->g_psxR[(mem)&0x7ffff])
#define psxRu8ref(mem) (*(uint8_t *)&PCSX::g_emulator.m_psxMem->g_psxR[(mem)&0x7ffff])
#define psxRu16ref(mem) (*(uint16_t *)&PCSX::g_emulator.m_psxMem->g_psxR[(mem)&0x7ffff])
#define psxRu32ref(mem) (*(uint32_t *)&PCSX::g_emulator.m_psxMem->g_psxR[(mem)&0x7ffff])
#define psxHs8(mem) PCSX::g_emulator.m_psxMem->g_psxH[(mem)&0xffff]
#define psxHs16(mem) (SWAP_LE16(*(int16_t *)&PCSX::g_emulator.m_psxMem->g_psxH[(mem)&0xffff]))
#define psxHs32(mem) (SWAP_LE32(*(int32_t *)&PCSX::g_emulator.m_psxMem->g_psxH[(mem)&0xffff]))
#define psxHu8(mem) (*(uint8_t *)&PCSX::g_emulator.m_psxMem->g_psxH[(mem)&0xffff])
#define psxHu16(mem) (SWAP_LE16(*(uint16_t *)&PCSX::g_emulator.m_psxMem->g_psxH[(mem)&0xffff]))
#define psxHu32(mem) (SWAP_LE32(*(uint32_t *)&PCSX::g_emulator.m_psxMem->g_psxH[(mem)&0xffff]))
#define psxHs8ref(mem) PCSX::g_emulator.m_psxMem->g_psxH[(mem)&0xffff]
#define psxHs16ref(mem) (*(int16_t *)&PCSX::g_emulator.m_psxMem->g_psxH[(mem)&0xffff])
#define psxHs32ref(mem) (*(int32_t *)&PCSX::g_emulator.m_psxMem->g_psxH[(mem)&0xffff])
#define psxHu8ref(mem) (*(uint8_t *)&PCSX::g_emulator.m_psxMem->g_psxH[(mem)&0xffff])
#define psxHu16ref(mem) (*(uint16_t *)&PCSX::g_emulator.m_psxMem->g_psxH[(mem)&0xffff])
#define psxHu32ref(mem) (*(uint32_t *)&PCSX::g_emulator.m_psxMem->g_psxH[(mem)&0xffff])
#define PSXM(mem)                                              \
    (PCSX::g_emulator.m_psxMem->g_psxMemRLUT[(mem) >> 16] == 0 \
         ? NULL                                                \
         : (uint8_t *)(PCSX::g_emulator.m_psxMem->g_psxMemRLUT[(mem) >> 16] + ((mem)&0xffff)))
#define PSXMs8(mem) (*(int8_t *)PSXM(mem))
#define PSXMs16(mem) (SWAP_LE16(*(int16_t *)PSXM(mem)))
#define PSXMs32(mem) (SWAP_LE32(*(int32_t *)PSXM(mem)))
#define PSXMu8(mem) (*(uint8_t *)PSXM(mem))
#define PSXMu16(mem) (SWAP_LE16(*(uint16_t *)PSXM(mem)))
#define PSXMu32(mem) (SWAP_LE32(*(uint32_t *)PSXM(mem)))
#define PSXMu32ref(mem) (*(uint32_t *)PSXM(mem))

    int psxMemInit();
    void psxMemReset();
    void psxMemShutdown();

    uint8_t psxMemRead8(uint32_t mem);
    uint16_t psxMemRead16(uint32_t mem);
    uint32_t psxMemRead32(uint32_t mem);
    void psxMemWrite8(uint32_t mem, uint8_t value);
    void psxMemWrite16(uint32_t mem, uint16_t value);
    void psxMemWrite32(uint32_t mem, uint32_t value);
    void *psxMemPointer(uint32_t mem);

    std::vector<Elf> m_elfs;
};

}  // namespace PCSX
