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

#ifndef __PSXMEMORY_H__
#define __PSXMEMORY_H__

#include "core/psxemulator.h"

#if defined(__BIGENDIAN__)

#define _SWAP16(b) ((((unsigned char *)&(b))[0] & 0xff) | (((unsigned char *)&(b))[1] & 0xff) << 8)
#define _SWAP32(b)                                                                      \
    ((((unsigned char *)&(b))[0] & 0xff) | ((((unsigned char *)&(b))[1] & 0xff) << 8) | \
     ((((unsigned char *)&(b))[2] & 0xff) << 16) | (((unsigned char *)&(b))[3] << 24))

#define SWAP16(v) ((((v)&0xff00) >> 8) | (((v)&0xff) << 8))
#define SWAP32(v) ((((v)&0xff000000ul) >> 24) | (((v)&0xff0000ul) >> 8) | (((v)&0xff00ul) << 8) | (((v)&0xfful) << 24))
#define SWAPu32(v) SWAP32((uint32_t)(v))
#define SWAPs32(v) SWAP32((int32_t)(v))

#define SWAPu16(v) SWAP16((uint16_t)(v))
#define SWAPs16(v) SWAP16((int16_t)(v))

#else

#define SWAP16(b) (b)
#define SWAP32(b) (b)

#define SWAPu16(b) (b)
#define SWAPu32(b) (b)

#endif

extern int8_t *g_psxM;
#define psxMs8(mem) g_psxM[(mem)&0x1fffff]
#define psxMs16(mem) (SWAP16(*(int16_t *)&g_psxM[(mem)&0x1fffff]))
#define psxMs32(mem) (SWAP32(*(int32_t *)&g_psxM[(mem)&0x1fffff]))
#define psxMu8(mem) (*(uint8_t *)&g_psxM[(mem)&0x1fffff])
#define psxMu16(mem) (SWAP16(*(uint16_t *)&g_psxM[(mem)&0x1fffff]))
#define psxMu32(mem) (SWAP32(*(uint32_t *)&g_psxM[(mem)&0x1fffff]))

#define psxMs8ref(mem) g_psxM[(mem)&0x1fffff]
#define psxMs16ref(mem) (*(int16_t *)&g_psxM[(mem)&0x1fffff])
#define psxMs32ref(mem) (*(int32_t *)&g_psxM[(mem)&0x1fffff])
#define psxMu8ref(mem) (*(uint8_t *)&g_psxM[(mem)&0x1fffff])
#define psxMu16ref(mem) (*(uint16_t *)&g_psxM[(mem)&0x1fffff])
#define psxMu32ref(mem) (*(uint32_t *)&g_psxM[(mem)&0x1fffff])

extern int8_t *g_psxP;
#define psxPs8(mem) g_psxP[(mem)&0xffff]
#define psxPs16(mem) (SWAP16(*(int16_t *)&g_psxP[(mem)&0xffff]))
#define psxPs32(mem) (SWAP32(*(int32_t *)&g_psxP[(mem)&0xffff]))
#define psxPu8(mem) (*(uint8_t *)&g_psxP[(mem)&0xffff])
#define psxPu16(mem) (SWAP16(*(uint16_t *)&g_psxP[(mem)&0xffff]))
#define psxPu32(mem) (SWAP32(*(uint32_t *)&g_psxP[(mem)&0xffff]))

#define psxPs8ref(mem) g_psxP[(mem)&0xffff]
#define psxPs16ref(mem) (*(int16_t *)&g_psxP[(mem)&0xffff])
#define psxPs32ref(mem) (*(int32_t *)&g_psxP[(mem)&0xffff])
#define psxPu8ref(mem) (*(uint8_t *)&g_psxP[(mem)&0xffff])
#define psxPu16ref(mem) (*(uint16_t *)&g_psxP[(mem)&0xffff])
#define psxPu32ref(mem) (*(uint32_t *)&g_psxP[(mem)&0xffff])

extern int8_t *g_psxR;
#define psxRs8(mem) g_psxR[(mem)&0x7ffff]
#define psxRs16(mem) (SWAP16(*(int16_t *)&g_psxR[(mem)&0x7ffff]))
#define psxRs32(mem) (SWAP32(*(int32_t *)&g_psxR[(mem)&0x7ffff]))
#define psxRu8(mem) (*(uint8_t *)&g_psxR[(mem)&0x7ffff])
#define psxRu16(mem) (SWAP16(*(uint16_t *)&g_psxR[(mem)&0x7ffff]))
#define psxRu32(mem) (SWAP32(*(uint32_t *)&g_psxR[(mem)&0x7ffff]))

#define psxRs8ref(mem) g_psxR[(mem)&0x7ffff]
#define psxRs16ref(mem) (*(int16_t *)&g_psxR[(mem)&0x7ffff])
#define psxRs32ref(mem) (*(int32_t *)&g_psxR[(mem)&0x7ffff])
#define psxRu8ref(mem) (*(uint8_t *)&g_psxR[(mem)&0x7ffff])
#define psxRu16ref(mem) (*(uint16_t *)&g_psxR[(mem)&0x7ffff])
#define psxRu32ref(mem) (*(uint32_t *)&g_psxR[(mem)&0x7ffff])

extern int8_t *g_psxH;
#define psxHs8(mem) g_psxH[(mem)&0xffff]
#define psxHs16(mem) (SWAP16(*(int16_t *)&g_psxH[(mem)&0xffff]))
#define psxHs32(mem) (SWAP32(*(int32_t *)&g_psxH[(mem)&0xffff]))
#define psxHu8(mem) (*(uint8_t *)&g_psxH[(mem)&0xffff])
#define psxHu16(mem) (SWAP16(*(uint16_t *)&g_psxH[(mem)&0xffff]))
#define psxHu32(mem) (SWAP32(*(uint32_t *)&g_psxH[(mem)&0xffff]))

#define psxHs8ref(mem) g_psxH[(mem)&0xffff]
#define psxHs16ref(mem) (*(int16_t *)&g_psxH[(mem)&0xffff])
#define psxHs32ref(mem) (*(int32_t *)&g_psxH[(mem)&0xffff])
#define psxHu8ref(mem) (*(uint8_t *)&g_psxH[(mem)&0xffff])
#define psxHu16ref(mem) (*(uint16_t *)&g_psxH[(mem)&0xffff])
#define psxHu32ref(mem) (*(uint32_t *)&g_psxH[(mem)&0xffff])

extern uint8_t **g_psxMemWLUT;
extern uint8_t **g_psxMemRLUT;

#define PSXM(mem) (g_psxMemRLUT[(mem) >> 16] == 0 ? NULL : (uint8_t *)(g_psxMemRLUT[(mem) >> 16] + ((mem)&0xffff)))
#define PSXMs8(mem) (*(int8_t *)PSXM(mem))
#define PSXMs16(mem) (SWAP16(*(int16_t *)PSXM(mem)))
#define PSXMs32(mem) (SWAP32(*(int32_t *)PSXM(mem)))
#define PSXMu8(mem) (*(uint8_t *)PSXM(mem))
#define PSXMu16(mem) (SWAP16(*(uint16_t *)PSXM(mem)))
#define PSXMu32(mem) (SWAP32(*(uint32_t *)PSXM(mem)))

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

#endif
