/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include "pshitty.h"

#define FTFA_BASE_ADDR (0x1F600000)
#define FTFB_BASE_ADDR (0x1F600002)

#define FTF_BASE_ADDRS(__fn) ((((__fn) & 1) == 0) ? FTFA_BASE_ADDR : FTFB_BASE_ADDR)

#define FTFA_REGS (((volatile uint8_t *) FTFA_BASE_ADDR)
#define FTFB_REGS (((volatile uint8_t *) FTFB_BASE_ADDR)

#define FTFx_REGS(__fn) (((volatile uint8_t *) FTF_BASE_ADDRS(__fn)))

enum { FTFA = 0, FTFB = 1 };

void ftfifo_init(int fn)
{
    // TODO: synch with the PC to ensure buffers are clear of garbage from previous transfers or whatever.
    
}

// get 1 byte from FT FIFO
uint8_t ftfifo_get(int fn)
{
    // wait for the RX FIFO to had data
    while((FTFA_REGS[1] & FTF_STAT_RX_RDY) == 0);
    // read a byte from the RX FIFO
    return FTFA_REGS[0];
}

// send 1 byte to FT FIFO
void ftfifo_put(int fn, uint8_t d)
{
    // wait for the TX FIFO to be ready to accept data
    while((FTFA_REGS[1] & FTF_STAT_TX_RDY) == 0);
    // write a byte to the TX FIFO
    FTFA_REGS[0] = d;
}

uint16_t ftfifo_get16(void) { return (ftfifo_get() | (ftfifo_get() << 8)); }
uint32_t ftfifo_get32(void) { return (ftfifo_get16() | (ftfifo_get16() << 16)); }

void ftfifo_put16(uint16_t d) { ftfifo_put(d & 0xFF); ftfifo_put(d >> 8); }
void ftfifo_put32(uint32_t d) { ftfifo_put16(d & 0xFFFF); ftfifo_put16(d >> 16); }
