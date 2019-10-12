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

// un-comment this to use some error recovery stuff.
//#define ENHANCED_ERROR

// un-comment this to use RTS/CTS flow control
//#define USE_RTSCTS

#ifdef USE_RTSCTS
#define RTR_ON() { *R_PS1_SIO1_CTRL |= SIO_CTRL_RTR_EN;} }
#define RTR_OFF() { *R_PS1_SIO1_CTRL &= ~(SIO_CTRL_RTR_EN); }
#else
#define RTR_ON(){}
#define RTR_OFF(){}
#endif

#define SIO1_BAUD_DIV (2073600)
#define BAUD_RATE (57600)

#define SIO1_RX_Ready() (((*R_PS1_SIO1_STAT) & SIO_STAT_RX_RDY) != 0)

#define SIO1_TX_Ready() (((*R_PS1_SIO1_STAT) & (SIO_STAT_TX_EMPTY | SIO_STAT_TX_RDY)) == (SIO_STAT_TX_EMPTY | SIO_STAT_TX_RDY))

// true if RX Overrun, Frame Error or Parity Error occured
// otherwise false
#define SIO1_Err() (((*R_PS1_SIO1_STAT) & (SIO_STAT_RX_OVRN_ERR | SIO_STAT_FRAME_ERR | SIO_STAT_PARITY_ERR)) != 0)

// these are the default values for the corresponding registers
static const uint16_t
    // init with TX and RX enabled.
    def_ctrl =  (SIO_CTRL_RX_EN | SIO_CTRL_TX_EN), 
    /* 8bit, no-parity, 1 stop-bit */
    def_mode = (SIO_MODE_CHLEN_8 | SIO_MODE_P_NONE | SIO_MODE_SB_1 | SIO_MODE_BR_16),
    def_baud = (2073600/BAUD_RATE);

static inline void psio_setup(uint32_t ctrl, uint32_t mode, uint32_t baud)
{
    *R_PS1_SIO1_CTRL = ctrl;
    *R_PS1_SIO1_MODE = mode;
    *R_PS1_SIO1_BAUD = baud;
}

// sets the SIO1 registers to their default values
void psio_init(void) { psio_setup(def_ctrl, def_mode, def_baud); }

// get 1 byte from SIO1 RX FIFO
uint8_t psio_get(void)
{
    RTR_ON();
    while(!SIO1_RX_Ready());
    uint8_t d = *R_PS1_SIO1_DATA;
    RTR_OFF();
    return d;
}

void sio_reset(void) { *R_PS1_SIO1_CTRL = SIO_CTRL_RESET_INT | SIO_CTRL_RESET_ERR; }

// this needs more investigation.
void sio_reset_driver(void) { psio_setup(SIO_CTRL_RESET_INT, 0x0000, 0x0000); }

// I think this is wrong and should be the same as sio_reset().
//void sio_clear_error(void) { *R_PS1_SIO1_CTRL = (SIO_CTRL_RESET_ERR); }

void psio_put(uint8_t d)
{
#ifdef ENHANCED_ERROR
    volatile uint8_t x;

    if (SIO1_Err()) {

        // I guess this is to preserve the data that's currently in the TX FIFO?
        x = *R_PS1_SIO1_DATA;

        while (SIO1_Err()) {
            // reset the interrupt and error
            sio_reset();

            delay_ms(5);

            // restore the TX FIFO?
            *R_PS1_SIO1_DATA = x;

            // restore mode and ctrl
            *R_PS1_SIO1_MODE = (def_mode);
            *R_PS1_SIO1_CTRL = (def_ctrl);
        }
    }
#endif
    while(!SIO1_TX_Ready());
//    while (((*R_PS1_SIO1_STAT) & (SIO_STAT_TX_EMPTY | SIO_STAT_TX_RDY)) != (SIO_STAT_TX_EMPTY | SIO_STAT_TX_RDY));

    // push the byte into the TX FIFO
    *R_PS1_SIO1_DATA = d;
}

uint16_t psio_get16(void) { return (psio_get() | (psio_get() << 8)); }
uint32_t psio_get32(void) { return (psio_get16() | (psio_get16() << 16)); }

void psio_put16(uint16_t d) { psio_put(d & 0xFF); psio_put(d >> 8); }
void psio_put32(uint32_t d) { psio_put16(d & 0xFFFF); psio_put16(d >> 16); }
