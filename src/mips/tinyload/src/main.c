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

#include <ps1hwregs.h>
#include <ps1sdk.h>
#include <serialio.h>

#define SIO1_BAUD_DIV (2073600)
#define BAUD_RATE (115200)

static const uint16_t \
    // init with TX and RX enabled.
    def_ctrl =  (SIO_CTRL_RX_EN | SIO_CTRL_TX_EN), 
    /* 8bit, no-parity, 1 stop-bit */
    def_mode = (SIO_MODE_CHLEN_8 | SIO_MODE_P_NONE | SIO_MODE_SB_1 | SIO_MODE_BR_16),
    def_baud = (2073600/BAUD_RATE);

static inline void tl_setup(uint32_t ctrl, uint32_t mode, uint32_t baud)
{
    *R_PS1_SIO1_CTRL = ctrl;
    *R_PS1_SIO1_MODE = mode;
    *R_PS1_SIO1_BAUD = baud;
}

static inline void tl_init(void) { tl_setup(def_ctrl, def_mode, def_baud); }

static inline uint8_t tl_get(void)
{
#ifdef USE_RTR
    *R_PS1_SIO1_CTRL |= SIO_CTRL_RTR_EN;
#endif
    while(!((*R_PS1_SIO1_STAT) & SIO_STAT_RX_RDY));
    uint8_t d = *R_PS1_SIO1_DATA;
#ifdef USE_RTR
    *R_PS1_SIO1_CTRL &= ~(SIO_CTRL_RTR_EN);
#endif
    return d;
}

#ifdef ENHANDED_ERROR
void sio_reset(void) { *R_PS1_SIO1_CTRL = SIO_CTRL_RESET_INT | SIO_CTRL_RESET_ERR; }

// this needs more investigation.
void sio_reset_driver(void) { tl_setup(SIO_CTRL_RESET_INT, 0x0000, 0x0000); }

// I think this is wrong and should be the same as sio_reset().
//void sio_clear_error(void) { *R_PS1_SIO1_CTRL = (SIO_CTRL_RESET_ERR); }

static inline void tl_put(uint8_t d)
{
    volatile uint8_t x;

    if ((*R_PS1_SIO1_STAT) & (SIO_STAT_RX_OVRN_ERR | SIO_STAT_FRAME_ERR | SIO_STAT_PARITY_ERR)) {
        // RX Overrun, Frame Error or Parity Error occured

        // I guess this is to preserve the data that's currently in the TX FIFO?
        x = *R_PS1_SIO1_DATA;

        while ((*R_PS1_SIO1_STAT) & (SIO_STAT_RX_OVRN_ERR | SIO_STAT_FRAME_ERR | SIO_STAT_PARITY_ERR)) {
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

    while (!((*R_PS1_SIO1_STAT) & SIO_STAT_TX_RDY));

    // push the byte into the TX FIFO
    *R_PS1_SIO1_DATA = data;
}
#else
static inline void tl_put(uint8_t d)
{
    while (((*R_PS1_SIO1_STAT) & (SIO_STAT_TX_EMPTY | SIO_STAT_TX_RDY)) != (SIO_STAT_TX_EMPTY | SIO_STAT_TX_RDY));
    *R_PS1_SIO1_DATA = d;
}
#endif

static inline uint16_t tl_get16(void) { return (tl_get() | (tl_get() << 8)); }
static inline uint32_t tl_get32(void) { return (tl_get16() | (tl_get16() << 16)); }

static inline uint16_t tl_put16(uint16_t d) { tl_put(d & 0xFF); tl_put(d >> 8); }
static inline uint16_t tl_put32(uint32_t d) { tl_put16(d & 0xFFFF); tl_put(d >> 16); }

int main(void)
{
    int rv = 1;
    uint32_t load_addr;
    uint32_t load_size;
    uint32_t load_sum;
    uint32_t calc_sum = 0;
    uint8_t d;

    while(rv != 0)
    {
        tl_init(); // (re-) initialize SIO1

        // loop until we get 'P', 'L'
        // when we get a 'P' and another character, we send a response char:
        //  '+': if we got an 'L'
        //  '-': if we got something else
        do
        {
            do { d = tl_get(); } while (d != 'P');
            tl_put((d = tl_get()) == 'L' ? '+' : '-' );
        } while(d != 'L');

        load_addr = tl_get32();
        load_size = tl_get32();
        load_sum = tl_get32();

        for(int i = 0; i < load_size; i++)
        {
            d = tl_get();
            calc_sum += d;
            ((uint8_t *) load_addr)[i] = d;
        }

        calc_sum ^= load_sum;

        // send a '+' if sums match, otherwise send a '!'
        tl_put(calc_sum ? '!' : '+');

        // start over if sums don't match.
        if(calc_sum != 0) continue;

        FlushCache();
        rv = ((int (*)(void)) load_addr)();
    }

end:
#if 1
    while(1);
#endif

    return rv;
}
