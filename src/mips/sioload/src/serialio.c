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

#include <fileio.h>
#include <ps1hwregs.h>
#include <ps1sdk.h>
#include <serialio.h>
#include <stdio.h>

#include "common/hardware/cop0.h"

typedef struct {
    uint32_t inited, mode, ctrl, baud;
} port_config_t;

static port_config_t config = {0, 0, 0, 0};

#define SIO1_BAUD_DIV (2073600)

static inline void sio_set_ctrl_m(uint16_t mask, uint16_t ctrl) {
    *R_PS1_SIO1_CTRL = ((*R_PS1_SIO1_CTRL) & mask) | ctrl;
}

static inline void sio_set_ctrl(uint16_t ctrl) { *R_PS1_SIO1_CTRL = ctrl; }
static inline void sio_set_mode(uint16_t mode) { *R_PS1_SIO1_MODE = (mode & (~3)) | SIO_MODE_BR_16; }
static inline void sio_set_baud(uint32_t baud) { *R_PS1_SIO1_BAUD = SIO1_BAUD_DIV / baud; }

static inline void sio_set_data(uint8_t d) { *R_PS1_SIO1_DATA = d; }

/*
 * the sio_put_xxx functions not only write the value to the register but also update the config value for that register
 */
static inline void sio_put_baud(uint32_t baud) {
    config.baud = baud;
    sio_set_baud(config.baud);
}

static inline void sio_put_ctrl(uint16_t mask, uint16_t ctrl) {
    config.ctrl = ctrl;
    sio_set_ctrl_m(mask, config.ctrl);
}

static inline void sio_put_mode(uint16_t mode) {
    // bits 0 and 1 should always be 0 and 1, respectively
    // this apparently corresponds to "baud rate multiplier 16"
    config.mode = mode;
    sio_set_mode(config.mode);
}

static inline uint16_t sio_get_stat(void) { return *R_PS1_SIO1_STAT & SIO_STAT_MASK; }

static inline uint8_t sio_get_data(void) { return *R_PS1_SIO1_DATA; }

static inline uint16_t sio_get_ctrl(void) {
    uint16_t d = *R_PS1_SIO1_CTRL;
    return
        //(((d >> 5) & 1) << 1) | ((d >> 1) & 1);
        ((d & SIO_CTRL_RTR_EN) >> 4) | ((d & SIO_CTRL_DTR_EN) >> 1);
}

static inline uint16_t sio_get_mode(void) { return *R_PS1_SIO1_MODE & 0x1FFF; }

static inline uint32_t sio_get_baud(void) { return SIO1_BAUD_DIV / (*R_PS1_SIO1_BAUD); }

void sio_reset(void) { *R_PS1_SIO1_CTRL = SIO_CTRL_RESET_INT | SIO_CTRL_RESET_ERR; }

// this needs more investigation.
void sio_reset_driver(void) {
    sio_set_ctrl(SIO_CTRL_RESET_INT);
    sio_set_mode(0x0000);
    sio_set_baud(0x0000);
}

// I think this is wrong and should be the same as sio_reset().
void sio_clear_error(void) { sio_set_ctrl(SIO_CTRL_RESET_ERR); }

// this should probably check STAT for errors.
int sio_peek8(uint32_t timeout) {
    int ret = -1;

    // this may not be necessary. Some UARTs won't transfer if yout don't though.

    // RTR(Ready To Receive akia "RTS"/Request to Send): on
    sio_set_ctrl_m(~(SIO_CTRL_RTR_EN), SIO_CTRL_RTR_EN);

    // wait for data in the RX FIFO

    if (timeout == 0) {
        while (!(sio_get_stat() & SIO_STAT_RX_RDY))
            ;
    } else {
        uint32_t tries = 0;
        while (!(sio_get_stat() & SIO_STAT_RX_RDY)) {
            if (++tries >= timeout) goto _done;
        }
    }

    // pop a byte from the RX FIFO
    ret = *R_PS1_SIO1_DATA;

_done:
    // RTR/RTS: off
    sio_set_ctrl_m(~(SIO_CTRL_RTR_EN), 0);

    return ret;
}

// FIXME: the timeout support is shit.  these functions need to have a way to indicate that a timeout occured.
//  currently sio_peek8 returns a negative value but that's just stupid.

uint16_t sio_peek16(uint32_t timeout) {
    uint16_t d;
    d = sio_peek8(timeout) | (sio_peek8(timeout) << 8);
    return d;
}

uint32_t sio_peek32(uint32_t timeout) {
    uint32_t d;

    d = sio_peek8(timeout) | (sio_peek8(timeout) << 8) | (sio_peek8(timeout) << 16) | (sio_peek8(timeout) << 24);
    return d;
}

// FIXME: add sio_poke16 and 32
int sio_poke8(uint8_t data, uint32_t timeout) {
    volatile uint8_t d;

    if (sio_get_stat() & (SIO_STAT_RX_OVRN_ERR | SIO_STAT_FRAME_ERR | SIO_STAT_PARITY_ERR)) {
        // RX Overrun, Frame Error or Parity Error occured

        // I guess this is to preserve the data that's currently in the TX FIFO?
        d = *R_PS1_SIO1_DATA;

        while (sio_get_stat() & (SIO_STAT_RX_OVRN_ERR | SIO_STAT_FRAME_ERR | SIO_STAT_PARITY_ERR)) {
            // reset the interrupt and error
            sio_reset();

            delay_ms(5);

            // restore the TX FIFO?
            *R_PS1_SIO1_DATA = d;

            // restore mode and ctrl
            sio_set_mode(config.mode);
            sio_set_ctrl(config.ctrl);
        }
    }

    // FIXME: what happens if the CTRL SIO_CTRL_TX_EN isn't set??

    if (timeout == 0) {
        while (!(sio_get_stat() & SIO_STAT_TX_RDY))
            ;
    } else {
        uint32_t tries = 0;
        while (!(sio_get_stat() & SIO_STAT_TX_RDY)) {
            if (++tries >= timeout) return -2;
        }
    }

    // push the byte into the TX FIFO
    *R_PS1_SIO1_DATA = data;
    return data;
}

uint8_t sio_get_byte(void) {
    uint8_t ret;

    // RTR(Ready To Receive akia "RTS"/Request to Send): on
    sio_set_ctrl_m(~(SIO_CTRL_RTR_EN), SIO_CTRL_RTR_EN);

    // wait for data in the RX FIFO

    while (!(sio_get_stat() & SIO_STAT_RX_RDY))
        ;

    // pop a byte from the RX FIFO
    ret = *R_PS1_SIO1_DATA;

_done:
    // RTR/RTS: off
    sio_set_ctrl_m(~(SIO_CTRL_RTR_EN), 0);

    return ret;
}

void sio_put_byte(uint8_t d) {
    while ((sio_get_stat() & (SIO_STAT_TX_EMPTY | SIO_STAT_TX_RDY)) != (SIO_STAT_TX_EMPTY | SIO_STAT_TX_RDY))
        ;
    *R_PS1_SIO1_DATA = d;
}

void init_sio(uint32_t baud) {
    /* 8bit, no-parity, 1 stop-bit */
    sio_put_mode(SIO_MODE_CHLEN_8 | SIO_MODE_P_NONE | SIO_MODE_SB_1);
    sio_put_baud(baud);
    sio_put_ctrl(0, SIO_CTRL_RX_EN | SIO_CTRL_TX_EN);
}
