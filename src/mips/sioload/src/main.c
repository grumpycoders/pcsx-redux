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

static port_config_t config;

#define SIO1_BAUD_DIV (2073600)
// I don't understand this... PsyQ says "bps must be in the range 9600 - 2073600 and evenly divisible into 2073600"
// but reversing libsio shows 2116800 being divided by baud, not 2073600??
//#define SIO1_BAUD_DIV (2116800)

#define SIO_RESET() (*R_PS1_SIO1_CTRL = SIO_CTRL_RESET_INT | SIO_CTRL_RESET_ERR)

static inline void sio_put_baud(uint32_t baud) { *R_PS1_SIO1_BAUD = SIO1_BAUD_DIV / baud; }
static inline void sio_put_mode(uint16_t mode) { *R_PS1_SIO1_MODE = (mode & (~3)) | SIO_MODE_BR_16; }
static inline void sio_put_ctrl(uint16_t mask, uint16_t ctrl) { *R_PS1_SIO1_CTRL = ((*R_PS1_SIO1_CTRL & mask) | ctrl); }

/* the sio_set_xxx functions not only write the value to the register but also update the config value for that register
 */
static inline void sio_set_baud(uint32_t baud) {
    config.baud = baud;
    sio_put_baud(config.baud);
}

static inline void sio_set_ctrl(uint16_t mask, uint16_t ctrl) {
    config.ctrl = ctrl;
    sio_put_ctrl(mask, config.ctrl);
}

static inline void sio_set_mode(uint16_t mode) {
    // bits 0 and 1 should always be 0 and 1, respectively
    // this apparently corresponds to "baud rate multiplier 16"
    config.mode = mode;
    sio_put_mode(config.mode);
}

static inline uint16_t sio_get_status(void) { return *R_PS1_SIO1_STAT; }

static inline uint8_t sio_get_data(void) { return *R_PS1_SIO1_DATA; }

static inline void sio_put_data(uint8_t d) { *R_PS1_SIO1_DATA = d; }

// this should probably check STAT for errors.
uint8_t sio_get_byte(void) {
    uint8_t d;

    // this may not be necessary. Some UARTs won't transfer if yout don't though.

    // assert RTR(Ready To Receive akia "RTS"/Request to Send)
    sio_put_ctrl(~(SIO_CTRL_RTR_EN), SIO_CTRL_RTR_EN);

    // wait for data in the RX FIFO
    while (!(sio_get_status() & SIO_STAT_RX_RDY))
        ;

    // pop a byte from the RX FIFO
    d = *R_PS1_SIO1_DATA;

    // deassert RTR
    sio_put_ctrl(~(SIO_CTRL_RTR_EN), 0);

    return d;
}

int sio_put_byte(uint8_t data, uint32_t timeout) {
    volatile uint8_t d;

    if (sio_get_status() & (SIO_STAT_RX_OVRN_ERR | SIO_STAT_FRAME_ERR | SIO_STAT_PARITY_ERR)) {
        // I guess this is to preserve the data that's currently in the TX FIFO?
        d = *R_PS1_SIO1_DATA;

        while (sio_get_status() & (SIO_STAT_RX_OVRN_ERR | SIO_STAT_FRAME_ERR | SIO_STAT_PARITY_ERR)) {
            // RX Overrun, Frame Error or Parity Error

            // reset the interrupt and error
            SIO_RESET();

            delay_ms(5);

            // restore the TX FIFO?
            *R_PS1_SIO1_DATA = d;

            // restore mode and ctrl
            sio_put_mode(config.mode);
            sio_put_ctrl(0, config.ctrl);
        }
    }

    // FIXME: what happens if the CTRL SIO_CTRL_TX_EN isn't set??

    if (timeout == 0)
        while (!(sio_get_status() & SIO_STAT_TX_RDY))
            ;
    else {
        uint32_t tries = 0;
        while (!(sio_get_status() & SIO_STAT_TX_RDY)) {
            if (++tries >= timeout) return -2;
        }
    }

    // push the byte into the TX FIFO
    *R_PS1_SIO1_DATA = data;
    return data;
}

void init_sio(uint32_t baud) {
    /* 8bit, no-parity, 1 stop-bit */
    sio_set_mode(SIO_MODE_CHLEN_8 | SIO_MODE_P_NONE | SIO_MODE_SB_1);
    sio_set_baud(baud);
    sio_set_ctrl(0, SIO_CTRL_RX_EN | SIO_CTRL_TX_EN);
}

uint32_t sio_read32(void) {
    uint32_t d;

    d = sio_get_byte() | (sio_get_byte() << 8) | (sio_get_byte() << 16) | (sio_get_byte() << 24);
    return d;
}

void sioload() {
    int i;
    uint8_t sync;
    uint8_t* p;
    uint8_t header_buf[2048];
    EXE_Header* header = (EXE_Header*)header_buf;
    uint32_t x_addr,  // ignored
        write_addr, n_load;

    while (1) sio_put_byte('X', 0);  // sends an X to pc

    do {
        sync = sio_get_byte();
    } while (sync != 99);

    for (i = 0; i < sizeof(header_buf); i++) {
        header_buf[i] = sio_get_byte();
    }

    x_addr = sio_read32();
    write_addr = sio_read32();
    n_load = sio_read32();

    for (i = 0; i < n_load; i++) {
        ((uint8_t*)write_addr)[i] = sio_get_byte();
    }

    header->exec.stack_addr = 0x801FFF00;
    header->exec.stack_size = 0;
    EnterCriticalSection();
    Exec(&(header->exec), 1, 0);
}

// extern long _sio_control(unsigned long cmd, unsigned long arg, unsigned long param);

//~ int Sio1Callback (void (*func)())
//~ {
//~ return InterruptCallback(8, func);
//~ }

// NOTE: This will remove whatever "tty" device is installed and
// install the kernel "dummy" console driver.
int DelSIO(void) {
    close(stdin);
    close(stdout);
    DelDevice("tty");
    SIO_RESET();
    AddDummyConsoleDevice();
    if (open("tty00:", O_RDONLY) != stdin) return 1;
    if (open("tty00:", O_WRONLY) != stdout) return 1;
    return 0;
}

int main(void) {
    DelSIO();  // removes the "tty" device

    // 2073600(2Mbaud) is max
    // 1036800(1Mbaud)
    init_sio(115200);
    sioload();
    return 0;
}
