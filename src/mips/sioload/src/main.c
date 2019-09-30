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

#include <ps1sdk.h>
#include <stdio.h>
#include <fileio.h>
#include <ps1hwregs.h>
#include <serialio.h>

#include "common/hardware/cop0.h"

static inline void sio_set_baud(uint16_t v)
{
    // I don't understand this... PsyQ says "bps must be in the range 9600 - 2073600 and evenly divisible into 2073600"
    *R_PS1_SIO1_BAUD = 2116800/v;
}

static inline void sio_set_ctrl(uint16_t mask, uint16_t v)
{   
    *R_PS1_SIO1_CTRL = ((*R_PS1_SIO1_CTRL & mask) | v);
}

static inline void sio_set_mode(uint16_t v)
{
    // bits 0 and 1 should always be 0 and 1, respectively
    // this apparently corresponds to "baud rate multiplier 16"
    *R_PS1_SIO1_MODE = (v & (~3)) | 2;
}

static inline uint16_t sio_get_status(void)
{
    return  *R_PS1_SIO1_STAT;
}

static inline uint8_t sio_get_data(void)
{
    return *R_PS1_SIO1_DATA;
}

static inline void sio_put_data(uint8_t d)
{
    *R_PS1_SIO1_DATA = d;
}

uint8_t read_sio(void)
{
    uint8_t d;
    
    // this may not be necessary. Some UARTs won't transfer if yout don't though.
    
    // assert RTR(Ready To Receive akia "RTS"/Request to Send)
    sio_set_ctrl(~(SIO_CTRL_RTR_EN), SIO_CTRL_RTR_EN);
    
    // wait for data in the RX FIFO
    while(!(sio_get_status() & SIO_STAT_RX_RDY));
    
    // pop a byte from the RX FIFO
    d = sio_get_data();

    // deassert RTR
    sio_set_ctrl(~(SIO_CTRL_RTR_EN), 0);

    return d;
}

void write_sio(uint8_t d)
{
    // wait for TX FIFO to be ready and empty
    while((sio_get_status() & (SIO_STAT_TX_EMPTY | SIO_STAT_TX_RDY)) != (SIO_STAT_TX_EMPTY | SIO_STAT_TX_RDY));

    // push a byte into the TX FIFO
    sio_put_data(d);
}

void init_sio(uint32_t baud)
{
    sio_set_mode(SIO_MODE_CHLEN_8 | SIO_MODE_P_NONE | SIO_MODE_SB_1); /* 8bit, no-parity, 1 stop-bit */
    sio_set_baud(baud);
    sio_set_ctrl(0, SIO_CTRL_RX_EN | SIO_CTRL_TX_EN);
}

uint32_t sio_read32(void)
{
    uint32_t d;
    
    d = read_sio() | \
        (read_sio() << 8) | \
        (read_sio() << 16) | \
        (read_sio() << 24);
    return d; 
}

void sioload()
{
    int i;
    uint8_t sync;
    uint8_t *p;
    uint8_t header_buf[2048];
    EXE_Header *header = (EXE_Header *) header_buf;
    uint32_t x_addr, // ignored
            write_addr,
            n_load;

    write_sio('X'); // sends an X to pc

    do { sync = read_sio(); } while (sync != 99);

    for(i = 0; i < sizeof(header_buf); i++)
    {
        header_buf[i] = read_sio();
    }
    
    x_addr = sio_read32();
    write_addr = sio_read32();
    n_load = sio_read32();

    for(i = 0; i < n_load; i++)
    {
        ((uint8_t *) write_addr)[i] = read_sio();
    }
    
    header->exec.stack_addr = 0x801FFF00;
    header->exec.stack_size = 0;
    EnterCriticalSection();
    Exec(&(header->exec), 1, 0);
}

//extern long _sio_control(unsigned long cmd, unsigned long arg, unsigned long param);

//~ int Sio1Callback (void (*func)())
//~ {
    //~ return InterruptCallback(8, func);
//~ }

// NOTE: This will remove whatever "tty" device is installed and
// install the kernel "dummy" console driver.
int DelSIO(void)
{
    close(stdin);
    close(stdout);
    DelDevice("tty");
    sio_set_ctrl(0,SIO_CTRL_RESET_INT | SIO_CTRL_RESET_ERR);
    AddDummyConsoleDevice();
    if(open("tty00:", O_RDONLY) != stdin) return 1;
    if(open("tty00:", O_WRONLY) != stdout) return 1;
    return 0;
}

int main(void)
{      
    DelSIO(); // removes the "tty" device

    // 2073600(2Mbaud) is max
    // 1036800(1Mbaud)
    init_sio(1036800);
    sioload();
    return 0;
}

