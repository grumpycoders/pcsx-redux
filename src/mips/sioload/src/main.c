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

void sioload(void) {
    int i;
    int sync;
    uint8_t* p;
    uint8_t header_buf[2048];
    EXE_Header* header = (EXE_Header*)header_buf;
    uint32_t x_addr,  // ignored
        write_addr, n_load;

    while (1) {
        sio_poke8('X', 0);  // sends an X to pc
    }

    do {
        sync = sio_peek8(10000);
    } while (sync != 99);

    for (i = 0; i < sizeof(header_buf); i++) {
        header_buf[i] = sio_peek8(0);
    }

    // ignored
    x_addr = sio_peek32(0);
    write_addr = sio_peek32(0);
    n_load = sio_peek32(0);

    for (i = 0; i < n_load; i++) {
        ((uint8_t*)write_addr)[i] = sio_peek8(0);
    }

    // could at least send back a kiss goodbye...

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
    sio_reset();

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
