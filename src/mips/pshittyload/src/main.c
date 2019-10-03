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
#include "ftfifo.h"

// switch between implementations
#if 1
#define COMMS_INIT() (0)
#define COMMS_PEEK8 FT_peek8
#define COMMS_PEEK16 FT_peek16
#define COMMS_PEEK32 FT_peek32

#define COMMS_POKE8(__d, __timeout) FT_poke8(__d, __timeout)
#define COMMS_POKE16(__d, __timeout) FT_poke16(__d, __timeout)
#define COMMS_POKE32(__d, __timeout) FT_poke32(__d, __timeout)
#else
#define COMMS_INIT() sio_init(115200)
#endif

/*
 * pshitty protocol:
 *
 * host writes 'P','S' then reads a byte from comms
 * ps reads 1 byte, if it's not 'P', discard it. and try gain.
 * ps reads 1 byte, if it's not 'S', writes '!'(NAK) then returns to waiting for 'P'
 * ps writes '+'(ACK)
 *
 * Host writes 32-bit load address(little endian)
 * Host writes 32-bit file size(little endian)
 * Reads 1 byte response from ps
 * ps reads load address and file size.
 * if load address + (file size - 2048) is invalid, ps writes '!' NAK and returns to syncing
 * ps writes '+'(ACK)
 * If host receives a NAK, returns to start of protocol.
 * Host writes the whole file(file size number bytes)
 * Host reads 1 byte, fails if not received after a resonable time(maybe 5 seconds)
 * ps reads 2048 bytes into exehdr buffer.
 * ps reads (file size - 2048) bytes to load address
 * ps writes ACK
 * ps calls Exec(&(exehdr->exec), 1, 0);
 * If host read a NAK, success! Otherwise failure.
 * ps writes NAK(this should never happen unless Exec fails or the main() of the exe returns.
 * ps returns to syncing
 *
 */

// wait for remote to send 'P', 'S'
// if the second char is not 'S', responds with a '!'(NAK) before continuing to wait.
// otherwise sends a '+'(ACK) and returns
void pshitty_sync(void) {
    int res = 0;
    while (1) {
        uint8_t d = COMMS_PEEK8(0, &res);
        if (res != 0) continue;
        if (d != 'P') {
            continue;
        }

        d = COMMS_PEEK8(0, &res);
        if (res != 0) continue;
        if (d != 'S') {
            COMMS_POKE8('!', 0);  // NAK
        } else {
            COMMS_POKE8('+', 0);  // ACK
            return;
        }
    }
}

void pshitty_loader(void) {
    uint8_t buf[2048];
    int err = 0;
    uint32_t load_addr, load_len;
    EXE_Header *exehdr = (EXE_Header *)buf;

    while (1) {
        int rv = -1;
        int res = 0;

        pshitty_sync();

        load_addr = COMMS_PEEK32(1000, &res);
        if (res != 0) goto error;

        load_len = COMMS_PEEK32(1000, &res);
        if (res != 0) goto error;

        if (load_len < sizeof(buf)) {
            goto error;
        }

        for (int i = 0; i < sizeof(buf); i++) {
            buf[i] = COMMS_PEEK8(1000, &res);
            if (res != 0) break;
        }
        if (res != 0) goto error;

        load_len -= sizeof(buf);

        for (int i = 0; i < load_len; i++) {
            ((uint8_t *)load_addr)[i] = COMMS_PEEK8(1000, &res);
            if (res != 0) break;
        }
        if (res != 0) goto error;

        exehdr->exec.stack_addr = 0x801FFF00;
        exehdr->exec.stack_size = 0;
        EnterCriticalSection();
        rv = Exec(&(exehdr->exec), 1, 0);

    error:
        COMMS_POKE32(rv, 10000);
    }
}

//~ void load_exec_this(void *dest, void *src, int len, void *entry)
//~ {
//~ memcpy(dest, src, len);
//~ FlushCache();
//~ if(entry == NULL) entry = dest;

//~ ((void) entry)();
//~ }

//~ load_exec_this((void *) 0x80100000, &fifo_echo_shell_bin, sizeof(fifo_echo_shell_bin), 0);

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

    //    sio_reset();

    AddDummyConsoleDevice();

    if (open("tty00:", O_RDONLY) != stdin) return 1;
    if (open("tty00:", O_WRONLY) != stdout) return 1;

    return 0;
}

int main(void) {
    //    DelSIO();  // removes the "tty" device

    COMMS_INIT();

    pshitty_loader();

    return 0;
}
