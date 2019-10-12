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

#define _KBuffer ((void *) 0xA000B070)
#define _KExecInfo ((void *) 0xA000B870)

int psLoad(ExecInfo *exec)
{
    int i;
    EXE_Header *hdr = (EXE_Header *) _KBuffer;

    // load the 2048-byte header of the EXE into "header" and the "text" of the into
    //  the "text_addr" specified by the header.
    printf("psLoad() reading 2048 bytes first.\r\n");
    for(i = 0; i < 2048; i++) {
        uint8_t b = psio_get();
        ((uint8_t *) hdr)[i] = b;
    }

    for(i = 0; i < sizeof(ExecInfo); i++) {
        ((uint8_t *) exec)[i] = ((uint8_t *) &hdr->exec)[i];
    }

    printf("psLoad() reading %i bytes\r\n", hdr->exec.text_size);
    for(i = 0; i < hdr->exec.text_size; i++) {
        uint8_t b = psio_get();
        ((uint8_t *) hdr->exec.text_addr)[i] = b;
    }

    printf("\r\nDone, calling flushCache()\r\n");
    FlushCache();
    return 1;
}

void main(void)
{
    int rv = 1;
    uint8_t d;
    ExecInfo *info = (ExecInfo *) _KExecInfo;

    printf("pshittyload starting...\r\n");
    while(rv != 0)
    {
        psio_init(); // (re-) initialize SIO1

        // loop until we get 'P', 'L'
        // when we get a 'P' and another character, we send a response char:
        //  '+': if we got an 'L'
        //  '-': if we got something else
        do
        {
            do { d = psio_get(); } while (d != 'P');
            psio_put((d = psio_get()) == 'L' ? '+' : '-' );
        } while(d != 'L');
        printf("Got PL signature, calling psLoad(%p)\r\n", info);

        psLoad(info);
        printf("psLoad(%p) done, calling Exec2(%p)\r\n", info, info);
        rv = Exec2(info, 0, 0);
    }
}
