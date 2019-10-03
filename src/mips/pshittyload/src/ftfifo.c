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

#include "ftfifo.h"
#include <fileio.h>
#include <ps1hwregs.h>
#include <ps1sdk.h>
#include <serialio.h>
#include <stdio.h>
#include "common/hardware/cop0.h"

uint8_t FT_peek8(uint32_t timeout, int *presult) {
    int res = 0;
    uint8_t d = 0;

    if (timeout == 0) {
        while (!(*FTFIFO_STAT & FTFIFO_STAT_RXRDY))
            ;
    } else {
        while (!(*FTFIFO_STAT & FTFIFO_STAT_RXRDY)) {
            if (--timeout <= 0) {
                res = -1;
                goto fail;
            }
        }
    }

    d = *FTFIFO_DATA;

fail:
    if (presult) *presult = res;

    return d;
}

int FT_poke8(uint8_t d, uint32_t timeout) {
    int res = 0;

    if (timeout == 0) {
        while (!(*FTFIFO_STAT & FTFIFO_STAT_TXRDY))
            ;
    } else {
        while (!(*FTFIFO_STAT & FTFIFO_STAT_TXRDY)) {
            if (--timeout == 0) {
                res = -1;
                goto fail;
            }
        }
    }

    *FTFIFO_DATA = d;

fail:
    return res;
}

uint32_t FT_peek32(uint32_t timeout, int *presult) {
    int res = 0;
    uint32_t d, d32 = 0;

    for (int i = 0; i < 4; i++) {
        d = FT_peek8(0, &res);
        if (res != 0) break;
        d32 |= (d << (i * 8));
    }

    if (presult) *presult = res;

    return d32;
}

int FT_poke32(uint32_t d, uint32_t timeout) {
    for (int i = 0; i < 4; i++) {
        if (FT_poke8(d & 0xFF, timeout) != 0) {
            return -1;
        }
        d >>= 8;
    }

    return 0;
}
