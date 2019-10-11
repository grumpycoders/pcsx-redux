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

#include "common/hardware/hwregs.h"
#include "common/hardware/sio1.h"

void sio1_init() {
    // enable TX and RX, and nothing else
    SIO1_CTRL = 5;
    // 01001110
    // Baudrate Reload Factor: MUL16 (2)
    // Character length: 8 (3)
    // Parity Disabled
    // Parity Type: irrelevant
    // Stop bit length: 1 (1)
    //  --> 8N1
    SIO1_MODE = 0x4e;
    SIO1_BAUD = 2073600 / 115200;
}

void sio1_putc(uint8_t byte) {
    while ((SIO1_STAT & 1) == 0);
    SIO1_DATA = byte;
}
