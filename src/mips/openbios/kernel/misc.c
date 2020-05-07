/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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
#include "openbios/fileio/fileio.h"
#include "openbios/kernel/globals.h"
#include "openbios/kernel/misc.h"

void setMemSize(int memSize) {
    uint32_t current = RAM_SIZE;
    switch (memSize) {
        case 2:
            RAM_SIZE = current & ~0x300;
            break;
        case 8:
            RAM_SIZE = current | 0x300;
            break;
        default:
            psxprintf("Effective memory must be 2/8 MBytes\n");
            return;
    }

    __globals60.ramsize = memSize;
    psxprintf("Change effective memory : %d MBytes\n", memSize);
}
