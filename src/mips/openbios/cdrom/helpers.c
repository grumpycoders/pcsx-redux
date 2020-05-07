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

#include "common/syscalls/syscalls.h"
#include "openbios/cdrom/events.h"
#include "openbios/cdrom/helpers.h"

int cdromBlockReading(int count, int sector, char * buffer) {
    int retries;

    sector += 150;

    /* I can't in good conscience reproduce the bug seen in the retail bios
       code. The following bloc that computes the msf of the sector to read
       is inside the for loop in the retail bios code. Which means that the
       'sector' variable gets mangled every time there's a retry, and
       further retries will always fail or return the wrong sector. */

    int minutes = sector / 4500;
    sector %= 4500;
    uint8_t msf[3] = {
        (minutes % 10) + (minutes / 10) * 0x10,
        ((sector / 75) % 10) + ((sector / 75) / 10) * 0x10,
        ((sector % 75) % 10) + ((sector % 75) / 10) * 0x10
    };

    for (retries = 0; retries < 10; retries++) {
        int cyclesToWait = 99999;
        while (!syscall_cdromSeekL(msf) && (--cyclesToWait > 0));

        if (cyclesToWait < 1) {
            syscall_exception(0x44, 0x0b);
            return -1;
        }

        while (!syscall_testEvent(g_cdEventDNE)) {
            if (syscall_testEvent(g_cdEventERR)) {
                syscall_exception(0x44, 0x0c);
                return -1;
            }
        }

        cyclesToWait = 99999;
        while (!syscall_cdromRead(count, buffer, 0x80) && (--cyclesToWait > 0));
        if (cyclesToWait < 1) {
            syscall_exception(0x44, 0x0c);
            return -1;
        }
        while (1) {
            // Here, the original code basically does the following:
            //   if (cyclesToWait < 1) return 1;
            // which is 1) useless, since cyclesToWait never mutates
            // and 2) senseless as we're supposed to return the
            // number of sectors read.
            // An optimzing compiler would cull it out anyway, so
            // it's no use letting it here.
            if (syscall_testEvent(g_cdEventDNE)) return count;
            if (syscall_testEvent(g_cdEventERR)) break;
            if (syscall_testEvent(g_cdEventEND)) {
                syscall_exception(0x44, 0x17);
                return -1;
            }
        }
        syscall_exception(0x44, 0x16);
    }

    syscall_exception(0x44, 0x0c);
    return -1;
}
