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

uint32_t g_cdEventACK; /* 0x0010 */
uint32_t g_cdEventDNE; /* 0x0020 */
uint32_t g_cdEventRDY; /* 0x0040 */
uint32_t g_cdEventEND; /* 0x0080 */
uint32_t g_cdEventERR; /* 0x8000 */

// Yes, these undeliver some events that never got created in the first place.
void cdromUndeliverAllExceptAckAndRdy() {
    syscall_undeliverEvent(0xf0000003, 0x20);
    syscall_undeliverEvent(0xf0000003, 0x80);
    syscall_undeliverEvent(0xf0000003, 0x8000);
    syscall_undeliverEvent(0xf0000003, 0x100); // never created
    syscall_undeliverEvent(0xf0000003, 0x200); // never created
}

void cdromUndeliverAll() {
    syscall_undeliverEvent(0xf0000003, 0x40);
    syscall_undeliverEvent(0xf0000003, 0x10);
    syscall_undeliverEvent(0xf0000003, 0x20);
    syscall_undeliverEvent(0xf0000003, 0x80);
    syscall_undeliverEvent(0xf0000003, 0x8000);
    syscall_undeliverEvent(0xf0000003, 0x100); // never created
    syscall_undeliverEvent(0xf0000003, 0x200); // never created
}

