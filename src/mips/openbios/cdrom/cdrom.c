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

#include <stddef.h>

#include "common/syscalls/syscalls.h"
#include "openbios/cdrom/cdrom.h"
#include "openbios/cdrom/events.h"
#include "openbios/cdrom/filesystem.h"

static void initializeHandlersAndEvents() {
    syscall_enqueueCDRomHandlers();
    g_cdEventACK = syscall_openEvent(0xf0000003, 0x0010, 0x2000, NULL);
    g_cdEventDNE = syscall_openEvent(0xf0000003, 0x0020, 0x2000, NULL);
    g_cdEventRDY = syscall_openEvent(0xf0000003, 0x0040, 0x2000, NULL);
    g_cdEventEND = syscall_openEvent(0xf0000003, 0x0080, 0x2000, NULL);
    g_cdEventERR = syscall_openEvent(0xf0000003, 0x8000, 0x2000, NULL);
    leaveCriticalSection();
    g_cdromCWD[0] = 0;
}

static void initializeSoftwareAndHardware() {
    initializeHandlersAndEvents();
    while (!syscall_cdromInnerInit());
}

void initCDRom() {
    initializeSoftwareAndHardware();
    volatile int delay = 0;
    while(++delay < 50000);
    cdromReadPathTable();
}
