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

#include "common/compiler/stdint.h"
#include "common/syscalls/syscalls.h"
#include "openbios/fileio/fileio.h"
#include "openbios/kernel/events.h"

struct EventInfo {
    uint32_t class, flags, spec, mode, handler, unknown1, unknown2;
};

int initEvents(int count) {
    psxprintf("\nConfiguration : EvCB\t0x%02\t\t", count);
    int size = count * sizeof(struct EventInfo);
    struct EventInfo * array = syscall_kmalloc(size);
    if (!array) return 0;
    *((uint32_t*) 0xa0000124) = size;
    *((struct EventInfo**) 0xa0000120) = array;
    struct EventInfo * ptr = array;
    while (ptr < (array + count)) ptr++->flags = 0;
    return size;
}
