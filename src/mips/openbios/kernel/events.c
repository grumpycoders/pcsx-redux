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
#include "openbios/kernel/globals.h"

struct EventInfo {
    uint32_t class, flags, spec, mode;
    void (*handler)();
    uint32_t unknown1, unknown2;
};

int initEvents(int count) {
    psxprintf("\nConfiguration : EvCB\t0x%02x\t\t", count);
    int size = count * sizeof(struct EventInfo);
    struct EventInfo * array = syscall_kmalloc(size);
    if (!array) return 0;
    __globals.eventsSize = size;
    __globals.events = array;
    struct EventInfo * ptr = array;
    while (ptr < (array + count)) ptr++->flags = 0;
    return size;
}

static int getFreeEvCBSlot(void) {
    struct EventInfo * ptr, * end;
    int slot = 0;

    ptr = __globals.events;
    end = (struct EventInfo*)(((char *) ptr) + __globals.eventsSize);
    while (ptr < end) {
        if (ptr->flags == 0) return slot;
        ptr++;
        slot++;
    }

    return -1;
}

uint32_t openEvent(uint32_t class, uint32_t spec, uint32_t mode, void (*handler)()) {
    int slot = getFreeEvCBSlot();
    if (slot == -1) return -1;

    struct EventInfo *event = __globals.events + slot;
    event->class = class;
    event->spec = spec;
    event->mode = mode;
    event->flags = 0x1000;
    event->handler = handler;
    return slot | 0xf1000000;
}

__attribute__((section(".ramtext"))) void deliverEvent(uint32_t class, uint32_t spec) {
    struct EventInfo * ptr, * end;

    ptr = __globals.events;
    end = (struct EventInfo*)(((char *) ptr) + __globals.eventsSize);
    while (ptr < end) {
        if ((ptr->flags == 0x2000) && (class == ptr->class) && (spec == ptr->spec)) {
            if (ptr->mode == 0x2000) ptr->flags = 0x4000;
            else if ((ptr->mode = 0x1000) && ptr->handler) ptr->handler();
        }
        ptr++;
    }
}

int enableEvent(uint32_t event) {
    struct EventInfo * ptr = __globals.events + (event & 0xffff);
    if (ptr->flags) ptr->flags = 0x2000;
    return 1;
}

int closeEvent(uint32_t event) {
    struct EventInfo * ptr = __globals.events + (event & 0xffff);
    ptr->flags = 0;
    return 1;
}

void undeliverEvent(uint32_t class, uint32_t spec) {
    struct EventInfo * ptr, * end;

    ptr = __globals.events;
    end = (struct EventInfo*)(((char *) ptr) + __globals.eventsSize);
    while (ptr < end) {
        if ((ptr->flags == 0x4000) && (class == ptr->class) && (spec == ptr->spec) && (ptr->mode == 0x2000)) {
            ptr->flags = 0x2000;
        }
        ptr++;
    }
}

int testEvent(uint32_t event) {
    struct EventInfo * ptr = __globals.events + (event & 0xffff);
    if (ptr->flags == 0x4000) {
        ptr->flags = 0x2000;
        return 1;
    }
    return 0;
}


int waitEvent(uint32_t event) {
    struct EventInfo * ptr = __globals.events + (event & 0xffff);
    if (ptr->flags == 0x4000) {
        ptr->flags = 0x2000;
        return 1;
    }
    if (ptr->flags == 0x2000) {
        volatile uint32_t * flags = &ptr->flags;
        while (*flags != 0x4000);
        *flags = 0x2000;
        return 1;
    }
    return 0;
}
