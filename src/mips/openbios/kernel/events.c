/*

MIT License

Copyright (c) 2020 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

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
        if (ptr->flags == EVENT_FLAG_FREE) return slot;
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
    event->flags = EVENT_FLAG_DISABLED;
    event->handler = handler;
    return slot | 0xf1000000;
}

__attribute__((section(".ramtext"))) void deliverEvent(uint32_t class, uint32_t spec) {
    struct EventInfo * ptr, * end;

    ptr = __globals.events;
    end = (struct EventInfo*)(((char *) ptr) + __globals.eventsSize);
    while (ptr < end) {
        if ((ptr->flags == EVENT_FLAG_ENABLED) && (class == ptr->class) && (spec == ptr->spec)) {
            if (ptr->mode == EVENT_MODE_NO_CALLBACK) ptr->flags = EVENT_FLAG_PENDING;
            else if (ptr->mode == EVENT_MODE_CALLBACK && ptr->handler) ptr->handler();
        }
        ptr++;
    }
}

int enableEvent(uint32_t event) {
    struct EventInfo * ptr = __globals.events + (event & 0xffff);
    if (ptr->flags != 0) ptr->flags = EVENT_FLAG_ENABLED;
    return 1;
}

int disableEvent(uint32_t event) {
    struct EventInfo * ptr = __globals.events + (event & 0xffff);
    if (ptr->flags != 0) ptr->flags = EVENT_FLAG_DISABLED;
    return 1;
}

int closeEvent(uint32_t event) {
    struct EventInfo * ptr = __globals.events + (event & 0xffff);
    ptr->flags = EVENT_FLAG_FREE;
    return 1;
}

void undeliverEvent(uint32_t class, uint32_t spec) {
    struct EventInfo * ptr, * end;

    ptr = __globals.events;
    end = (struct EventInfo*)(((char *) ptr) + __globals.eventsSize);
    while (ptr < end) {
        if ((ptr->flags == EVENT_FLAG_PENDING) && (class == ptr->class) && (spec == ptr->spec) && (ptr->mode == EVENT_MODE_NO_CALLBACK)) {
            ptr->flags = EVENT_FLAG_ENABLED;
        }
        ptr++;
    }
}

int testEvent(uint32_t event) {
    struct EventInfo * ptr = __globals.events + (event & 0xffff);
    if (ptr->flags == EVENT_FLAG_PENDING) {
        ptr->flags = EVENT_FLAG_ENABLED;
        return 1;
    }
    return 0;
}


int waitEvent(uint32_t event) {
    struct EventInfo * ptr = __globals.events + (event & 0xffff);
    if (ptr->flags == EVENT_FLAG_PENDING) {
        ptr->flags = EVENT_FLAG_ENABLED;
        return 1;
    }
    if (ptr->flags == EVENT_FLAG_ENABLED) {
        volatile uint32_t * flags = &ptr->flags;
        while (*flags != EVENT_FLAG_PENDING);
        *flags = EVENT_FLAG_ENABLED;
        return 1;
    }
    return 0;
}
