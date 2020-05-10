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

#include "common/psxlibc/handlers.h"
#include "common/syscalls/syscalls.h"
#include "openbios/kernel/globals.h"

int __attribute__((section(".ramtext"))) sysEnqIntRP(int priority, struct HandlerInfo * handler) {
    struct HandlerInfo * ptr;
    ptr = __globals.handlersArray[priority].first;
    __globals.handlersArray[priority].first = handler;
    handler->next = ptr;

    return 0;
}

struct HandlerInfo * __attribute__((section(".ramtext"))) sysDeqIntRP(int priority, struct HandlerInfo * handler) {
    struct HandlerInfo * ptr;

    ptr = __globals.handlersArray[priority].first;
    if (!ptr) {
        return NULL;
    } else if (ptr == handler) {
        __globals.handlersArray[priority].first = ptr->next;
        return ptr;
    } else {
        struct HandlerInfo * prev = ptr;
        if (ptr->next) {
            for (ptr = ptr->next; ptr && ptr != handler; ptr = ptr->next) {
                prev = ptr;
            }
        }
        if (ptr == handler) {
            prev->next = ptr->next;
            return ptr;
        }
    }
    return NULL;
}
