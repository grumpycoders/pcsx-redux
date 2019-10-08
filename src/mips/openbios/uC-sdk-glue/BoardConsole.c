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

#include <stdio.h>
#include "BoardConsole.h"

#include "common/hardware/sio1.h"

void BoardConsoleInit() {
    sio1_init();
}

void BoardConsolePuts(const char * str) {
    char c;
    while ((c = *str++)) sio1_putc(c);
}

void BoardConsolePutc(int c) {
    sio1_putc(c);
}

static void xprintfCallback(const char * str, int strsize, void * opaque0) {
    while (strsize--) sio1_putc(*str++);
}

void BoardConsolePrintf(const char * fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    BoardConsoleVPrintf(fmt, ap);
    va_end(ap);
}

void BoardConsoleVPrintf(const char * fmt, va_list ap) {
    vxprintf(xprintfCallback, NULL, fmt, ap);
}
