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

#include <string.h>

#include "openbios/pio/pio.h"

static const char * const licenseText = "Licensed by Sony Computer Entertainment Inc.";

int checkExp1PreHookLicense() {
    return strcmp((char *)0x1f000084, licenseText) == 0;
}

void runExp1PreHook() {
    ((void(*)())0x1f000080)();
}

int checkExp1PostHookLicense() {
    return strcmp((char *)0x1f000004, licenseText) == 0;
}

void runExp1PostHook() {
    ((void(*)())0x1f000000)();
}
