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

#include <devfs.h>
#include <stdio.h>
#include <fio.h>

#include "common/hardware/cop0.h"
#include "common/hardware/spu.h"
#include "common/util/djbhash.h"
#include "openbios/kernel/handlers.h"

static void start(const char* systemPath, const char* exePath);

int main() {
    *((uint32_t*) 0x60) = 0x02;
    *((uint32_t*) 0x64) = 0x00;
    *((uint32_t*) 0x68) = 0xff;
    muteSpu();

    register_devfs();
    register_stdio_devices();

    printf("OpenBIOS starting.\n");

    if (djbHash((const char *) 0x1f000084, 44) == 0xf0772daf) {
        (*((void(**)()) 0x1f000080))();
    }

    start("cdrom:SYSTEM.CNF;1", "cdrom:PSX.EXE;1");

    return 0;
}


void start(const char* systemPath, const char* exePath) {
    writeCOP0Status(readCOP0Status() & 0xfffffbfe);
    muteSpu();

    installKernelHandlers();
}
