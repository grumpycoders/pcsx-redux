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
#include <fio.h>
#include <romfs.h>
#include <unistd.h>

#include "common/hardware/cop0.h"
#include "common/hardware/sio1.h"
#include "common/hardware/spu.h"
#include "common/util/djbhash.h"
#include "openbios/kernel/handlers.h"

extern const char romfs[];

static void start(const char* systemPath, const char* exePath);

int main() {
    *((uint32_t*)0x60) = 0x02;
    *((uint32_t*)0x64) = 0x00;
    *((uint32_t*)0x68) = 0xff;
    muteSpu();

    sio1_init();
    sio1_putc('H');
    sio1_putc('i');
    sio1_putc('\r');
    sio1_putc('\n');
    register_devfs();
    register_stdio_devices();
    register_romfs("romfs", (uint8_t *) romfs);

    printf("OpenBIOS starting.\r\n");

    printf("Checking for EXP1...\r\n");

    if (djbHash((const char *) 0x1f000084, 44) == 0xf0772daf) {
        void(*ptr)() = *(void(**)()) 0x1f000080;
        printf("Signature match, jumping to %p\r\n", ptr);
        (*ptr)();
    } else {
        printf("Signature not matching - skipping EXP1\r\n");
    }

    start("cdrom:SYSTEM.CNF;1", "cdrom:PSX.EXE;1");

    return 0;
}

void start(const char* systemPath, const char* exePath) {
    writeCOP0Status(readCOP0Status() & 0xfffffbfe);
    muteSpu();

    installKernelHandlers();

    void(*shell)() = (void(*)()) 0x80030000;

    printf("Trying to load the shell...\r\n");
    int shellFile = open("/romfs/pshittyload.bin", O_RDONLY);
    if (shellFile >= 0) {
        ssize_t size = read(shellFile, shell, 0x80200000 - 0x80030000);
        printf("Shell found, read %i bytes from it.\r\n", size);
        close(shellFile);
        uint8_t* shellData = (uint8_t*) shell;
        for (ssize_t i = 0; i < size; i++) {
            if ((i % 16) == 0) {
                printf("\r\n%08X - ", i);
            }
            printf("%02x ", shellData[i]);
        }
        printf("\r\n");
        printf("Executing the shell.\r\n");
        shell();
        printf("Shell is done running.\r\n");
    } else {
        printf("Shell not found.\r\n");
    }
}
