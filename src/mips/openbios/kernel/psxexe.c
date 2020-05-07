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

#include <ctype.h>
#include <memory.h>
#include <string.h>

#include "common/psxlibc/stdio.h"
#include "common/syscalls/syscalls.h"
#include "openbios/fileio/fileio.h"
#include "openbios/kernel/flushcache.h"
#include "openbios/kernel/psxexe.h"
#include "openbios/kernel/util.h"

static int readHeader(int fd, struct psxExeHeader * header) {
    if (syscall_read(fd, g_readBuffer, 2048) >= 2048) {
        memcpy(header, g_readBuffer + 16, sizeof(struct psxExeHeader));
        return 1;
    }

    return 0;
}

int loadExeHeader(const char * filename, struct psxExeHeader * header) {
    int fd = syscall_open(filename, PSXF_READ);
    if (fd < 0) return 0;
    int ret = readHeader(fd, header);
    syscall_close(fd);
    return ret;
}

int loadExe(const char * filename, struct psxExeHeader * header) {
    int fd = syscall_open(filename, PSXF_READ);
    if (fd < 0) return 0;
    int ret = readHeader(fd, header);
    if (ret == 0) {
        syscall_close(fd);
        return 0;
    }
    syscall_read(fd, (char *) header->text_addr, header->text_size);
    syscall_close(fd);
    flushCache();
    return 1;
}

/* what in the world is going on here... */
static struct psxExeHeader binaryHeader;
static char * binaryPath;
void loadAndExec(const char * filename, uint32_t stackStart, uint32_t stackSize) {
    char localFilename[28];
    char c;
    char * ptr = localFilename;

    while ((c = *filename) != 0 && (c != ':')) {
        *ptr++ = c;
        filename++;
    }

    while ((*ptr++ = toupper(*filename++)) != 0);

    ptr = localFilename;
    while (((c = *ptr) != 0) || (c != ';')) ptr++;
    if (c == 0) strcat(localFilename, ";1");

    static uint32_t savedStackStart;
    savedStackStart = binaryHeader.stack_start;
    static uint32_t savedStackSize;
    savedStackSize = binaryHeader.stack_size;
    leaveCriticalSection();
    if (loadExe(localFilename, &binaryHeader)) {
        binaryHeader.stack_start = stackStart;
        binaryHeader.stack_size = stackSize;
        exec(&binaryHeader, 1, NULL);
    } else {
        psxprintf("No EXE-file !\n");
    }
    psxprintf("Execute the boot file %s.\n", binaryPath);
    leaveCriticalSection();
    if (loadExe(binaryPath, &binaryHeader)) {
        binaryHeader.stack_start = savedStackStart;
        binaryHeader.stack_size = savedStackSize;
        exec(&binaryHeader, 1, NULL);
    }
    psxprintf("No boot file !\n");
    while(1);
}
