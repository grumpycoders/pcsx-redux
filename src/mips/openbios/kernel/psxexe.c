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
        memcpy(header, g_readBuffer + 16, 60); // BIOS does not copy the whole struct
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

    while (((c = *filename) != 0) && (c != ':')) {
        *ptr++ = c;
        filename++;
    }

    while ((*ptr++ = toupper(*filename++)) != 0);

    ptr = localFilename;
    while (((c = *ptr) != 0) && (c != ';')) ptr++;
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
