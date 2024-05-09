/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

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

#include "common/psxlibc/device.h"

#include <string.h>

#include "common/hardware/pcsxhw.h"
#include "common/syscalls/syscalls.h"
#include "openbios/card/backupunit.h"
#include "openbios/card/card.h"
#include "openbios/kernel/libcmisc.h"
#include "openbios/sio0/card.h"
#include "osdebug.h"

static char s_findFilePattern[20];
static int s_buNextFileIndex;

static int patternMatch(const char *filename, const char *pattern) {
    char c;

    while ((c = *filename++)) {
        if ((*pattern != '?') && (*pattern != c)) return 0;
        pattern++;
    }
    if (*pattern && (*pattern != '?')) return 0;
    return 1;
}

static int buNextFileInternal(int deviceId, int index, const char *pattern) {
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;

    for (; index < 15; index++) {
        struct BuDirectoryEntry *buEntry = &g_buDirEntries[port][index];
        if (syscall_getDeviceStatus() == 0) {
            if (buEntry->allocState != 0x51) continue;
        } else {
            if (buEntry->allocState != 0xa1) continue;
        }
        if (strlen(buEntry->name) == 0) continue;
        if (!patternMatch(buEntry->name, pattern)) continue;
        s_buNextFileIndex = index;
        return index;
    }

    return -1;
}

static int buDevInit(int deviceId) {
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;

    if (!syscall_mcReadSector(deviceId, 0, g_buBuffer[port])) {
        for (unsigned i = 0; i < 15; i++) {
            psxbzero(&g_buDirEntries[port][i], sizeof(struct BuDirectoryEntry));
        }
        for (unsigned i = 0; i < 20; i++) {
            g_buBroken[port][i] = -1;
        }
        return 0;
    }

    int status = mcWaitForStatusAndReturnIndex();
    if (status != 0) {
        if (status != 3) return 0;
        return buInit(deviceId);
    }
    if ((g_buBuffer[port][0] == 'M') && (g_buBuffer[port][1] == 'C')) return 1;
    if (g_buAutoFormat) return buFormat(deviceId);
    return 0;
}

static __attribute__((noreturn)) void dev_bu_unimplemented(const char *function, uint32_t ra) {
    osDbgPrintf("=== Unimplemented memory card function %s from %p ===\r\n", function, ra);
    osDbgPrintf("=== halting ===\r\n");
    pcsx_debugbreak();
    while (1) asm("");
}

int dev_bu_open(struct File *file, const char *path, int mode) {
    int deviceId = file->deviceId;
    file->errno = PSXEBUSY;
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;
    int firstIndex;
    struct BuDirectoryEntry *buEntries = g_buDirEntries[port];

    if (g_buOperation[port] != 0) return 1;

    mcResetStatus();
    if (((mode & PSXF_ASYNC) != PSXF_ASYNC) && !buDevInit(deviceId)) return 1;
    if ((mode & PSXF_CREAT) == PSXF_CREAT) {
        syscall_setDeviceStatus(0);
        firstIndex = buNextFileInternal(deviceId, 0, path);
        if (firstIndex != -1) {
            file->errno = PSXEEXIST;
            return 1;
        }
        int availableBlocks = 0;
        int bitmap[15];
        for (unsigned i = 0; i < 15; i++) {
            bitmap[i] = 0;
            if ((buEntries[i].allocState & 0xf0) == 0xa0) availableBlocks++;
        }
        unsigned futureBlockCount = mode >> 16;
        futureBlockCount &= 0x0000ffff;
        file->length = futureBlockCount << 13;
        if (futureBlockCount > availableBlocks) {
            file->errno = PSXENOSPC;
            return 1;
        }
        // [sic] yes, this is totally useless and redundant
        futureBlockCount = file->length >> 13;
        if ((file->length & 0x1fff) != 0) futureBlockCount++;
        int blockCount = 0;
        int prevIndex;
        for (int index = 0; index < 15; index++) {
            struct BuDirectoryEntry *entry = &buEntries[index];
            if ((entry->allocState & 0xf0) != 0xa0) continue;
            if (blockCount == 0) {
                entry->allocState = 0x51;
                entry->fileSize = file->length;
                strncpy(entry->name, path, 20);
                bitmap[index] = 0x51;
                firstIndex = index;
            } else {
                buEntries[prevIndex].nextBlock = index;
                entry->allocState = 0x52;
                if (bitmap[index] != 0x51) bitmap[index] = 0x52;  // what?
            }
            prevIndex = index;
            if (futureBlockCount > ++blockCount) continue;
            entry->nextBlock = -1;
            if (blockCount > 1) entry->allocState = 0x53;
            if (!buWriteTOC(deviceId, bitmap)) break;
            while (firstIndex) {  // yes, that's broken... it'll do an infinite loop
                entry = &buEntries[firstIndex];
                entry->nextBlock = -1;
                firstIndex = entry->nextBlock;  // yes, I shit you not
                entry->allocState = 0xa0;
                entry->fileSize = 0;
            }
            file->errno = PSXEBUSY;
            blockCount++;
            prevIndex = index;
        }
    } else {
        syscall_setDeviceStatus(0);
        firstIndex = buNextFileInternal(deviceId, 0, path);
        if (firstIndex == -1) {
            file->errno = PSXENOENT;
            return 1;
        }
    }
    file->LBA = firstIndex;
    file->offset = 0;
    file->errno = PSXENOERR;
    file->length = buEntries[firstIndex].fileSize;
    return 0;
}

int dev_bu_close(struct File *file) {
    int deviceId = file->deviceId;
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;
    if (g_buOperation[port] == 0) {
        mcResetStatus();
        return 0;
    } else {
        return 1;
    }
}

int g_buOpSectorStart[2];
int g_buOpSectorCount[2];
int g_buOpActualSector[2];
char *g_buOpBuffer[2];
struct File *g_buOpFile[2];

static int s_buOpError[2];

int buRelativeToAbsoluteSector(int port, int block, int sector) {
    while (sector > 0x3f) {
        block = g_buDirEntries[port][block].nextBlock;
        sector = sector - 0x40;
        if (block == -1) return -1;
    }
    return (block * 64) + sector + 0x40;
}

int buGetReallocated(int port, int sector) {
    int32_t *broken = g_buBroken[port];
    for (int index = 0; index < 20; index++) {
        if (sector == broken[index]) return index + 16 + 20;
    }
    return -1;
}

static int buReadBuffer(int deviceId, int sector, int sectorCount, char *buffer) {
    int actualSector;
    int ret = 0;

    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;
    for (int index = 0; index < sectorCount; index++) {
        actualSector = buGetReallocated(port, sector);
        if (actualSector == -1) actualSector = sector;
        if (!syscall_mcReadSector(deviceId, actualSector, buffer)) return 0;
        int status = mcWaitForStatusAndReturnIndex();
        if (status != 0) {
            s_buOpError[port] = status;
            return -1;
        }
        buffer += 0x80;
        ret += 0x80;
        sector++;
    }
    return ret;
}

static int buWriteBuffer(int deviceId, int sector, int sectorCount, char *buffer) {
    int actualSector;
    int ret = 0;

    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;
    for (int index = 0; index < sectorCount; index++) {
        actualSector = buGetReallocated(port, sector);
        if (actualSector == -1) actualSector = sector;
        if (!syscall_mcWriteSector(deviceId, actualSector, buffer)) return 0;
        int status = mcWaitForStatusAndReturnIndex();
        if (status == 4) {
            // I don't get it... this acts as if the *previous* write failed...
            // The buffer, sector, and index are definitely all incremented
            // *after* this loop. Meaning any sort of write retry on broken
            // sectors will just do utter nonsense and corrupt data.
            actualSector = buGetReallocated(port, sector - 1);
            if (actualSector == -1) actualSector = sector - 1;
            if (!buReallocateBrokenSectorAndRetry(deviceId, actualSector, buffer - 0x80)) {
                s_buOpError[port] = 1;
                return -1;
            }
        } else if (status != 0) {
            s_buOpError[port] = status;
            return -1;
        }
        buffer += 0x80;
        ret += 0x80;
        sector++;
    }
    if (!cardInfo(deviceId)) return 0;
    int status = mcWaitForStatusAndReturnIndex();
    if (status == 4) {
        // This time the retry is technically correct, except...
        actualSector = buGetReallocated(port, sector - 1);
        // ... they forgot a -1 here...
        // There's just no way the sector reallocation system
        // works in any meaningful way, at least while using
        // the BIOS to write. Hopefully there's code in the
        // SDKs that correct these horrors...?
        if (actualSector == -1) actualSector = sector;
        actualSector = buReallocateBrokenSectorAndRetry(deviceId, actualSector, buffer - 0x80);
        if (actualSector == 0) {
            s_buOpError[port] = 1;
            return -1;
        }
    } else if (status != 0) {
        s_buOpError[port] = status;
        return -1;
    }
    return ret;
}

int dev_bu_read(struct File *file, void *buffer, int size) {
    int deviceId = file->deviceId;
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;

    if (g_buOperation[port] != 0) return -1;
    mcResetStatus();
    uint32_t offset = file->offset;
    if (((offset & 0x7f) != 0) || (offset >= file->length)) {
        file->errno = PSXEINVAL;
        return -1;
    }

    uint32_t sectorStart = offset >> 7;
    int sectorCount = size < 0 ? size + 0x7f : size;
    sectorCount >>= 7;

    if ((file->flags & PSXF_ASYNC) != 0) {
        if (g_buOperation[port] != 0) return -1;  // yes, again...
        g_buOperation[port] = 2;
        g_buOpSectorStart[port] = sectorStart;
        g_buOpSectorCount[port] = sectorCount;
        g_buOpBuffer[port] = buffer;
        g_buOpFile[port] = file;
        mcResetStatus();  // yes, again...
        if (sectorCount == 0) {
            // you'd think you'd want this as an early out, wouldn't you?
            file->errno = PSXENOERR;
            g_mcOverallSuccess = 1;
            buFinishAndTrigger(port, 4);
            return 0;
        }
        int absoluteSector = buRelativeToAbsoluteSector(port, file->LBA, sectorStart);
        int actualSector = buGetReallocated(port, absoluteSector);
        if (actualSector == -1) actualSector = absoluteSector;
        g_buOpActualSector[port] = actualSector;
        file->errno = PSXEBUSY;
        if (!syscall_mcReadSector(deviceId, actualSector, buffer)) return -1;
        file->errno = PSXENOERR;
        return 0;
    }

    int writtenSectorCount = 0;
    while (sectorCount > 0) {
        int sectorLimit = sectorStart & 0x3f;
        if ((sectorStart > 0) && (sectorLimit != 0)) {
            sectorLimit -= 0x40;
        }
        sectorLimit = 0x40 - sectorLimit;
        int actualSectorCount = sectorCount;
        if (sectorCount > sectorLimit) actualSectorCount = sectorLimit;
        int absoluteSector = buRelativeToAbsoluteSector(port, file->LBA, sectorStart);
        int bytesWritten = buReadBuffer(deviceId, absoluteSector, actualSectorCount, buffer);
        sectorCount -= actualSectorCount;
        if (bytesWritten != (actualSectorCount * 0x80)) break;
        sectorStart += actualSectorCount;
        buffer += actualSectorCount * 0x80;
        writtenSectorCount += actualSectorCount;
    }

    int bytesWritten = writtenSectorCount * 0x80;
    file->offset += bytesWritten;
    file->errno = PSXENOERR;
    g_buOperation[port] = 0;
    if (size != bytesWritten) return -s_buOpError[port];

    return size;
}

int dev_bu_write(struct File *file, void *buffer, int size) {
    int deviceId = file->deviceId;
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;

    if (g_buOperation[port] != 0) return -1;
    mcResetStatus();
    uint32_t offset = file->offset;
    if (((offset & 0x7f) != 0) || (offset >= file->length)) {
        file->errno = PSXEINVAL;
        return -1;
    }

    uint32_t sectorStart = offset >> 7;
    int sectorCount = size < 0 ? size + 0x7f : size;
    sectorCount >>= 7;

    if ((file->flags & PSXF_ASYNC) != 0) {
        if (g_buOperation[port] != 0) return -1;  // yes, again...
        g_buOperation[port] = 3;
        g_buOpSectorStart[port] = sectorStart;
        g_buOpSectorCount[port] = sectorCount;
        g_buOpBuffer[port] = buffer;
        g_buOpFile[port] = file;
        mcResetStatus();  // yes, again...
        if (sectorCount == 0) {
            // you'd think you'd want this as an early out, wouldn't you?
            file->errno = PSXENOERR;
            g_mcOverallSuccess = 1;
            buFinishAndTrigger(port, 4);
            return 0;
        }
        int absoluteSector = buRelativeToAbsoluteSector(port, file->LBA, sectorStart);
        int actualSector = buGetReallocated(port, absoluteSector);
        if (actualSector == -1) actualSector = absoluteSector;
        g_buOpActualSector[port] = actualSector;
        file->errno = PSXEBUSY;
        if (!syscall_mcWriteSector(deviceId, actualSector, buffer)) return -1;
        file->errno = PSXENOERR;
        return 0;
    }

    int writtenSectorCount = 0;
    while (sectorCount > 0) {
        int sectorLimit = sectorStart & 0x3f;
        if ((sectorStart > 0) && (sectorLimit != 0)) {
            sectorLimit -= 0x40;
        }
        sectorLimit = 0x40 - sectorLimit;
        int actualSectorCount = sectorCount;
        if (sectorCount > sectorLimit) actualSectorCount = sectorLimit;
        int absoluteSector = buRelativeToAbsoluteSector(port, file->LBA, sectorStart);
        int bytesWritten = buWriteBuffer(deviceId, absoluteSector, actualSectorCount, buffer);
        sectorCount -= actualSectorCount;
        if (bytesWritten != (actualSectorCount * 0x80)) break;
        sectorStart += actualSectorCount;
        buffer += actualSectorCount * 0x80;
        writtenSectorCount += actualSectorCount;
    }

    int bytesWritten = writtenSectorCount * 0x80;
    file->offset += bytesWritten;
    file->errno = PSXENOERR;
    g_buOperation[port] = 0;
    if (size != bytesWritten) return -s_buOpError[port];

    return size;
}

int dev_bu_erase(struct File *file, const char *path) {
    file->errno = PSXEBUSY;
    int deviceId = file->deviceId;
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;

    if (g_buOperation[port] != 0) return 1;

    mcResetStatus();
    if (!buDevInit(deviceId)) return 1;

    syscall_setDeviceStatus(0);
    int index = buNextFileInternal(deviceId, 0, path);
    if (index == -1) {
        file->errno = PSXENOENT;
        return 1;
    }
    int bitmap[15];
    for (unsigned i = 0; i < 15; i++) {
        bitmap[i] = 0;
    }
    struct BuDirectoryEntry *entry = &g_buDirEntries[port][index];
    entry->allocState = 0xa1;
    bitmap[index] = 0x51;
    int size = entry->fileSize;
    int nextBlock = entry->nextBlock;
    if (size < 0) size += 0x1fff;
    int count = (size >> 13) - 1;
    if (count > 0) {
        entry = &g_buDirEntries[port][nextBlock];
        while ((entry->nextBlock != -1) && (entry->allocState == 0x52)) {
            int block = nextBlock;
            nextBlock = entry->nextBlock;
            entry->allocState = 0xa2;
            count--;
            bitmap[block] = 0x52;
            if (count < 1) break;
            entry = &g_buDirEntries[port][nextBlock];
        }
    }
    if (count > 0) {
        entry = &g_buDirEntries[port][nextBlock];
        if ((entry->nextBlock == -1) && (entry->allocState == 0x53)) {
            entry->allocState = 0xa3;
            bitmap[nextBlock] = 0x52;
        }
    }

    if (buWriteTOC(deviceId, bitmap) != 0) {
        for (unsigned i = 0; i < 15; i++) {
            if (bitmap[i]) {
                entry = &g_buDirEntries[port][i];
                entry->fileSize = 0;
                entry->nextBlock = -1;
                entry->allocState = 0xa0;
            }
        }
        file->errno = PSXEBUSY;
        return 1;
    }

    file->errno = PSXENOERR;
    return 0;
}

void dev_bu_undelete() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    dev_bu_unimplemented("mcUndelete", ra);
}

struct DirEntry *dev_bu_firstFile(struct File *file, const char *filename, struct DirEntry *entry) {
    file->errno = PSXEBUSY;

    int deviceId = file->deviceId;
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;

    if (g_buOperation[port] != 0) return NULL;

    mcResetStatus();
    if (!buDevInit(deviceId)) return NULL;
    for (unsigned i = 0; i < 19; i++) s_findFilePattern[i] = '?';
    if (strlen(filename) == 0) {
        s_findFilePattern[19] = 0;
    } else {
        char *out = s_findFilePattern;
        char c;
        while ((c = *filename++)) {
            if (c == '*') break;
            *out++ = c;
        }
        if (c == '*') {
            char *end = s_findFilePattern + 20;
            while (out < end) *out++ = '?';
        }
        *out = 0;
    }
    s_buNextFileIndex = -1;
    return dev_bu_nextFile(file, entry);
}

struct DirEntry *dev_bu_nextFile(struct File *file, struct DirEntry *entry) {
    int deviceId = file->deviceId;
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;

    if (g_buOperation[port] != 0) {
        file->errno = PSXEBUSY;
        return NULL;
    }

    mcResetStatus();
    int index = buNextFileInternal(deviceId, s_buNextFileIndex + 1, s_findFilePattern);
    if (index == -1) {
        file->errno = PSXENOENT;
        return NULL;
    }

    entry->attributes = g_buDirEntries[port][index].allocState & 0xf0;
    uint32_t size = g_buDirEntries[port][index].fileSize;
    entry->LBA = (index + 1) * 0x40;
    entry->size = size;
    strcpy(entry->name, g_buDirEntries[port][index].name);
    file->errno = PSXENOERR;

    return entry;
}

int dev_bu_format(struct File *file) {
    int deviceId = file->deviceId;
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;

    if (g_buOperation[port] != 0) {
        file->errno = PSXEBUSY;
        return 1;
    }

    mcResetStatus();
    if (!buFormat(deviceId)) {
        file->errno = PSXEBUSY;
        return 1;
    }
    file->errno = PSXENOERR;
    return 0;
}

int dev_bu_rename(struct File *file, const char *oldName, struct File *unused, const char *newName) {
    file->errno = PSXEBUSY;
    int deviceId = file->deviceId;
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;

    if (g_buOperation[port] != 0) return 1;

    mcResetStatus();
    if (!buDevInit(deviceId)) return 1;

    syscall_setDeviceStatus(0);
    if (buNextFileInternal(deviceId, 0, newName) != -1) {
        file->errno = PSXEEXIST;
        return 1;
    }
    int index = buNextFileInternal(deviceId, 0, oldName);
    if (index == -1) {
        file->errno = PSXENOENT;
        return 1;
    }
    int bitmap[15];
    for (unsigned i = 0; i < 15; i++) {
        bitmap[i] = 0;
    }
    char *entryToUpdate = g_buDirEntries[port][index].name;
    strcpy(entryToUpdate, newName);
    bitmap[index] = 0x51;
    if (buWriteTOC(deviceId, bitmap) != 0) {
        strcpy(entryToUpdate, oldName);
        file->errno = PSXEBUSY;
        return 1;
    }

    file->errno = PSXENOERR;
    return 0;
}

void dev_bu_deinit() {
    uint32_t ra;
    asm("move %0, $ra\n" : "=r"(ra));
    dev_bu_unimplemented("mcDeinit", ra);
}

static const struct Device s_cardDevice = {
    .name = "bu",
    .flags = 0x14,
    .blockSize = 0x80,
    .desc = "MEMORY CARD",
    .init = (void (*)())psxdummy,
    .open = dev_bu_open,
    .action = psxdummy,
    .close = dev_bu_close,
    .ioctl = psxdummy,
    .read = dev_bu_read,
    .write = dev_bu_write,
    .erase = dev_bu_erase,
    .undelete = dev_bu_undelete,
    .firstFile = dev_bu_firstFile,
    .nextFile = dev_bu_nextFile,
    .format = dev_bu_format,
    .chdir = psxdummy,
    .rename = dev_bu_rename,
    .deinit = dev_bu_deinit,
    .check = psxdummy,
};

int addMemoryCardDevice() { return syscall_addDevice(&s_cardDevice); }
