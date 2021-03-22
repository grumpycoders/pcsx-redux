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

#include "openbios/card/backupunit.h"

#include <stdint.h>
#include <string.h>

#include "common/hardware/pcsxhw.h"
#include "common/kernel/events.h"
#include "common/syscalls/syscalls.h"
#include "openbios/card/card.h"
#include "openbios/kernel/libcmisc.h"
#include "openbios/sio0/card.h"
#include "osdebug.h"

int g_buOperation[2];
int g_buAutoFormat;

struct BuDirectoryEntry g_buDirEntries[2][15];
uint8_t g_buBuffer[2][128];
int32_t g_buBroken[2][20];

static int s_buCurrentState[2];
static int s_buCurrentSector[2];

static __attribute__((noreturn)) void buUnimplemented(const char *function, int op) {
    osDbgPrintf("=== Unimplemented backup unit function %s, op %i ===\r\n", function, op);
    osDbgPrintf("=== halting ===\r\n");
    pcsx_debugbreak();
    while (1)
        ;
}

static void buClear() {
    g_buOperation[1] = 0;
    g_buOperation[0] = 0;
    g_buAutoFormat = 0;

    mcResetStatus();

    struct BuDirectoryEntry *ptr1 = g_buDirEntries[0], *ptr2 = g_buDirEntries[1];

    for (unsigned i = 0; i < 15; i++) {
        psxbzero(ptr1, sizeof(struct BuDirectoryEntry));
        psxbzero(ptr2, sizeof(struct BuDirectoryEntry));

        ptr1->allocState = ptr2->allocState = 0xa0;
        ptr1->nextBlock = ptr2->nextBlock = -1;
        ptr1->fileSize = ptr2->fileSize = 0;
        ptr1++;
        ptr2++;
    }
}

static void buComputeSectorChecksum(uint8_t *buffer) {
    uint8_t checksum = 0;
    for (unsigned i = 0; i < 0x7f; i++) checksum ^= buffer[i];
    buffer[0x7f] = checksum;
}

static int buVerifySectorChecksum(uint8_t *buffer) {
    uint8_t checksum = 0;
    for (unsigned i = 0; i < 0x7f; i++) checksum ^= buffer[i];
    return buffer[0x7f] == checksum;
}

int buFormat(int deviceId) {
    int port = deviceId < 0 ? deviceId + 15 : deviceId;
    port >>= 4;

    uint8_t *const buffer = g_buBuffer[port];

    psxbzero(buffer, 0x80);
    buffer[0] = 'M';
    buffer[1] = 'C';
    buComputeSectorChecksum(buffer);
    syscall_mcAllowNewCard();

    if (!syscall_mcWriteSector(deviceId, 0, buffer)) return 0;
    mcWaitForStatus();

    for (unsigned i = 0; i < 15; i++) {
        struct BuDirectoryEntry *entry = &g_buDirEntries[port][i];
        psxbzero(entry, sizeof(struct BuDirectoryEntry));
        entry->allocState = 0xa0;
        entry->fileSize = 0;
        entry->nextBlock = -1;
        memcpy(buffer, entry, sizeof(struct BuDirectoryEntry));
        buComputeSectorChecksum(buffer);
        if (!syscall_mcWriteSector(deviceId, i + 1, buffer)) return 0;
        mcWaitForStatusAndReturnIndex();
    }

    for (unsigned i = 0; i < 20; i++) {
        int32_t *broken = &g_buBroken[port][i];
        *broken = -1;
        memcpy(buffer, broken, sizeof(uint32_t));
        buComputeSectorChecksum(buffer);
        if (!syscall_mcWriteSector(deviceId, i + 16, buffer)) return 0;
        mcWaitForStatusAndReturnIndex();
    }

    return 1;
}

static int buValidateEntryAndCorrect(int port, int entryId) {
    struct BuDirectoryEntry *entries = g_buDirEntries[port];
    struct BuDirectoryEntry *entry = &entries[entryId];

    uint8_t mask;

    switch (entry->allocState) {
        case 0x51:
            mask = 0xa0;
            break;
        case 0xa1:
            mask = 0x50;
            break;
        default:
            return 0;
    }

    int32_t size = entry->fileSize;
    int16_t next = entry->nextBlock;

    if (size < 0) size += 0x1fff;
    int blocks = size >> 13;
    blocks--;

    if ((blocks > 0) && (next != -1)) {
        int16_t ptr = next;
        int count = blocks;
        while (mask != (entries[ptr].allocState) & 0xf0) {
            ptr = entries[ptr].nextBlock;
            if ((--count < 0) || (ptr == -1)) return 0;
        }

        entry->name[0] = 0;
        entry->allocState = 0xa0;
        entry->fileSize = 0;
        entry->nextBlock = -1;

        while ((blocks > 0) && (next != -1)) {
            entry = &entries[next];
            next = entry->nextBlock;
            blocks--;
            entry->allocState = 0xa0;
            entry->fileSize = 0;
            entry->nextBlock = -1;
        }

        return 1;
    }

    return 0;
}

int buInit(int deviceId) {
    syscall_mcAllowNewCard();

    int port = deviceId < 0 ? deviceId + 15 : deviceId;
    port >>= 4;

    uint8_t *const buffer = g_buBuffer[port];
    struct BuDirectoryEntry *const dirEntries = g_buDirEntries[port];
    int32_t *const broken = g_buBroken[port];

    if (!syscall_mcReadSector(deviceId, 0, buffer)) goto buInitFailure;
    if (!mcWaitForStatus()) goto buInitFailure;
    if (buffer[0] != 'M' || buffer[1] != 'C') {
        if (g_buAutoFormat) return buFormat(deviceId);
        goto buInitFailure;
    }
    syscall_mcAllowNewCard();
    syscall_mcWriteSector(deviceId, 0x3f, buffer);
    mcWaitForStatus();
    for (unsigned i = 0; i < 15; i++) {
        psxbzero(&dirEntries[i], sizeof(struct BuDirectoryEntry));
        dirEntries[i].allocState = 0xa0;
        dirEntries[i].fileSize = 0;
    }
    for (unsigned i = 0; i < 15; i++) {
        if (!syscall_mcReadSector(deviceId, i + 1, buffer)) goto buInitFailure;
        if (!mcWaitForStatus()) goto buInitFailure;
        if (!buVerifySectorChecksum(buffer)) goto buInitFailure;
        memcpy(&dirEntries[i], buffer, sizeof(struct BuDirectoryEntry));
    }
    uint32_t entriesStates[15];
    for (unsigned i = 0; i < 15; i++) {
        entriesStates[i] = 0;
        if (buValidateEntryAndCorrect(port, i)) entriesStates[i] = 0x52;
    }
    // this is fully unused...?
    int numBlocks[15];
    for (unsigned i = 0; i < 15; i++) numBlocks[i] = 0;
    for (unsigned i = 0; i < 15; i++) {
        uint32_t allocState = dirEntries[i].allocState;
        if ((allocState != 0x51) && (allocState != 0xa1)) continue;
        numBlocks[i] = 1;
        int32_t size = dirEntries[i].fileSize;
        int16_t next = dirEntries[i].nextBlock;
        if (size < 0) size += 0x1fff;
        int blocks = size >> 13;
        while ((--blocks > 0) && (next != -1)) {
            numBlocks[next]++;
            next = dirEntries[next].nextBlock;
        }
    }
    for (unsigned i = 0; i < 15; i++) {
        if (entriesStates[i] != 0) continue;
        // what ?
        dirEntries[i].fileSize = 0;
        dirEntries[i].allocState = 0xa0;
        dirEntries[i].nextBlock = -1;
    }
    for (unsigned i = 0; i < 20; i++) {
        if (!syscall_mcReadSector(deviceId, i + 16, buffer)) goto buInitFailure;
        if (!mcWaitForStatus()) goto buInitFailure;
        if (!buVerifySectorChecksum(buffer)) goto buInitFailure;
        memcpy(&broken[i], buffer, 4);
    }

    return 1;

buInitFailure:
    for (unsigned i = 0; i < 15; i++) {
        psxbzero(&dirEntries[i], sizeof(struct BuDirectoryEntry));
    }
    for (unsigned i = 0; i < 20; i++) {
        broken[i] = -1;
    }

    return 0;
}

int initBackupUnit() {
    g_buOperation[1] = 0;
    g_buOperation[0] = 0;

    buClear();
    buInit(0x00);
    buInit(0x10);
    return 0;
}

int cardInfo(int deviceId) {
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;
    g_buOperation[port] = 1;
    int ret = syscall_cardInfoInternal(deviceId);
    if (!ret) g_buOperation[port] = 0;
    return ret != 0;
}

static void buFinishAndTrigger(int port, int spec) {
    g_buOperation[port] = 0;
    s_buCurrentState[port] = 0;
    s_buCurrentSector[port] = 0;
    syscall_deliverEvent(EVENT_BU, spec);
}

void buLowLevelOpCompleted() {
    g_mcOverallSuccess = 1;
    int deviceId = syscall_mcGetLastDevice();
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;
    uint8_t *buffer = g_buBuffer[port];
    struct BuDirectoryEntry *dirEntries = g_buDirEntries[port];
    int32_t *broken = g_buBroken[port];

    switch (g_buOperation[port]) {
        case 0:
            return;
        case 1:
        case 8:
            buFinishAndTrigger(port, 0x0004);
            break;
        case 4:
            switch (s_buCurrentState[port]) {
                case 1:
                    if ((buffer[0] != 'M') || (buffer[1] == 'C')) {
                        g_mcOverallSuccess = 0;
                        g_mcErrors[2] = 1;
                        buFinishAndTrigger(port, 0x2000);
                        return;
                    }
                    for (unsigned int i = 0; i < 15; i++) {
                        psxbzero(&dirEntries[i], sizeof(struct BuDirectoryEntry));
                        dirEntries[i].fileSize = 0;
                        dirEntries[i].nextBlock = -1;
                        dirEntries[i].allocState = 0xa0;
                    }
                    if (!syscall_mcReadSector(deviceId, 1, buffer)) {
                        g_mcOverallSuccess = 0;
                        g_mcErrors[0] = 1;
                        buFinishAndTrigger(port, 0x8000);
                        return;
                    }
                    s_buCurrentSector[port] = 0;
                    s_buCurrentState[port] = 2;
                    break;
                case 2:
                    if (buVerifySectorChecksum(buffer)) {
                        memcpy(&dirEntries[s_buCurrentSector[port]], buffer, sizeof(struct BuDirectoryEntry));
                    }
                    if (++s_buCurrentSector[port] < 15) {
                        if (syscall_mcReadSector(deviceId, s_buCurrentSector[port], buffer)) return;
                        g_mcOverallSuccess = 0;
                        g_mcErrors[0] = 1;
                        buFinishAndTrigger(port, 0x8000);
                        return;
                    }
                    uint32_t entriesStates[15];
                    for (unsigned i = 0; i < 15; i++) {
                        entriesStates[i] = 0;
                        if (buValidateEntryAndCorrect(port, i)) entriesStates[i] = 0x52;
                    }
                    // this is fully unused...?
                    int numBlocks[15];
                    for (unsigned i = 0; i < 15; i++) numBlocks[i] = 0;
                    for (unsigned i = 0; i < 15; i++) {
                        uint32_t allocState = dirEntries[i].allocState;
                        if (allocState != 0x51) continue;
                        numBlocks[i] = 1;
                        int32_t size = dirEntries[i].fileSize;
                        int16_t next = dirEntries[i].nextBlock;
                        if (size < 0) size += 0x1fff;
                        int blocks = size >> 13;
                        while ((--blocks > 0) && (next != -1)) {
                            numBlocks[next]++;
                            next = dirEntries[next].nextBlock;
                        }
                    }
                    for (unsigned i = 0; i < 15; i++) {
                        if (entriesStates[i] != 0) continue;
                        // what ?
                        dirEntries[i].fileSize = 0;
                        dirEntries[i].allocState = 0xa0;
                        dirEntries[i].nextBlock = -1;
                    }
                    for (unsigned i = 0; i < 20; i++) {
                        broken[i] = -1;
                    }
                    if (!syscall_mcReadSector(deviceId, 16, buffer)) {
                        buFinishAndTrigger(port, 0x8000);
                    }
                    s_buCurrentSector[port] = 0;
                    s_buCurrentState[port] = 3;
                    break;
                case 3:
                    if (buVerifySectorChecksum(buffer)) {
                        memcpy(&broken[s_buCurrentSector[port]], buffer, 4);
                    }
                    if (++s_buCurrentSector[port] < 20) {
                        if (syscall_mcReadSector(deviceId, s_buCurrentSector[port] + 16, buffer)) return;
                        g_mcOverallSuccess = 0;
                        g_mcErrors[0] = 1;
                        buFinishAndTrigger(port, 0x8000);
                        return;
                    }
                    buFinishAndTrigger(port, 0x0004);
                    break;
            }
            break;
        default:
            buUnimplemented("buLowLevelOpCompleted", g_buOperation[port]);
    }
}

void buError0() {
    g_mcErrors[0] = 1;
    int deviceId = syscall_mcGetLastDevice();
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;

    if (g_buOperation[port]) buFinishAndTrigger(port, 0x8000);
}

void buError1() {
    g_mcErrors[1] = 1;
    int deviceId = syscall_mcGetLastDevice();
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;

    if (g_buOperation[port]) buFinishAndTrigger(port, 0x0100);
}

void buError2() {
    g_mcErrors[2] = 1;
    int deviceId = syscall_mcGetLastDevice();
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;

    if (g_buOperation[port]) buFinishAndTrigger(port, 0x2000);
}

int buReadTOC(int deviceId) {
    int port = deviceId >= 0 ? deviceId : deviceId + 15;
    port >>= 4;
    g_buOperation[port] = 4;
    if (syscall_mcReadSector(deviceId, 0, g_buBuffer[port])) {
        g_buOperation[port] = 4;
        s_buCurrentState[port] = 1;
        return 1;
    } else {
        g_buOperation[port] = 0;
        return 0;
    }
}
