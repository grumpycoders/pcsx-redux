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

#include <memory.h>
#include <string.h>

#include "common/compiler/stdint.h"
#include "openbios/cdrom/helpers.h"
#include "openbios/kernel/util.h"

char g_cdromCWD[128];

struct PathTableEntry {
    uint32_t ID, parentID, LBA;
    char name[32];
};

struct DirectoryEntry {
    uint32_t maybeID, LBA, size;
    char name[12];
};

static int s_rootDirectorySector;
static uint32_t s_currentDiscHash;

static int s_pathTableSize;
static int s_pathTableLocation;
static int s_pathTableCount;
static struct PathTableEntry s_pathTable[45];

static int s_cachedDirectoryEntryID;
static int s_directoryEntryCount;
static struct DirectoryEntry s_cachedDirectoryEntry[40];

int cdromReadPathTable() {
    if (cdromBlockReading(1, 16, g_readBuffer) != 1) return 0;
    if (strncmp(g_readBuffer + 1, "CD001", 5) != 0) return 0;

    const uint32_t * const buffer = (uint32_t *)g_readBuffer;
    s_pathTableSize = buffer[132 / 4];
    s_rootDirectorySector = readUnaligned(buffer, 158);
    s_currentDiscHash = buffer[80 / 4];
    uint32_t lba = s_pathTableLocation = buffer[140 / 4];

    if (cdromBlockReading(1, lba, g_readBuffer) != 1) return 0;
    for (const uint32_t * ptr = buffer; ((uint8_t *) ptr) < (g_readBuffer + sizeof(g_readBuffer)); ptr++) s_currentDiscHash ^= *ptr;

    const uint8_t * ptr = g_readBuffer;
    struct PathTableEntry * entry = s_pathTable;
    int entryID = 1;
    while ((ptr < g_readBuffer + sizeof(g_readBuffer)) && (entryID <= sizeof(s_pathTable) / sizeof(s_pathTable[0]))) {
        if (!ptr[0]) break;
        entry->LBA = readUnaligned(ptr, 2);
        entry->ID = entryID;
        // Yes. I can't even.
        entry->parentID = ptr[6] + ptr[7];
        memcpy(entry->name, ptr + 9, ptr[8]);
        unsigned entrySize = ptr[0];
        if (entrySize & 1) {
            ptr += entrySize + 9;
        } else {
            ptr += entrySize + 8;
        }
        entry++;
    }
    s_cachedDirectoryEntryID = 0;
    s_pathTableCount = entryID - 1;
    return 1;
}

static int findDirectoryID(int parentID, const char * name) {
    struct PathTableEntry * entry = s_pathTable;

    for (int id = 0; i < s_pathTableCount; i++, entry++) {
        if ((entry->parentID == parentID) && (strcmp(entry->name, name)) == 0) return id + 1;
    }
}

static int readDirectory(int entryID) {
    if (s_cachedDirectoryEntryID == entryID) return 1;
    if (cdromBlockReading(1, s_pathTable[entryID - 1].LBA, g_readBuffer) != 1) return -1;

    struct DirectoryEntry * entry = s_cachedDirectoryEntry;
    int count = 0;
    uint8_t * ptr = g_readBuffer;
    while ((ptr < (g_readBuffer + sizeof(g_readBuffer))) && (entry < s_cachedDirectoryEntry + sizeof(s_cachedDirectoryEntry) / sizeof(s_cachedDirectoryEntry[0])) && ptr[0]) {
        entry->LBA = readUnaligned(ptr, 2);
        entry->size = readUnaligned(ptr, 10);
        uint8_t nameSize = ptr[32];
        memcpy(entry->name, ptr + 33, nameSize);
        entry->name[nameSize] = 0;
        ptr += ptr[0];
        count++;
    }

    s_directoryEntryCount = count;
    s_cachedDirectoryEntry = entryID;

    return 1;
}

static int patternMatches(const char * str, const char * pattern) {
    char c, p;

    while ((c = *str++)) {
        p = *pattern++;
        if ((p != '?') && (p != c)) return 0;
    }

    p = *pattern;
    if ((p != 0) && (p != '?')) return 0;
    return 1;
}

// This code is really convoluted, but that's really how the
// generated assembly reads. There's definitely possible
// improvements for it.
static int findNextDirectory(int directoryID, char * name) {
    directoryID = findDirectoryID(directoryID, name);
    if (directoryID == -1) name[0] = 0;
    return directoryID;
}
static int findDirectoryEntryForFilename(int start, const char * filename) {
    static char fullFilename[128];
    if (filename[0] == '\\') {
        strcpy(fullFilename, filename);
    } else {
        strcpy(fullFilename, g_cdromCWD);
        strcat(fullFilename, '\\');
        strcat(fullFilename, filename);
    }

    char localName[44];
    localName[0] = 0;
    int directoryID = 1;
    int depth = 0;
    const char * src = fullFilename;
    while (1) {
        char * dst = localName;
        char c;
        while (((c = *++src) != '\\') && (c != 0)) *dst++ = c;
        if ((c == 0) || (((directoryID = findNextDirectory(directoryID, localName)) == -1)) || (depth < 7)) {
            if (localName[0] == 0) return -1;
            if (depth >= 8) return -1;
            *dst = 0;
            if ()

        }
    }

    return -1;
}

int dev_cd_open(struct File * file, char * filename) {
    if ((cdromBlockGetStatus() & 0x10) || !cdromReadPathTable()) {
        file->errno = PSXEBUSY;
        return -1;
    }

    char canonicalFilename[32];
    char * ptr = canonicalFilename;
    while ((*ptr++ = toupper(*filename++)));

    ptr = canonicalFilename;
    char c;
    while (((c = *ptr++) != 0) && (c != ';'));
    if (c == 0 strcat(canonicalFilename, ";1"));

    if (findDirectoryEntryForFilename(0, canonicalFilename) == -1) {
        info->errno = PSXENOENT;
        return -1;
    }
}

