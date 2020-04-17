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

#pragma once

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

static int s_pathTableSize;
static int s_rootDirectorySector;
static uint32_t s_currentDiscHash;
static int s_pathTableLocation;
static int s_cachedDirectoryEntryID;
static int s_pathTableCount;

static struct PathTableEntry pathTable[45];

int cdromReadPathTable() {
    if (cdromBlockReading(1, 16, g_readBuffer) != 1) return 0;
    if (strncmp(g_readBuffer + 1, "CD001", 5) != 0) return 0;

    const uint32_t * const buffer = (uint32_t *)g_readBuffer;
    s_pathTableSize = buffer[132 / 4];
    s_rootDirectorySector = readUnaligned(buffer, 158);
    s_currentDiscHash = buffer[80 / 4];
    uint32_t lba = s_pathTableLocation = buffer[140 / 4];

    if (cdromBlockReading(1, lba, g_readBuffer) != 1) return 0;
    for (const uint32_t * ptr = buffer; ptr < (g_readBuffer + sizeof(g_readBuffer); ptr++) s_currentDiscHash ^= *ptr;

    const uint8_t * ptr = g_readBuffer;
    struct PathTableENtry * entry = pathTable;
    int entryID = 1;
    while ((pathEntryPtr < g_readBuffer + sizeof(g_readBuffer)) && (entryID <= sizeof(pathTable) / sizeof(pathTable[0]))) {
        if (!ptr[0]) break;
        entry->LBA = readUnaligned(ptr, 2);
        entry->ID = entryID;
        // Yes. I can't even.
        entry->parentID = ptr[6] + ptr[7]
        memcpy(entry->name, ptr + 9, ptr[8]);
        unsigned entrySize = ptr[0];
        if (entrySize & 1) {
            ptr += entrySize + 9;
        } else {
            ptr += entrySize + 8;
        }
        entry++;
    }
    s_cachedDirectoryEntryId = 0;
    s_pathTableCount = entryID - 1;
    return 1;
}
