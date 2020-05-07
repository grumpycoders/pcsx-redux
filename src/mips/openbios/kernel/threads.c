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

#include <stddef.h>

#include "common/compiler/stdint.h"
#include "common/syscalls/syscalls.h"
#include "openbios/fileio/fileio.h"
#include "openbios/kernel/globals.h"
#include "openbios/kernel/threads.h"

int initThreads(int blocksCount, int count) {
    psxprintf("TCB\t0x%02x\n", count);
    int blockSize = blocksCount * sizeof(struct Thread *);
    struct Thread ** blocks = syscall_kmalloc(blockSize);
    if (!blocks) return 0;

    int arraySize = count * sizeof(struct Thread);
    struct Thread * array = syscall_kmalloc(arraySize);
    if (!array) return 0;

    struct Thread ** blockPtr = blocks;
    while (blockPtr < blocks + blocksCount) *blockPtr++ = NULL;
    struct Thread * threadPtr = array;
    while (threadPtr < array + count) threadPtr++->flags = 0x1000;
    array[0].flags = 0x4000;
    *blocks = array;

    __globals.blocks = blocks;
    __globals.threads = array;

    return blockSize + arraySize;
}
