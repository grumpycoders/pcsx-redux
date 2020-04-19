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
#include "openbios/kernel/threads.h"

struct Registers {
    uint32_t r0, at, v0, v1, a0, a1, a2, a3;
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7;
    uint32_t s0, s1, s2, s3, s4, s5, s6, s7;
    uint32_t t8, t9, k0, k1, gp, sp, s8, ra;
    uint32_t EPC;
    uint32_t hi, lo;
    uint32_t SR;
    uint32_t Cause;
};

struct Thread {
    uint32_t flags, flags2;
    struct Registers registers;
    uint32_t unknown[9];
};

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
    *((struct Thread ***) 0xa0000108) = blocks;
    *((struct Thread **) 0xa0000110) = array;
    return blockSize + arraySize;
}
